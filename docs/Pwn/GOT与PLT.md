## 重定向

二进制文件有两种类型：静态链接和动态链接。静态链接二进制文件包含运行需要的全部代码，不要加载外部库。动态链接没有包含全部代码，需要加载系统库来运行。

假设动态链接二进制文件加载（调用）系统库使用硬编码地址（绝对地址），那么系统库发生变化，二进制文件内的硬编码地址很可能全部改变。所以提出了一个**重定向**机制。

``.got``、``.plt``、``.got.plt``、``链接器``等是重定向的组成成分。

## 重定位表（relocations）

### **.got**

全局偏移表。用于记录在 ELF （二进制）文件中所用到的共享库中函数（或字符串）的绝对地址。

在程序刚开始运行时，GOT 表为空的，当函数*第一次被调用*时会动态解析符号的绝对地址然后转去执行，并将被解析符号的绝对地址记录在 GOT 中；第二次调用同一函数时，由于 GOT 中已经记录了其绝对地址，直接转去执行即可（不用重新解析）。（结合 **.got.plt** 理解）

### **.got.plt**

got 表中的一部分。用于重定向请求到 .got 上的对应偏移或者返回 .plt 中激活链接器寻找函数在 系统库 中的地址。

开始运行是 .got.plt 不为空。当 got 表中没有函数的记录值时，会把从 .plt 进入 .got.plt 的进程重定向到 .plt 中激活链接器，寻址完成后，.got 记录函数在系统库偏移，.got.plt 会记录函数在 .got 偏移。

### .plt

程序链接表。是调用系统库函数最开始的入口。它有两个功能，在 .got.plt 节中拿到地址，并跳转；当 .got.plt 没有所需地址的时，触发「链接器」去找到所需函数地址。

### .plt.got

没有太准确的相关资料，在 stackoverflow 上面有一个[帖子](https://stackoverflow.com/questions/58076539/plt-plt-got-what-is-different)提及，原文如下：

> The difference is that .got.plt is runtime-writable, while .got is not if you enable a defense against GOT overwriting attacks called RELRO (relocations read-only). To enable RELRO, you use the ld option -z relro. RELRO places GOT entries that must be runtime-writable for lazy binding in .got.plt, and all others in the read-only .got section

没太看懂，大概说 .got.plt 在运行时是可读写。但是当开启 RELRO 时，.got 是不可写的。

调用系统库函数

![](https://mrskye.cn-gd.ufileos.com/img/2020-04-24-eCAUdO88GUhYXSRv.png)

## 实例

> 引用自：[GOT and PLT for pwning](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

源码如下：

```c
// Build with: gcc -m32 -no-pie -g -o plt plt.c

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  puts("Hello world!");
  exit(0);
}
```

```shell
#pwndbg> info files
pwndbg> maintenance info sections

There are 36 section headers, starting at offset 0x1fb4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048330 000330 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048340 000340 0001a2 00  AX  0   0 16
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
```



gdb 反编译 main 函数，call 函数下断点，单步调试

```shell
pwndbg> disass main
Dump of assembler code for function main:
   0x0804843b <+0>:	lea    ecx,[esp+0x4]
   0x0804843f <+4>:	and    esp,0xfffffff0
   0x08048442 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048445 <+10>:	push   ebp
   0x08048446 <+11>:	mov    ebp,esp
   0x08048448 <+13>:	push   ebx
   0x08048449 <+14>:	push   ecx
   0x0804844a <+15>:	call   0x8048370 <__x86.get_pc_thunk.bx>
   0x0804844f <+20>:	add    ebx,0x1bb1
   0x08048455 <+26>:	sub    esp,0xc
   0x08048458 <+29>:	lea    eax,[ebx-0x1b00]
   0x0804845e <+35>:	push   eax
   0x0804845f <+36>:	call   0x8048300 <puts@plt>
   0x08048464 <+41>:	add    esp,0x10
   0x08048467 <+44>:	sub    esp,0xc
   0x0804846a <+47>:	push   0x0
   0x0804846c <+49>:	call   0x8048310 <exit@plt>
End of assembler dump.
pwndbg> break *0x0804845f
Breakpoint 1 at 0x804845f: file plt.c, line 7.
pwndbg> r
Breakpoint *0x0804845f
pwndbg> x/i $pc
=> 0x804845f <main+36>:	call   0x8048300 <puts@plt>
```

debug 到 call 函数，用 si 单步入进入 plt 函数里面，否则直接调 puts 代码。可以用``x/i $pc``查汇编，或者``disass 0x8048300``反编译一样能看到跳转的 .got.plt 地址 0x804a00c 。

```shell
pwndbg> si
pwndbg> x/i $pc
=> 0x8048300 <puts@plt>:	jmp    DWORD PTR ds:0x804a00c
```

查询 .got.plt 的跳转地址，是跳转回 .plt 。因为第一次调用 .got 表没有记录，需要跳转 .plt 激活链接器寻址。

```shell
pwndbg> x/wx 0x804a00c
0x804a00c:	0x08048306
pwndbg> si
0x08048306 in puts@plt ()
pwndbg> x/2i $pc
=> 0x8048306 <puts@plt+6>:	push   0x0
   0x804830b <puts@plt+11>:	jmp    0x80482f0
```

然后线程会进入系统库函数中（libc），并且 .got 记录 libc 地址，.got.plt 记录在 .got 中偏移。

## Pwning Relocations

通常就是控制程序执行流程嘛，但是通常某一部分不会同时开启写和执行权限，也就是 NX 保护嘛。

然后``.got.plt``是一个函数指针数组（库），就覆盖其中值控制执行流程。

对应的保护措施就是 RELRO ：partial and full RELRO。

Partial RELRO (enabled with `-Wl,-z,relro`):

- Maps the `.got` section as read-only (but *not* `.got.plt`)
- Rearranges sections to reduce the likelihood of global variables overflowing into control structures.

Full RELRO (enabled with `-Wl,-z,relro,-z,now`):

- Does the steps of Partial RELRO, plus:
- Causes the linker to resolve all symbols at link time (before starting execution) and then remove write permissions from `.got`.
- `.got.plt` is merged into `.got` with full RELRO, so you won’t see this section name.



## 参考文章

* [**An example of how Procedure Linkage Table Works**](https://bitguard.wordpress.com/2016/11/26/an-example-of-how-procedure-linkage-table-works/)

* [**.plt .plt.got what is different?**](https://stackoverflow.com/questions/58076539/plt-plt-got-what-is-different)

* [**GOT and PLT for pwning**](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html) 

