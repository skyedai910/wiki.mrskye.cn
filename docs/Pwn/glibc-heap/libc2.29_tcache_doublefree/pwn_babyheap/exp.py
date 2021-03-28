from pwn import *
context(log_level='debug',arch='amd64',os='linux',
	terminal=['tmux','sp','-h'])

p = process(["/lib/x86_64-linux-gnu/ld-2.27.so", "./pwn"], env={"LD_PRELOAD":"./libc.so.6"})

def command(id):
	p.recvuntil(">>")
	p.sendline(str(id))
def add(id,size):
	command(1)
	p.recvuntil("index")
	p.sendline(str(id))
	p.recvuntil("size")
	p.sendline(str(size))
def delete(id):
	command(2)
	p.recvuntil("index")
	p.sendline(str(id))
def edit(id,content):
	command(3)
	p.recvuntil("index")
	p.sendline(str(id))
	p.recvuntil("content")
	p.send(content)
def show(id):
	command(4)
	p.recvuntil("index")
	p.sendline(str(id))
def leave_name():
	command(5)
def show_name():
	command(6)


add(0,0x60)

gdb.attach(p)








p.interactive()
