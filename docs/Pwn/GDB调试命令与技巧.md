## x 查询指令

`x` 指令用于查看内存地址的值，`x`命令语法：

```shell
x/<n/f/u> <target addr>
```

* n ：输出个数
* f ：显示格式。 在 pwn 题中通常都是使用 16 进制查看。
  * x ：十六进制（常用）
  * d ：十进制格式
  * u ：十六进制格式显示无符号整型
  * o ：八进制格式量 
  * t ：二进制格式 
  * c ：字符格式 
  * f ：浮点数格式
* u ：查看字节单元数。在 pwn 题中，根据题目是 32 位还是 64 位灵活切换 w 和 g
  * b ：单字节（8 位，1 个字节）
  * h ：双字节（16 位，2 个字节）
  * w ：字（32位，4 个字节）（常用）
  * g ：大字（64 位，8 个字节）（常用）

可能常用形式：

``x /20xg addr``	查 64 位程序内存信息

``x /20xw addr``	查 32 位程序内存信息

## 查看调用中的堆栈

* ``where``：显示调用堆栈
* ``frame``：显示调用堆栈顶部
* ``up``：向调用堆栈底部移动
* ``down``：向调用堆栈顶部移动

## GDB 调试 PIE 程序



### 方法一：

安装 pwndbg 插件，然后这样下断点：0x相对基址偏移就是 IDA 显示的三位数

```shell
b *$rebase(0x相对基址偏移)
```

### 方法二：

在 /proc 目录中，每个进程都会在此目录下新建一个以进程 id 为名的文件夹，其中存储着进程的动态链接和地址的信息。
在每个进程的 *map_file* 文件夹中，存储着各个地址段的动态链接文件（地址）。

查找当前进程 pid 为 6158 :

```shell
$ ps -aux|grep 程序名
hu         6158  0.0  0.0   4356   632 pts/18   S+   07:50   0:00 ./程序名
hu         6162  0.0  0.0  21292  1088 pts/20   S+   07:51   0:00 grep --color=auto 程序名

```

知道 pid 之后有两种方式获取 elf 机制

#### 方式一：

进入目录 /proc/{pid}/map_files 查询动态链接文件（地址）:

```shell
/proc/6158/map_files$ ls
557d7b317000-557d7b319000  7f0d1da3c000-7f0d1dc3c000  7f0d1de6b000-7f0d1de6c000
557d7b518000-557d7b519000  7f0d1dc3c000-7f0d1dc40000  7f0d1de6c000-7f0d1de6d000
557d7b519000-557d7b51a000  7f0d1dc40000-7f0d1dc42000
7f0d1d87c000-7f0d1da3c000  7f0d1dc46000-7f0d1dc6c000
```

第一个 0x557d7b317000 为 elf 基地址。

真实地址为：0x557d7b317000  + 偏移（ida显示的三位地址）



#### 方式二：

使用 /usr/bin 目录下 pmap 程序。

*pmap + pid*命令可以将该进程的地址信息和相应地址段的权限打印出。

```shell
/usr/bin/pmap 6158
```

### 方法三：

IDA 远程调试

### 与 Pwntools 联动

上面方法都是在命令行启动的 GDB 情况下，如果编写成 exp 脚本调试方法看[这里](# Pwntools 调试 PIE 程序)



## Pwntools 调试 PIE 程序



### 传入明确地址

也就是在 ``gdb.attach(p,"b *真实地址")`` 这样传参。这个真实地址寻址原理在 [GDB 调试 PIE 程序](# GDB 调试 PIE 程序) 提及，在 exp 中就用 os 库执行命令获取并传参。

```python
# 脚本摘选自网络，未找到原作者
from pwn import *
import os
def DEBUG(bps=[],pie =False):
    cmd ='set follow-fork-mode parent\n'
    #cmd=''
    if pie:
        base =int(os.popen("pmap {}|awk '{{print $1}}'".format(p.pid)).readlines()[1],16)
        #base =int(os.popen("pmap -x {0} ".format(p.pid)).readlines()[2][:16],16)
        cmd +=''.join(['b *{:#x}\n'.format(b+base) for b in bps])
    else:
        cmd+=''.join(['b *$rebase({:#x})\n'.format(b) for b in bps])

    # if bps !=[]:
    #     cmd +='c'
    gdb.attach(p,cmd)
```

``base = int(os.popen(“pmap {}| awk ‘{{print $1}}’”.format(io.pid)).readlines()[1], 16)``获取 elf 基地址，根据传入偏移量，给``gdb.attach()``传入指令：``b *当前断点真实地址``。如果 pie 参数为假，传入指令：``b *$rebase(偏移量)``，偏移量是 ida 显示三位地址。

### 传入偏移量

和[传入明确地址](#传入明确地址) DEBUG 函数 pie 为假情况差不多。*但有帖子和我也试了一下，开启 pie 传入 gdb 命令* ``b *$rebase(偏移量)`` *还是能的。*

在你想打断点的前面调用 ``gdb.attach(p,"b *$rebase(偏移量)")``，一般能停下来，但是会停在断点的前面，然后自己手动 step 单步过去咯。

```python
from pwn import *
gdb.attach(p,"b *$rebase(偏移量)")
```



## 单步跟还是会跳过一些指令



比如说 ``call xxx@plt`` 调用 plt 时，step 不会跟进 plt 函数中，改用 **si** 。



## 脚本中 GDB 放置位置



**调用 gdb 有一定时延**

首先明确的在脚本中调用 gdb 并不是准确停在调用这一行，而是会执行到脚本的 下一（或几）行，举个例子：

```python
p.sendline('string1')
gdb.attach(p)
p.sendline('string2')
```

log 中会看到 string2 已经输入了，gdb 才真正进入。



```c
#include<stdio.h>
#include<unistd.h>
int main()
{
	char string1[5]={'h','e','l','l','o'};
	char string2[5]= {'h','e','l','l','o'};
	read(0,string1,5);
	read(0,string2,5);
	printf("%s",string1);
	printf("%s",string1);
 } 
```

假如想将上面这个程序，停在刚输入完而未进入 printf ，基于上面提及的特点，在最后一次输入前调用 gdb 。

```python
from pwn import *
p = process("./pwn")
p.sendline('a'*5)
gdb.attach(p)
p.sendline('a'*5)
```

**总结**：就是在最后一条输入命令前打断点。因为有时延，所以相邻命令也被执行。这种方法应该是用于大部分栈题目。堆题目因为菜单停顿，就直接调用咯。



## GDB 没有调试信息



### 程序已完成

顾名思义，程序已经退出，gdb 当然找不到进程信息。这种情况的几种可能：**栈题目**或者线性的程序（执行完一系列操作就退出）退出了；gdb 调用后面没有其他操作。

### 程序退出情况

提前调用 gdb 咯。且不要再脚本末尾调用 gdb ，就是避免[gdb 后无其他操作](# gdb 后无其他操作)。

### gdb 后无其他操作

可能在堆调试比较常见，就在 gdb.attach() 后面加一行无关操作，比如说调用题目输出函数等，或者直接 sleep(1) ，等 gdb 获取到进程信息就行。


## gdb 查询各内存段权限

在有些题目 ida 分析的内存段权限好像有错误，可以用 gdb 验证。（eg：get_started_3dsctf_2016）

使用命令：

```shell
maintenance info sections
```

例子：

```shell
pwndbg> maintenance info sections
Exec file:
    `/home/skye/buu/get_started_3dsctf_2016/get_started_3dsctf_2016', file type elf32-i386.
 [0]     0x80480f4->0x8048114 at 0x000000f4: .note.ABI-tag ALLOC LOAD READONLY DATA HAS_CONTENTS

```

如果需要在其他窗口调试，需要获取 PID ，具体请看这里：[GDB检查内存权限](https://www.coder.work/article/168338)