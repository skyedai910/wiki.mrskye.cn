# VM虚拟机

## 介绍

VM就是虚拟机，类属于VMware之类的。而虚拟机是在程序中用代码来实现的一个虚拟系统，用这个虚拟系统来解释一串**字节码**。

通俗的来说，VM就是自己设计一套的指令集和解析指令集的解释器。再简单一点就是自己实现一套汇编语言。

VM设计的主要是的C语言解释器，[手把手教C语言编译器虚拟器设计](<https://lotabout.me/2015/write-a-C-interpreter-2/>)。



一般情况下，需要对整个虚拟解释器结构进行逆向，找出其中定义了什么函数，功能等等，还需要结合提供的字节码进行分析。

> 字节码（Byte-code）是一种包含执行程序，由一序列 op 代码/数据对组成的二进制文件，是一种中间码。被看作是**包含一个[执行程序](https://baike.baidu.com/item/执行程序)的二进制文件**，更像一个对象模型。字节码被这样叫是因为通常每个 opcode 是一字节长，但是指令码的长度是变化的。每个指令有从 0 到 255（或十六进制的： 00 到FF)的一字节[操作码](https://baike.baidu.com/item/操作码)，被参数例如寄存器或内存地址跟随。

![img](https://gss1.bdstatic.com/-vo3dSag_xI4khGkpoWK1HF6hhy/baike/crop%3D0%2C17%2C512%2C338%3Bc0%3Dbaike80%2C5%2C5%2C80%2C26/sign=b769daa0c095d143ce39be634ec0ae33/b64543a98226cffcebd98911b1014a90f703eaa6.jpg)

## 题目类型

VM类题目现在主流是Pwn题，但也有在逆向的题目，少部分也有在杂项。

虽然是有几个方向，但是基本归结起来是两类：

1. 给出可执行程序和字节码，逆向虚拟引擎（定义的函数，进行的操作），结合题目提供的字节码，推出来flag

2. 只给出可执行程序，逆向虚拟引擎（定义的函数，进行的操作），构造字节码，读取flag

   

## 做题技巧

> 来自[一筐萝卜](<https://radishes.top/>)

当在打CTF拿到一个VM题的时候，思路一定清晰，不能盲目的去分析；

1. 分析虚拟机入口，找出来题目提供的字节码
2. 理清虚拟机的结构，逆向处各个handler的意思
3. 根据各个handler来将字节码还原成汇编代码
4. 根据汇编代码推出flag

如果动态调试分析的时候，可能会很复杂，跳来跳去的，所以建议先用IDA来静态分析。

![](https://raw.githubusercontent.com/skyedai910/Picbed/master/img/20191210235228.png)



## 🌰例子

### 红帽杯RHVM

初始化函数打开了 flag 文件，并使用 [dup2](<https://baike.baidu.com/item/dup2>) 将[文件描述符](https://baike.baidu.com/item/文件描述符)重定向到 563 。

```c
fd = open("/flag", 0);
if ( fd == -1 )
{
  puts("What?");
  exit(-1);
}
dup2(fd, 563);
```

在执行完 main 函数后会跳转到这里。如果将stdin的fileno修改为563，那么这里scanf会读取到flag，然后在下一行的printf输出flag。

```c
printf("Could you tell me your name?");
__isoc99_scanf("%99s", &v0);
printf("Goodbye~ %s\n", &v0);
puts("See you next time.");
exit(0);
```

 找到VM定义的入口，逆向出虚拟引擎。找到引擎中定义的 MovDataToReg 和 MovRegToData 可以越界读取Data段。

具体WP，[看这里](http://dittozzz.top/2019/11/25/2019红帽杯final三道pwn的wp/)。



### 红帽杯PVP GAME

程序读取输入后，对输入的字符串进行base64解码

```c
_BYTE *__fastcall Base64Decode(const char *src)
{
  int v2; // [rsp+10h] [rbp-220h]
  int v3; // [rsp+14h] [rbp-21Ch]
  signed __int64 OrignLen; // [rsp+18h] [rbp-218h]
  signed __int64 len; // [rsp+20h] [rbp-210h]
  _BYTE *dest; // [rsp+28h] [rbp-208h]
  int v7[126]; // [rsp+30h] [rbp-200h]
  unsigned __int64 v8; // [rsp+228h] [rbp-8h]

  qmemcpy(v7, &unk_1B60, 0x1ECuLL);
  len = strlen(src);
  if ( strstr(src, "==") )                      // base64
  {
    OrignLen = 3 * (len / 4) - 2;
  }
  else if ( strchr(src, '=') )
  {
    OrignLen = 3 * (len / 4) - 1;
  }
  else
  {
    OrignLen = 3 * (len / 4);
  }
  dest = calloc(1uLL, OrignLen + 1);
  dest[OrignLen] = 0;
  v2 = 0;
  v3 = 0;
  while ( v2 < len - 2 )
  {
    dest[v3] = ((unsigned __int8)v7[(unsigned __int8)src[v2 + 1]] >> 4) | 4 * v7[(unsigned __int8)src[v2]];
    dest[v3 + 1] = ((unsigned __int8)v7[(unsigned __int8)src[v2 + 2]] >> 2) | 16 * v7[(unsigned __int8)src[v2 + 1]];
    dest[v3 + 2] = LOBYTE(v7[(unsigned __int8)src[v2 + 3]]) | ((unsigned __int8)v7[(unsigned __int8)src[v2 + 2]] << 6);
    v3 += 3;
    v2 += 4;
  }
  return dest;
}
```

然后运行defence文件提供的字节码来对输入的code进行检查。最后运行输入的字节码。

```c
for ( j = 0; j <= 15; ++j )
  RunOpcode(Defence, a2, 24LL * j, a4, a5, a6, Code[j].opcode, Code[j].arg1, Code[j].arg2);
return puts("Game Over!");
```

输入的字节码是压入数据和执行函数。因为程序开始就给出了 libc  的地址，所以就解题的关键就是逆向出虚拟引擎的内容。

具体WP，[看这里](http://dittozzz.top/2019/11/25/2019红帽杯final三道pwn的wp/)。



### 南邮WxyVM1

从 main 函数看，就是将 input 加密后与 真·flag 的加密值对比，相同的输出 correct 。

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v4; // [rsp+Bh] [rbp-5h]
  signed int i; // [rsp+Ch] [rbp-4h]

  puts("[WxyVM 0.0.1]");
  puts("input your flag:");
  scanf("%s", &input);
  v4 = 1;
  vm_start();//input加密函数
  if ( strlen(&input) != 24 )
    v4 = 0;
  for ( i = 0; i <= 23; ++i )
  {
    if ( *(&input + i) != enc[i] )
      v4 = 0;
  }
  if ( v4 )
    puts("correct");
  else
    puts("wrong");
  return 0LL;
}
```

也就是说将 vm_start 的加密原理搞出来就好了。函数里面调用了 byte_6010C0 这个数组的15000个元素，其中每三个为一组参加一次循环。byte_6010C0[i] 作为 switch 的操作指令，byte_6010C0[i + 1] 作为 input 的下标，byte_6010C0[i + 2] 作为进行操作的操作数。

```c
__int64 vm_start()
{
  unsigned int v0; // ST04_4
  __int64 result; // rax
  signed int i; // [rsp+0h] [rbp-10h]
  char v3; // [rsp+8h] [rbp-8h]

  for ( i = 0; i <= 14999; i += 3 )
  {
    v0 = byte_6010C0[i];
    v3 = byte_6010C0[i + 2];
    result = v0;
    switch ( v0 )
    {
      case 1u:
        result = byte_6010C0[i + 1];
        *(&input + result) += v3;
        break;
      case 2u:
        result = byte_6010C0[i + 1];
        *(&input + result) -= v3;
        break;
      case 3u:
        result = byte_6010C0[i + 1];
        *(&input + result) ^= v3;
        break;
      case 4u:
        result = byte_6010C0[i + 1];
        *(&input + result) *= v3;
        break;
      case 5u:
        result = byte_6010C0[i + 1];
        *(&input + result) ^= *(&input + byte_6010C0[i + 2]);
        break;
      default:
        continue;
    }
  }
  return result;
}
```

到这里基本已经清楚了，把数据都dump下来，写个脚本逆一下就ok了。然后还需要注意的是，这里的运算是以byte为单位，可能会产生溢出，所以应该每次操作之后模一下256。

具体WP，[看这里](<https://www.52pojie.cn/forum.php?mod=viewthread&tid=828110>)。

 

### 南邮WxyVM2

程序的基本情况与 WxyVM1 相同，最大的不同就是VM虚拟引擎。这道题使用的是 dword_69417c ~ dword_6941dc 数组的多次混合运算。