# Libc2.29 unlink Attack

## unsortbin 变化

libc2.23 没有对 unsortedbin 进行完整性检查：

```c
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);
```

libc2.29 增加了完整性检查：

```c
/* 开始遍历整理unsorted bin将堆块放入对应各种bin中*/
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          /* 提取倒数第二个chunk */
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          /* libc2.29新增完整性检查 */
          if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

## 原理

当 malloc、calloc 之类的从 smallbin 中取堆块时，取出成功后，如果 tcache 没有满就会将 smallbin 剩下的堆块放入 tcache 中，：

```c
  /* malloc从small bin取空间 */
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      /* 对应大小small bin不为空时 */
      if ((victim = last (bin)) != bin)
        {
          /* 提前后一个chunk */
          bck = victim->bk;
    /* 检查后一个chunk fd指针是否指向当前chunk，防止伪造 */
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          /* 设置inuse位 */
          set_inuse_bit_at_offset (victim, nb);
          /* unlink取出victim */
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
    /* 当前size smallbin还有堆块时，将剩下smallbin放入对应大小tcache。前提是tcache有空余位置 */
    /* 获取size对应的tcache序号 */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
        /* 检查tcache有没有满和smallbin有没有剩余堆块 */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
          /* 提取即将放入tcache堆块的后一块chunk */
		      bck = tc_victim->bk;
          /* 设置标志位 */
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
          /* 直接unlink将tc_victim取出，没有完整性检查 */
		      bin->bk = bck;
		      bck->fd = bin;

          /* 将tc_victim放入tcache */
		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

smallbin 剩余堆块 unlink 取出没有进行检查：

```c
if (tc_victim != 0)
		    {
          /* 提取即将放入tcache堆块的后一块chunk */
		      bck = tc_victim->bk;
          /* 设置标志位 */
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
          /* 直接unlink将tc_victim取出，没有完整性检查 */
		      bin->bk = bck;
		      bck->fd = bin;
```

涉及利用的几条关键语句：

```c
bck = tc_victim->bk;
bin->bk = bck;
bck->fd = bin;
```

bin 是一个 libc 地址，也就是 0x7f 开头的 6 位地址。

当劫持 ``tc_victim->bk`` 也就是控制 ``bck`` 为我们``攻击地址-0x10``，``bck->fd = bin;`` 将 bin 写入攻击地址。实现效果为：

```c
*(target-0x10)=bin
```

攻击完成（放入一个堆块）后，这时原来的链表被打乱无法取出下一个堆块，所以攻击前需要让对应大小 tcache 数量为 6 ，放入一个堆完成攻击就退出循环不再放入堆块，就不会报错退出。

为了不报错需要同一大小堆块在 **``tcache``有 6 个**、**``smallbin``有 2 个**。因为 tcache 机制，tcache 没有满时被释放堆块是放不进 smallbin 。 

用切割 unsortedbin 方法在 smallbin 放入两个堆块，即 **last remainder**。就是在 unsortedbin 拿了一大块堆块，如果用剩下的大于 remainder_size ，就将剩下的放到对应的 bin 中。

```c
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```

假设 unsortedbin 中有一个 0x400 堆，malloc 0x300 后，unsorbin 剩下 0x100 。这时 malloc 一个比 0x100 大的空间，系统遍历 unsortedbin 将各个堆块放入对应的 bin 中，0x100 顺利放入 smallbin。

堆布置图示：

![Libc2.29 unlink Attack](https://gitee.com/mrskye/Picbed/raw/master/img/20201124204915.png)

chunk1 fd 指针需要是 chunk0 地址，用来绕过 chunk0 分配时的检查：

```c
    /* 检查后一个chunk fd指针是否指向当前chunk，防止伪造 */
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
```

## 总结

![Libc2.29 unlink Attack](https://gitee.com/mrskye/Picbed/raw/master/img/20201124204915.png)

使用前提：

1. UAF：用于修改 chunk1 的 bk
2. 有能够跳过 tcache 申请堆的函数或机制：触发 smallbin unlink 放入 tcache 
3. 能泄露堆地址：chunk1 fd 填为 chunk0 地址，让 chunk0 成功分配

实现效果：

任意地址写入一个 libc 地址（0x7fxxxxxxxxxx)

应用：

可以参考 libc2.23 unlink

## 相关例题

HITCON CTF 2019 Quals — One Punch Man 

[Black Watch 入群题]PWN2

## 参考文章

[HITCON CTF 2019 Quals — One Punch Man ](https://medium.com/@ktecv2000/hitcon-ctf-2019-quals-one-punch-man-pwn-292pts-3e94eb3fd312)

[HITCON2019-Quals One_punch_Man](https://ruan777.github.io/2020/02/04/HITCON2019-Quals-One-punch-Man/)

[glibc2.29下unsortedbin_attack的替代方法](https://blog.csdn.net/qq_38154820/article/details/106294152)