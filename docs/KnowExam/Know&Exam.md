# 知识点&题目索引

## 整数溢出

* pwn2_sctf_2016

  > 考点		：整数溢出、ROP
  >
  > 做题笔记：
  >
  > 实验环境：BUU

## ROP

* ez_pz_hackover_2016

  > 考         点：简单ROP、strcmp
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  
* 铁人三项(第五赛区)_2018_rop

  > 考         点：简单ROP、write
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* bjdctf_2020_babyrop

  > 考         点：简单ROP
  >
  > 做题笔记：
  >
  > 实验环境：BUU

## 栈迁移

* [Black Watch 入群题]PWN-spwn

  > 考         点：栈迁移
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：这条题目注意 puts 和 write 所需栈空间的大小与写入 bss 的位置关系
  
* ciscn_2019_es_2

  > 考         点：简单栈迁移
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：注意 /bin/sh 写入位置与栈生长方向

## 格式化字符串

* [BJDCTF 2nd]r2t4

  > 考         点：格式化字符串、__stack_chk_fail
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：与正常绕过 canary 不同的是，故意触发报错；留有后门，难度低于 redpwn2020 dead-canary

* redpwn2020 dead-canary

  > 考         点：格式化字符串、__stack_chk_fail 、栈迁移
  >
  > 做题笔记：[redpwnCTF 2020 pwn部分writeup](https://blog.csdn.net/weixin_43921239/article/details/106951800)
  >
  > 实验环境：[github](https://github.com/skyedai910/CTF_Warehouse/tree/master/2020_redpwnCTF/pwn/dead-canary)
  >
  > 备        注：与[BJDCTF 2nd]r2t4一样主动触发 canary ，没有留后门，需要自己构建 ROP 链（如果用onegadget不需要 ROP）

