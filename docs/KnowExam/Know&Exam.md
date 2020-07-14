# 知识点&题目索引

## 整数溢出

* bjdctf_2020_babystack2

  > 考         点：整数溢出
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* pwn2_sctf_2016

  > 考         点：整数溢出、ROP
  >
  > 做题笔记：
  >
  > 实验环境：BUU

## ROP（栈溢出）

* jarvisoj_level3

* jarvisoj_tell_me_something

* jarvisoj_level4

* bjdctf_2020_babyrop

* jarvisoj_test_your_memory

* PicoCTF_2018_rop_chain

  > 考         点：简单ROP
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* ez_pz_hackover_2016

  > 考         点：简单ROP、strcmp
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  
* 铁人三项(第五赛区)_2018_rop

* jarvisoj_level1

  > 考         点：简单ROP、write
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* bjdctf_2020_babyrop2

  > 考         点：ret2libc、格式化字符串绕过canary
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* jarvisoj_level3_x64

  > 考         点：ret2csu、write
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  
* pwnable.tw-3x17

* DASCTF五月赛-Memory Monster II

  > 考         点：64位劫持 fini_array进行ROP
  >
  > 做题笔记：
  >
  > 实验环境：pwnable.tw、github

## 栈迁移

* gyctf_2020_borrowstack

  > 考         点：栈迁移、onegedget
  >
  > 做题笔记：https://www.mrskye.cn/archives/14/
  >
  > 实验环境：BUU
  >
  > 备        注：测试不能使用system('/bin/sh')，空间不足，详细看wp

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

* jarvisoj_fm

  > 考         点：格式化字符串、任意地址小数字覆盖
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：可以思考一下如果要求覆盖的是 1 怎么构造

* [RACTF]Finches in a Stack

  > 考         点：格式化字符串、绕过 canary 
  >
  > 做题笔记：https://www.mrskye.cn/archives/138/#FinchesinaStack
  >
  > 实验环境：
  >
  > 备        注：原题为 Ubuntu18，有后门

* [RACTF]Finches in a Pie

  > 考         点：格式化字符串、绕过 canary 、PIE
  >
  > 做题笔记：https://www.mrskye.cn/archives/138/#FinchesinaStack
  >
  > 实验环境：
  >
  > 备        注：原题为 Ubuntu18，有后门

* [BJDCTF 2nd]r2t4

  > 考         点：格式化字符串、__stack_chk_fail
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：与正常绕过 canary 不同的是，故意触发报错；留有后门，难度低于 redpwn2020 dead-canary

* redpwn2020 dead-canary

  > 考         点：格式化字符串、__stack_chk_fail 
  >
  > 做题笔记：[redpwnCTF 2020 pwn部分writeup](https://blog.csdn.net/weixin_43921239/article/details/106951800)
  >
  > 实验环境：[github](https://github.com/skyedai910/CTF_Warehouse/tree/master/2020_redpwnCTF/pwn/dead-canary)
  >
  > 备        注：与[BJDCTF 2nd]r2t4一样主动触发 canary ，没有留后门，需要自己构建 ROP 链（如果用onegadget不需要 ROP）

## 静态编译

* cmcc_simplerop

  > 考         点：系统调用号、简单栈溢出
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* get_started_3dsctf_2016

  > 考         点：mprotect改内存权限、简单栈溢出
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：本地可只用栈溢出、远程需要配合mprotect

* 2017 湖湘杯 pwn300

## 骚东西

* pwnable_orw

  > 考         点：seccomp沙箱、shellcode
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* bjdctf_2020_router

  > 考         点：linux 多指令执行
  >
  > 做题笔记：
  >
  > 实验环境：BUU

* jarvisoj_level1

  > 考         点：linux 多指令执行
  >
  > 做题笔记：
  >
  > 实验环境：BUU
  >
  > 备        注：本地可只写shellcode、远程需要ret2libc

