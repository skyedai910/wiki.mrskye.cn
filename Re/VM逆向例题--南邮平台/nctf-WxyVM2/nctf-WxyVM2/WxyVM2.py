f = open('WxyVM2.txt', 'r')
text = f.read()
f.close()
enc = [0xFFFFFFC0, 0xFFFFFF85, 0xFFFFFFF9, 0x0000006C, 0xFFFFFFE2, 0x00000014, 0xFFFFFFBB, 0xFFFFFFE4, 0x0000000D, 0x00000059, 0x0000001C, 0x00000023, 0xFFFFFF88, 0x0000006E, 0xFFFFFF9B, 0xFFFFFFCA, 0xFFFFFFBA, 0x0000005C, 0x00000037, 0xFFFFFFFF, 0x00000048, 0xFFFFFFD8, 0x0000001F, 0xFFFFFFAB, 0xFFFFFFA5]
ori = text.split(';\n')
ops = []
for s in ori:
    if s.startswith('d'):
        continue
    elif s.startswith('input'):
        t = 'b' + '00' + s[6:8] + s[9:]
        ops.append(t)
    elif s.startswith('b'):
        t = s[:1] + s[9:11] + s[12:14] + s[15:]
        ops.append(t)
    elif s.startswith('--'):
        t = s[2:3] + s[-2:] + '-=1'
        ops.append(t)
    elif s.startswith('++'):
        t = s[2:3] + s[-2:] + '+=1'
        ops.append(t)
    else:
        continue
ops = ops[::-1]

def getPart(op):
    index = int(op[1:3], 16)
    symbol = op[3:4]
    num = op[5:]
    if num.endswith('u'):
        num = num[:-1]
    if num.startswith('0x'):
        num = int(num, 16)
    else:
        num = int(num)
    return index, symbol, num

def cal(index, symbol, num):
    if symbol == '+':
        enc[index] = (enc[index] - num) % 256
    elif symbol == '-':
        enc[index] = (enc[index] + num) % 256
    elif symbol == '^':
        enc[index] = (enc[index] ^ num) % 256
    else:
        print 'error'

for op in ops:
    index, symbol, num = getPart(op)
    # print 'enc[', index, ']', symbol, num
    cal(index, symbol, num)

flag = ''
for i in range(len(enc)):
    flag += chr(enc[i])
print flag