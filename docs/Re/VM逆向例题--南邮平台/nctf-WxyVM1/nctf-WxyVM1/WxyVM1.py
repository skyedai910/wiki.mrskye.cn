import re
f = open('WxyVM1.txt', 'r')
enc = [0xFFFFFFC4, 0x00000034, 0x00000022, 0xFFFFFFB1, 0xFFFFFFD3, 0x00000011, 0xFFFFFF97, 0x00000007, 0xFFFFFFDB, 0x00000037, 0xFFFFFFC4, 0x00000006, 0x0000001D, 0xFFFFFFFC, 0x0000005B, 0xFFFFFFED, 0xFFFFFF98, 0xFFFFFFDF, 0xFFFFFF94, 0xFFFFFFD8, 0xFFFFFFB3, 0xFFFFFF84, 0xFFFFFFCC, 0x00000008]
text = f.read()
f.close()
pat = re.compile(r'db.{5}')
find_pat = pat.findall(text)
nums = []
for n in find_pat:
    n = n[2:]
    n = n.strip()
    if n.endswith('h'):
        n = int(n[:-1], 16)
    else:
        n = int(n)
    nums.append(n)

def cal(v0, v3, index):
    if v0 == 1:
        enc[index] = (enc[index] - v3) % 256
    elif v0 == 2:
        enc[index] = (enc[index] + v3) % 256
    elif v0 == 3:
        enc[index] = (enc[index] ^ v3) % 256
    elif v0 == 4:
        enc[index] = (enc[index] / v3) % 256
    elif v0 == 5:
        enc[index] = (enc[index] ^ enc[v3]) % 256

for i in range(5000):
    t = 5000 - i
    v0 = nums[3 * t - 3]
    v3 = nums[3 * t - 1]
    res = nums[3 * t - 2]
    cal(v0, v3, res)
flag = ''
for i in range(len(enc)):
    flag += chr(enc[i])
print flag