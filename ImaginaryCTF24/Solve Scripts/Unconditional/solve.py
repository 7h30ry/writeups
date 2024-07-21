import string

table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
table2 = [1, 3, 4, 2, 6, 5]

target = [0xb4, 0x31, 0x8e, 0x02, 0xaf, 0x1c, 0x5d, 0x23, 0x98, 0x7d, 0xa3, 0x1e, 0xb0, 0x3c, 0xb3, 0xc4,
          0xa6, 0x06, 0x58, 0x28, 0x19, 0x7d, 0xa3, 0xc0, 0x85, 0x31, 0x68, 0x0a, 0xbc, 0x03, 0x5d, 0x3d, 0x0b]

def brute(flag):
    flag = [i for i in flag]

    counter1 = 0
    counter2 = 0

    final_str = []

    def iterate(i):
        nonlocal counter1, counter2, final_str
        char = flag[i]
        v4 = (i & 1) != 0
        v1 = 0x60 < char <= 0x7A
        if (i & 1) == 0:
            if v1:
                rotated = (char >> table2[counter2]) | (char << (8 - table2[counter2]))
                flag[i] = rotated & 0xFF 
            else:
                rotated = ((char << 6) | (char >> 2)) ^ table1[counter1]
                flag[i] = rotated & 0xFF 
        else:
            if v1:
                flag[i] = (char ^ table1[counter1]) & 0xFF  
            else:
                flag[i] = ((4 * char) | (char >> 6)) & 0xFF 
        counter1 = (v4 + counter1) % 6
        counter2 = (v4 + counter2) % 6
        return i + 1

    i = 0
    while i < len(flag):
        i = iterate(i)
    return flag


flag = [0 for i in target]
all_chars = [[] for i in target]
charset = string.digits + string.ascii_letters + string.punctuation

for i in range(len(target)):
    for c in charset:
        flag[i] = ord(c)
        res = brute(flag)
        if res[i] == target[i]:
            all_chars[i].append(c)
    if len(all_chars[i]) == 0:
        if i == 4:
            flag[i] = ord('{')
        continue
    flag[i] = ord(all_chars[i][0])
    print(''.join(chr(c) for c in flag))

m = max([len(i) for i in all_chars])

for r in range(m):
    for i in range(len(all_chars)):
        if r < len(all_chars[i]):
            print(all_chars[i][r], end='')
        else:
            print('', end='')
    print()
