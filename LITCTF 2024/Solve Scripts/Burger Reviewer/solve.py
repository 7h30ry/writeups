import string

def cheese(s):
    idx = {13: '_', 17: chr(95), 19: '_', 26: chr(190-ord('_')), 29: '_', 34: chr(90+5), 39: '_'}
    for key, val in idx.items():
        s[key] = val
    return s

def _meat(s):
    m = 41
    meat = ['n', 'w', 'y', 'h', 't', 'f', 'i', 'a', 'i']
    dif = [4, 2, 2, 2, 1, 2, 1, 3, 3]
    for i in range(len(meat)):
        m -= dif[i]
        s[m] = meat[i]
    return s

def veggies(s):
    idx = {
        22: '2',
        23: '2',
        15: '4',
        12: '5',
        10: '9',
        25: '5',
        32: '3',
        36: '4',
        38: '7', 
        40: '2'
    }
    for key, val in idx.items():
        s[key] = val
    return s

def pizzaSauce(s):
    sauce = ['b', 'p', 'u', 'b', 'r', 'n', 'r', 'c']
    isDigit = [False, False, False, True, False, True, False, False, True, False, False, False, False, False]
    a, b, i = 7, 20, 0

    for j in range(7, 21):
        assert (s[j].isdigit() == isDigit[j - 7])

    while a < b:
        s[a] = sauce[i]
        s[b] = sauce[i + 1]
        a += 1
        b -= 1
        i += 2

        while a < b and s[a] not in string.ascii_letters:
            a += 1
        while a < b and s[b] not in string.ascii_letters: 
            b -= 1
    
    return s

flag = list("LITCTF{" + "X"*34 + "}")
cheesed = cheese(flag)
meat_r = _meat(cheesed)
veggie = veggies(meat_r)
final_flag = pizzaSauce(veggie) 
print(''.join(final_flag))
