<h3> LITCTF 2024 </h3>

![image](https://github.com/user-attachments/assets/fd31c0ee-7551-4295-9e93-23c24cc9a468)

Hey guys, `0x1337` here.

This writeup contains the challenge to which I solved during the CTF

### Web (5/6)
- Anti-Inspect
- Jwt-1
- Jwt-2
- Traversed
- KirbyTime

### Reversing (4/6)
- Forgotten Message
- Kablewy
- Burger Reviewer
- Revsite1

### Pwn (5/8)
- Function Pairing
- Infinite Echo
- Recurse
- W4dup 2de
- Iloveseccomp


Ok let's start and note that i won't give very detailed solution to some of the challenges

## Web

#### Anti Inspect

![image](https://github.com/user-attachments/assets/22522d4d-bf2e-4314-a110-f22c437621d9)

From the challenge name you can pretty much tell what this is about

Accessing the provided url works but the content doesn't seem to be rendered
![image](https://github.com/user-attachments/assets/241d3496-90cf-449f-b59f-ead079895b5a)

Trying to open dev tools doesn't work because it prevents me from right clicking

I used curl to get the html source
![image](https://github.com/user-attachments/assets/904d328c-2f47-4412-95d8-12901fd7a426)

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <body>
    <script>
      const flag = "LITCTF{your_%cfOund_teh_fI@g_94932}";
      while (true)
        console.log(
          flag,
          "background-color: darkblue; color: white; font-style: italic; border: 5px solid hotpink; font-size: 2em;"
        );
    </script>
  </body>
</html>
```

We can see the flag but that doesn't work when submitted perhaps due to `%c`

I just removed it and it worked

```
Flag: LITCTF{your_fOund_teh_fI@g_94932}
```

#### Jwt-1

![image](https://github.com/user-attachments/assets/b63b3313-9dff-48ae-b41e-19f40ea8644c)

Accessing the provided url shows this
![image](https://github.com/user-attachments/assets/57cd4dee-e5d0-4150-983e-7813080748e8)

If we click `Get Flag` we should get this
![image](https://github.com/user-attachments/assets/71fddc60-7988-4f34-bc8f-ff79f0d45e32)

We can register here
![image](https://github.com/user-attachments/assets/3cfd1abb-55ee-44ca-9cbf-d22b9fe91fe3)

Doing that we should have a valid credential that can get us logged in

Now that we are authentication I checked the cookie available and saw this jwt token
![image](https://github.com/user-attachments/assets/60ad4601-6236-479f-81fd-f1736d11ac23)

I decoded it using [jwt.io](https://jwt.io/)
![image](https://github.com/user-attachments/assets/54deac36-a15e-485e-a363-b4876ffc0578)

```json
{
  "alg": "HS256",
  "typ": "JWT"
}

{
  "name": "pwner123",
  "admin": false
}
```

I just tried changed the `admin` key value to `true` to see if we could access the flag
![image](https://github.com/user-attachments/assets/0bc05d64-8f23-49c5-bd5f-a2081e6f1750)

Ok that works! And it's because it doesn't check for signature validation

```
Flag: LITCTF{o0ps_forg0r_To_v3rify_1re4DV9}
```

#### Jwt-2
![image](https://github.com/user-attachments/assets/5ebdca89-9358-498d-9625-4e7cb50e2b00)

Ok same web app as the previous one but this time we are provided with the source code

I downloaded it and checking it shows this
![image](https://github.com/user-attachments/assets/37f03dea-d5b9-4a45-96c3-ea702ba04c8b)
![image](https://github.com/user-attachments/assets/352fb263-1395-4c0e-b497-d8b4b1c5b14f)
![image](https://github.com/user-attachments/assets/f3384796-7952-426e-ab82-b70825a6d8d4)



















