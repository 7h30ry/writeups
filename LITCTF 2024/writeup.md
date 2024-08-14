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

### Reversing (5/6)
- Forgotten Message
- Kablewy
- Burger Reviewer
- Revsite1
- Watchdog

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
























