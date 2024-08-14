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

First it imports some libraries

![image](https://github.com/user-attachments/assets/b2aa729a-27a4-459d-a134-90757f8963e5)

This is basically used for signing a jwt payload

![image](https://github.com/user-attachments/assets/178a1758-30d2-4b1a-85c0-0cef81049fc8)

Starts the web app to listen on port 3000 or the port specified in the environment variable

![image](https://github.com/user-attachments/assets/17e72ba8-1af4-480f-8012-b6da13ca61b2)

Let's take a look at the routes now:

- Login: It's going to make sure it's a valid user then sign the username and setting admin to `false`
  
![image](https://github.com/user-attachments/assets/c9d73009-7a1f-408f-b95a-aa23a7540888)

- Signup: It's going to basically just add the user to the accounts array and sign the username and setting admin to `false`

![image](https://github.com/user-attachments/assets/21b734aa-87b5-4eee-8122-f58b9fdf5753)

- Flag:  It's going to make sure the token is prevent then verifies the signature and make sure the username is set to admin meaning it's checking if `admin` is set to `true`

![image](https://github.com/user-attachments/assets/17606190-8267-432d-a6e3-5b03610ab8a2)

Because this verification does check the signature we can't go around this except via setting `admin` to `true`

We can easily do that because we know the jwt secret 

I wrote a [script](https://github.com/7h30ry/writeups/blob/main/LITCTF%202024/Solve%20Scripts/JWT-2/generate.js) to generate a token for me
![image](https://github.com/user-attachments/assets/00311e7d-0400-457f-86d0-86ee0acc517e)

That's pretty much just copy paste from the original server code with some modification

Running it i get a token and i used that to get the flag
![image](https://github.com/user-attachments/assets/b0e38e36-d324-4501-8e3d-c29b3f24e85f)

```
Flag: LITCTF{v3rifyed_thI3_Tlme_1re4DV9}
```

#### Traversed
![image](https://github.com/user-attachments/assets/36ba1ec0-f2b5-4394-9802-11cd84fa8f10)

Accessing the provided url shows this

From the challenge name you can probably tell this is going to be some sort of LFI
![image](https://github.com/user-attachments/assets/709051c1-e0e4-424d-af23-fc3638cded9f)

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <body>
    Welcome! The flag is hidden somewhere... Try seeing what you can do in the url bar.
    There isn't much on this page...
  </body>
</html>
```

The description on the web page suggests that we should play around with the url bar

I just guessed the parameter to be `page` and i was able to include any file
![image](https://github.com/user-attachments/assets/9e9a0d99-f305-45d2-aec2-00138218bf3f)

You could as well attempted to fuzz?

```
ffuf -c -u "http://litctf.org:31778/?FUZZ=../../../../../etc/passwd" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 117,965 -mc all
```

But doing that I got this
![image](https://github.com/user-attachments/assets/c173c0b3-f8b9-4a4d-af10-e914266ebea8)

Well i guess we just needed to guess the parameter

Ok now that we can include any file where's the flag

The challenge didn't specify the flag name nor the location so we need to figure that

I assumed the name would be `flag.txt`

Moving on I checked the content of `/etc/passwd`
![image](https://github.com/user-attachments/assets/34e735d8-1935-4e4b-a297-5149d141f056)

We have a user called `node` so I checked the directory if the flag is there but it wasn't
![image](https://github.com/user-attachments/assets/44bf9286-ca68-43f3-85bf-e75160e2c5e6)

I also tried to retrieve the web app source code but that failed
![image](https://github.com/user-attachments/assets/fd324fd4-6458-4e59-9737-0959abae6402)
![image](https://github.com/user-attachments/assets/10fd0e85-161e-4497-863f-95184ec0dc13)


Next thing i did was to read the environment variable file
![image](https://github.com/user-attachments/assets/a785a32b-1547-4bd9-9728-74828297bd9d)

It downloaded and i checked the content
![image](https://github.com/user-attachments/assets/e80cc063-793c-4957-91cb-7cb3aef00a64)

```
NODE_VERSION=16.20.2
HOSTNAME=ac58ff1071df
YARN_VERSION=1.22.19
BUN_INSTALL=/root/.bun
HOME=/root
PATH=/root/.bun/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/app
```

The path to this web app on the filesystem is `/app`

So i checked for the flag there
![image](https://github.com/user-attachments/assets/497a2106-3c01-40c1-89d2-662893ec572a)

We could have also gotten that using this
![image](https://github.com/user-attachments/assets/a924f50e-2fda-4c80-92d2-2c7ac85a6bc9)

```
Flag: LITCTF{backtr@ked_230fim0}
```






