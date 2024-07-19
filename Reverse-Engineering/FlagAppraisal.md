<h3> Flag Appraisal (MetaCTF July 2024) </h3>

Hi everyone, this is `0x1337` also known as `h4cky0u`

My github account was placed as spam so i'm currently waiting for Github support to fix it

So today I participated in the MetaCTF Monthly Challenge

And i'll be showing you how I solved the Reverse Engineering challenge called `Flag Appraisal`

![image](https://github.com/user-attachments/assets/84925ab1-e5a8-4afc-8170-ee3c8ffe0b53)

I actually never got to submit the flag because I ended up solving it 3 minutes after the ctf ended due to skill issue and one thing is that the ctf runs for just 2 hours

So less talking and let's get to the main thing

We are given a x64 executable called `pawn_shop`
![image](https://github.com/user-attachments/assets/d05a6885-6700-4192-94f3-abc1462e4e38)

The binary is also stripped so that means we won't have function name 

I ran the binary to get an overview of what it does
![image](https://github.com/user-attachments/assets/ed3a1f37-d643-45ed-aab6-1c4925dc4dcd)

It looks like the right input to solve this is going to be the flag

Time for some static analysis

Using Ghidra I decompiled the binary
