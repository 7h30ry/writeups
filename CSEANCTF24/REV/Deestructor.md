**Solved by: Logs**

I started straight with decompiling the binary in IDA
Looking at the main() function we see that running the code does nothing

![image](https://github.com/user-attachments/assets/2e17c594-ea51-43f0-89e2-25b06ba200c4)

So we move on to checking one functions. But checking all the functions in there pseudo-code yielded nothing so I checked again but in assembly

and I found this function, the second function after the main function

```
mov     rdi, 6E4E1712h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 66180757h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 6D131855h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 5F1B4414h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 5F061A05h
xor     rdi, r8
xor     rdi, rdi
; Attributes: bp-based frame

sub_40181F proc near
; __unwind {
push    rbp
mov     rbp, rsp
xor     r8, r8
mov     r8, 637466h
xor     rdi, rdi
mov     rdi, 63101107h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 721A0412h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 31531A39h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 680A1002h
xor     rdi, r8
xor     rdi, rdi
mov     rdi, 330D551Bh
xor     rdi, r8
nop
pop     rbp
retn
; } // starts at 40181F
sub_40181F endp
```

I noticed the hex in the assembly and o decode the first one ```6E4E1712 = ctf```, which, so following up the assembly using python I ended up with this 

![image](https://github.com/user-attachments/assets/9670566c-bc75-47d5-9279-194c60dc8cfc)

Which I just decided to complete the flag from there
