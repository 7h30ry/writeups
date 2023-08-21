# bite me

## Port Scan

![Screenshot from 2023-08-21 20-58-53](https://github.com/igepaul8/Writeups/assets/51336409/f155cef2-d663-4b7e-abd7-8c1d80d02c33)

We see that Only Port 22 and 80 are open

## The web page

![Screenshot from 2023-08-21 20-47-46](https://github.com/igepaul8/Writeups/assets/51336409/813fd2ae-7788-4cb7-ad40-54aadac93e1a)

Just a normal apache page, So we fuzz for directory

# Fuzzing
I use feroxbuster
![Screenshot from 2023-08-21 20-49-12](https://github.com/igepaul8/Writeups/assets/51336409/842eebea-5751-43cc-ad9a-9fccdf126b38)

the Directory /console is available

![Screenshot from 2023-08-21 21-04-03](https://github.com/igepaul8/Writeups/assets/51336409/45ac10d2-9a52-47f5-a355-cffab214eb5f)

Seeing that we do not have a username or password, We will check the source code first

![Screenshot from 2023-08-21 20-50-40](https://github.com/igepaul8/Writeups/assets/51336409/43756bfd-aa83-409d-ab14-a0f81c87f898)

We see a Javascript function, so after deobfuscating it with JsNIce i was able to read this

![Screenshot from 2023-08-21 20-51-53](https://github.com/igepaul8/Writeups/assets/51336409/43c2ef8d-b2f1-46ba-810f-122646b1ca7a)

It says, "Fred i turnd on php file syntax highlighting for you to review, jason"

So basically what this means is that we probably might have directories with extension .phps which allows us to read the php code for the website

So i decide to navigate to http://<thm-ip>/console/index.phps

![Screenshot from 2023-08-21 20-52-30](https://github.com/igepaul8/Writeups/assets/51336409/5841e86a-ff41-473d-bbc5-2f3dbf5d2c9e)

Seeing that it making a post request after the captcha has been solved and username and password has been inputed the takes us to anoter directory /mfa.php

Moving on we also checked the functions.phps "http://<thm-ip>/console/functions.phps"

![Screenshot from 2023-08-21 20-52-47](https://github.com/igepaul8/Writeups/assets/51336409/085f92f4-0fa4-476c-a1c8-98cafd68d3c4)

So here it is validating the user 
```
function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
```
And comparing the $user to the LOGIN_USER hash, i moved to "http://<thm-ip>/console/config.phps" fot that and got this
```
 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74');

```
So i used thei command to decrypt the hex and go the username
```
echo 6a61736f6e5f746573745f6163636f756e74 | xxd -r -p
jason_test_account
```

The second function in the functions.phps
```
// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
}
```
The is checking the the last three strings of the MD5 hash value of the password if it ends with '001'
So i wrote script for it check the md5.py above
and i got the password corresponding to the md5

So with the username "jason_test_account" and the password "abkr" which i got from the script i logged in to the page

## MFA

![Screenshot from 2023-08-21 21-11-15](https://github.com/igepaul8/Writeups/assets/51336409/01be14d3-3597-472d-acc6-37c8c653ac68)

After looging in we got an MFA so here i just brute force for the password with this bash script brute.sh you can intercept the request and use burpsuite also

So after getting the 4 digit code which was "2672" it might be different for you
I got another web page

![Screenshot from 2023-08-21 21-11-26](https://github.com/igepaul8/Writeups/assets/51336409/db071592-e29f-4650-96f1-efe5f928e5fc)

At the file browser input bar i input just a "/" and it listed the directory

![Screenshot from 2023-08-21 21-12-03](https://github.com/igepaul8/Writeups/assets/51336409/02d1d932-5609-4251-b4c7-3d51dd08bd4e)

so moving forward with that i the directory for jason which had the user.txt flag and the .ssh directory

![Screenshot from 2023-08-21 21-12-39](https://github.com/igepaul8/Writeups/assets/51336409/79b2b1b9-eb09-49f4-b01b-a3375d441380)

so i download the id_rsa for user jason, using the "File viewer"

![Screenshot from 2023-08-21 21-13-52](https://github.com/igepaul8/Writeups/assets/51336409/1af66c7c-3f5c-4890-bf5f-0f5231540fde)

After saving RSA key i had to get the passphrase for the RSA key
```
ssh2john idrsa > hash
john hash -w=/path/to/rockyou.txt 
```
and i got the passphrase 
```
1a2b3c4d
```
after logging in with ssh 

![Screenshot from 2023-08-21 21-25-04](https://github.com/igepaul8/Writeups/assets/51336409/60a49320-d691-4250-bf0a-3efce01f5f3f)


I type sudo -l and that we can run sudo command as fred without password
```
sudo -u fred bash
```
getting shell as fred

![Screenshot from 2023-08-21 22-04-14](https://github.com/igepaul8/Writeups/assets/51336409/a44efde9-cf23-47fa-ac5e-b3f4b4236ac4)

```
(root) NOPASSWD: /bin/systemctl restart fail2ban
```
## Privilege escalation

Humm…. What to do now! In comes Google. 
I look for privilege escalation with fail2ban. Lucky, 
I found an article by Youssef Ichioui *https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7* that clearly explained this vulnerability. 
In a nutshell, if an unprivileged user has the right permissions to the /etc/fail2ban/iptables-multiport.conf file and restart the service with elevated privileges, 
the user can gain elevated privileges by:

1.Changing the command to be executed when an IP address added to the deny list in iptables.

2. Restart fail2ban with elevated privileges

3. Simulating brute force on SSH

4. The evil command will be executed when fail2ban tries to add the incoming IP address to iptables.

Because the command is executed with elevated privileges, 
this will give the unprivileged users full system access to do as they please.

Great, now I got some information to work with. So, 
I look to see if I have written permission to any files in the /etc folder using the find tool and looking recursively in the subdirectories; 
any errors generated will be sent to /dev/null.

## Wrieable

We have write access to The result shows I have to write access to the */etc/fail2ban/action.d* directory 
and the *iptables-multiport.conf* file

## Editing
opening up the *iptables-multiport.conf* file

##actinban
![Screenshot from 2023-08-21 22-52-30](https://github.com/igepaul8/Writeups/assets/51336409/a1d24d2c-511a-4c64-8bb4-554c203a8515)

##actionunban
![Screenshot from 2023-08-21 22-56-29](https://github.com/igepaul8/Writeups/assets/51336409/e7758d2e-8040-4786-a400-99e3343365a5)


Then simulate a brute force attempt on SSH using hydra. 
I increased the thread count using the -t switch for hydra to speed up the process.

![Screenshot from 2023-08-21 22-26-27](https://github.com/igepaul8/Writeups/assets/51336409/7a5050c2-a94f-41d8-90bc-fe9759134e48)

After a few attempts, the SUID bit will be turned on, on the /bin/bash binary. 
I execute /bin/bash -p to get it to stick to the SUID binary. Hello, root.

![Screenshot from 2023-08-21 22-58-51](https://github.com/igepaul8/Writeups/assets/51336409/b86142a2-395a-4e31-9c95-de0b311fdd55)




