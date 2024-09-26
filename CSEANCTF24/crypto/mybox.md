## CSEAN CTF 2024

  - Challenge: My Box
  - Solver: Nano (Pwn-Stars)


![image](https://github.com/user-attachments/assets/4076c4fb-a205-4e12-a0fe-9e2caf974e7a)

We are given a zip file which contains the code running on the remote instance
![image](https://github.com/user-attachments/assets/db7bf13c-0059-41b3-8019-c5cbaf0bdbad)
![image](https://github.com/user-attachments/assets/6438ec4e-aea4-46e6-9d4b-2f58eac67e2f)

From the source code i'll start from the main function
![image](https://github.com/user-attachments/assets/ebdc8fb1-ebf3-44c1-9bd0-26478993393d)

We have three options to choose from:
- Generate
- Confirm
- Quit

The third function basically exits the process

![image](https://github.com/user-attachments/assets/bbf8ad00-a20c-4025-97e1-3e7426f48c42)

The second function basically checks if the input received matches the value stored in `e_flag`
![image](https://github.com/user-attachments/assets/997bb0f6-c124-4be7-b466-38caeb4e340b)

That means the main stuff is the "Generate" function
![image](https://github.com/user-attachments/assets/4ac2c877-dae3-4823-91aa-1104385de0a1)
