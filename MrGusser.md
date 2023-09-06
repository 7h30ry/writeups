```
Challenge Name: MrGuesser
Description: I lost my treasures while learning Data Structures and Algorithm can you help me recover it?
Difficulty: Easy
```
# Source code
The code was hosted on a sever but i was given a source code
```
from random import randint

flag = b"IDAN{[REDACTED]}"
guess = randint(1, 500_000_000_000)
#print(guess)
print("Enter the secret number to gain the treasure: ")
counter = 0

try:       
    while counter < 40:
        inp = int(input("Secret Number: "))
        if inp == guess:
            print(f"Weldone you guessed my secret \n Have your flag: {flag}")
            break
        elif inp > guess:
            print("Lower")
        else: 
            print("Higher")       
        counter += 1
        print(f"You have {255 - counter} chances left")
except Exception as e:
    print(f"Got '{e}'. \nPlease enter a valid number.")
```
Bacically what the code does is generate a random number ```guess = randint(1, 500_000_000_000)``` and we are to guess what the number is to get the flag
Seeing that we have a large number and giving only 40 trials ``` while counter < 40```

There wrote a script to solve it using Binary Search Algorithm (You can read up on it to understand what it entails)
I also used pwn tool to connect to the server

# Solve Script
```
from pwn import *
context.log_level = 'INFO'
host = 'ip' # ip address of the serve
port = 1234 # port number
def binary_search_game():
    lower_bound = 1
    upper_bound = 500_000_000_000
    conn = remote(host, port)
    while True: 
        mid = (lower_bound + upper_bound) // 2
        
        conn.sendlineafter("Secret Number: ", str(mid).encode('utf-8'))
        response = conn.recvline().decode('utf-8')
        #print(response)
        log.info(response)
        r = conn.recvline()
        log.info(r)

        if "Have your flag:" in response:
            log.success(response)
            break
        elif "Lower" in response:
            upper_bound = mid - 1
        elif "Higher" in response:
            lower_bound = mid + 1
    conn.close()


if __name__ == "__main__":
    binary_search_game()
```

It was a really fun chall.. Took me about 3hrs to solve :)
