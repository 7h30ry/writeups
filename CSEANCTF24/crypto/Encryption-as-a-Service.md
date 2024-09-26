we were given a challenge.py script

```python
#!/usr/bin/env python3
import random
import time

flag = b"csean-ctf{[redacted]}24"
e_flag = b""


def menu():
    print("1. Generate flag")
    print("2. Confirm flag")
    print("3. Exit")
    try:
        choice = int(input("> "))
        return choice
    except Exception:
        print("Invalid choice")
        exit()


def generate():
    global e_flag

    key = random.randint(0, 0x100)
    ct = int(time.time())
    random.seed(ct)
    sbox = list(range(256))
    random.shuffle(sbox)

    s = []

    for val in flag:
        r = key
        while val:
            r = sbox[r]
            val -= 1
        s.append(r)

    e_flag = bytes(s)

    print(f'Encrypted flag: {e_flag.hex()}')


def confirm():
    print(e_flag)
    print(f"DEBUG:: Current time: {int(time.time())}")
    s1 = input("Enter flag to check: ")
    if len(e_flag) == 0:
        print("Nothing to validate with")
        return
    else:
        print("Checking...")
        msg = s1.encode()
        if msg == e_flag:
            exit("You got it right")
        else:
            print("Hmmm try better")


def quit():
    exit("Good bye")


def main():
    while True:
        choice = menu()
        if choice == 1:
            generate()
        elif choice == 2:
            confirm()
        elif choice == 3:
            quit()


if __name__ == '__main__':
    main()
```

functionality:

Menu System: The program displays a simple menu with three options:

Generate an encrypted flag.
Confirm if the input matches the encrypted flag.
Exit the program.
Flag Encryption (in generate() function):

The generate() function encrypts the hardcoded flag (b"csean-ctf{[redacted]}24") using a basic transformation.
A random key is generated (an integer between 0 and 255), and the current time (in seconds since epoch) is used as the seed for shuffling a substitution box (sbox) that contains numbers from 0 to 255.
For each byte of the flag, the program uses a loop that replaces the byte value by iterating through the shuffled sbox using the key.
The result is stored in e_flag, which holds the encrypted flag in a byte string format.
Flag Confirmation (in confirm() function):

The user can enter a flag to compare against the encrypted flag stored in e_flag.
If the user-provided input matches e_flag, the program exits with a success message ("You got it right"), otherwise, it prompts the user to try again.
Exit: The program can be exited by selecting the "Exit" option or by confirming a correct flag.

Key Insights:
The encryption process is based on a random key and a substitution box, making it non-deterministic unless the same time seed and key are used.
The confirm() function compares the encrypted flag byte-for-byte, so the user must input the correct encrypted flag to win the challenge.

so now we write the solve script

```python
def to_bytes(h):
    return bytes.fromhex(h)

def to_hex(b):
    return b.hex()

def decrypt(enc, secret):
    """Decrypts the given encrypted flag with the provided secret."""
    msg = to_bytes(enc)
    return bytes([msg[i] ^ ((secret + i) % 256) for i in range(len(msg))])

# The encrypted flag (from showFlag output)
encrypted_flag_hex = "4958494c4002534554484c05446840094864440d4c6071321d2074750a3a7a7d"

# Flag prefix
flag_prefix = "csean-ctf{"

# Try every possible byte value for the secret
for secret in range(256):
    decrypted_flag = decrypt(encrypted_flag_hex, secret).decode(errors='ignore')
    
    # Check if the decrypted flag starts with the known prefix
    if decrypted_flag.startswith(flag_prefix):
        print(f"Found secret byte: {secret} -> Decrypted flag: {decrypted_flag}")
```

the hex being the value we got from the server
