def decrypt(enc_hex):
    encrypted_bytes = bytes.fromhex(enc_hex)
    length = len(encrypted_bytes)

    
    decrypted_chars = list(encrypted_bytes)

    
    if length > 0:
        decrypted_chars[length - 1] ^= 0x80

    for i in range(length - 2, -1, -1):
        decrypted_chars[i] ^= decrypted_chars[i + 1]

   
    decrypted_string = ''.join(chr(c) for c in decrypted_chars if c != 0)

    return decrypted_string

# Example usage:
enc_hex = input("[+] Enter hex string to decipher: ")
decrypted_text = decrypt(enc_hex)
print(f"[+] Deciphered Text: {decrypted_text}")
