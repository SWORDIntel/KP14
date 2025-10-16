#!/usr/bin/env python3
import os
import sys
import binascii

def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm (KSA)"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, data):
    """RC4 Pseudo-Random Generation Algorithm (PRGA)"""
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)

def rc4_encrypt(key, data):
    """RC4 encryption/decryption function"""
    if isinstance(key, str):
        key = [ord(c) for c in key]
    elif isinstance(key, int):
        key = [key]
    elif isinstance(key, bytes):
        key = list(key)
    
    # Convert hex strings to bytes if needed
    if all(c in '0123456789abcdefABCDEF' for c in str(key)):
        try:
            key = binascii.unhexlify(str(key))
            key = list(key)
        except:
            pass
    
    S = rc4_ksa(key)
    return rc4_prga(S, data)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <key>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    key = sys.argv[2]
    
    # Handle hex string keys
    if key.startswith("0x"):
        key = int(key, 16)
    elif all(c in '0123456789abcdefABCDEF' for c in key) and len(key) % 2 == 0:
        key = binascii.unhexlify(key)
    
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Process key
        if isinstance(key, str):
            key_bytes = key.encode()
        elif isinstance(key, int):
            key_bytes = bytes([key])
        else:
            key_bytes = key
            
        decrypted = rc4_encrypt(key_bytes, data)
        
        output_file = f"{input_file}_rc4_simple_{key}.bin"
        with open(output_file, 'wb') as f:
            f.write(decrypted)
        
        print(f"Decrypted file with RC4 key {key}")
        print(f"Output saved to {output_file}")
        
        # Show hex preview
        hex_preview = binascii.hexlify(decrypted[:64]).decode()
        print("\nHex preview:")
        print(hex_preview)
        
        # Show ASCII preview
        ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted[:64])
        print("\nASCII preview:")
        print(ascii_preview)
        
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
