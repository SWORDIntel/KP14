#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import binascii
from Crypto.Cipher import ARC4

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <file> <key_hex>")
        print(f"Example: {sys.argv[0]} payload.bin 9ed3a5")
        sys.exit(1)
    
    file_path = sys.argv[1]
    key_hex = sys.argv[2]
    
    # Convert key to bytes
    key = bytes.fromhex(key_hex)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Decrypt with RC4
    cipher = ARC4.new(key)
    decrypted = cipher.decrypt(data)
    
    # Output file path
    output_dir = Path(file_path).parent
    output_file = output_dir / f"{Path(file_path).stem}_rc4_{key_hex}.bin"
    
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    
    print(f"Decrypted file with RC4 key {key_hex}")
    print(f"Output saved to {output_file}")
    
    # Print hex preview
    print("\nHex preview:")
    print(binascii.hexlify(decrypted[:64]).decode())
    
    # Print ASCII preview
    print("\nASCII preview:")
    printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in decrypted[:64]])
    print(printable)

if __name__ == "__main__":
    main()
