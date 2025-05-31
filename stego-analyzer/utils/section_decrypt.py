#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import binascii

def xor_decrypt(data, key):
    """Perform XOR decryption with a key (int or bytes)."""
    if isinstance(key, int):
        return bytes([b ^ key for b in data])
    else:
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def main():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <file> <start_offset> <end_offset> <key_hex>")
        print(f"Example: {sys.argv[0]} payload.bin 0xE680 0xE800 9e")
        sys.exit(1)
    
    file_path = sys.argv[1]
    start_offset = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2])
    end_offset = int(sys.argv[3], 16) if sys.argv[3].startswith('0x') else int(sys.argv[3])
    key_hex = sys.argv[4]
    
    # Convert key to bytes or int
    if len(key_hex) <= 2:
        key = int(key_hex, 16)
    else:
        key = bytes.fromhex(key_hex)
    
    with open(file_path, 'rb') as f:
        f.seek(start_offset)
        section_data = f.read(end_offset - start_offset)
    
    decrypted = xor_decrypt(section_data, key)
    
    # Output file path
    output_dir = Path(file_path).parent
    output_file = output_dir / f"{Path(file_path).stem}_section_{start_offset:x}_{end_offset:x}_{key_hex}.bin"
    
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    
    print(f"Decrypted section [{start_offset:x}-{end_offset:x}] with key {key_hex}")
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
