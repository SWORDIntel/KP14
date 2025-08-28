
#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import binascii
from Crypto.Cipher import ARC4

def xor_decrypt(data, key):
    """Perform XOR decryption with a key (int or bytes)."""
    if isinstance(key, int):
        return bytes([b ^ key for b in data])
    else:
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def rc4_decrypt(data, key):
    """Decrypt data using RC4 with the given key."""
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <file> <key_spec>")
        print(f"Example: {sys.argv[0]} payload.bin 'xor:9e,rc4:d3a5,xor:0a61200d'")
        sys.exit(1)
    
    file_path = sys.argv[1]
    key_spec = sys.argv[2]
    
    # Parse key specification
    decryption_steps = []
    for step in key_spec.split(','):
        method, key_hex = step.split(':')
        if method == 'xor':
            if len(key_hex) <= 2:
                key = int(key_hex, 16)
            else:
                key = bytes.fromhex(key_hex)
            decryption_steps.append(('xor', key))
        elif method == 'rc4':
            key = bytes.fromhex(key_hex)
            decryption_steps.append(('rc4', key))
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Apply decryption steps
    current_data = data
    step_results = []
    
    for i, (method, key) in enumerate(decryption_steps):
        if method == 'xor':
            current_data = xor_decrypt(current_data, key)
            key_desc = f"{key:02x}" if isinstance(key, int) else key.hex()
            step_results.append(f"xor_{key_desc}")
        elif method == 'rc4':
            current_data = rc4_decrypt(current_data, key)
            step_results.append(f"rc4_{key.hex()}")
    
    # Output file path
    output_dir = Path(file_path).parent
    step_desc = "_".join(step_results)
    output_file = output_dir / f"{Path(file_path).stem}_multi_{step_desc}.bin"
    
    with open(output_file, 'wb') as f:
        f.write(current_data)
    
    print(f"Applied multi-layer decryption: {key_spec}")
    print(f"Output saved to {output_file}")
    
    # Print hex preview
    print("\nHex preview:")
    print(binascii.hexlify(current_data[:64]).decode())
    
    # Print ASCII preview
    print("\nASCII preview:")
    printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in current_data[:64]])
    print(printable)

if __name__ == "__main__":
    main()
