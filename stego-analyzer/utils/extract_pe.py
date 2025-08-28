#!/usr/bin/env python3
"""
Extract PE files from binary data based on MZ signatures
"""
import os
import sys
import binascii

def extract_pe(input_file, output_dir):
    """Extract potential PE files from binary data"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Find all MZ signatures
    mz_offsets = []
    offset = 0
    while True:
        offset = data.find(b'MZ', offset)
        if offset == -1:
            break
        mz_offsets.append(offset)
        offset += 2
    
    print(f"Found {len(mz_offsets)} potential PE files at offsets: {mz_offsets}")
    
    # Extract each potential PE file
    for i, start_offset in enumerate(mz_offsets):
        # Determine end offset (next MZ or end of file)
        if i + 1 < len(mz_offsets):
            end_offset = mz_offsets[i + 1]
        else:
            end_offset = len(data)
        
        # Extract the PE file
        pe_data = data[start_offset:end_offset]
        
        # Save to file
        output_file = os.path.join(output_dir, f"extracted_pe_{start_offset:08x}.bin")
        with open(output_file, 'wb') as f:
            f.write(pe_data)
        
        print(f"Extracted potential PE file from offset 0x{start_offset:X} to 0x{end_offset:X}")
        print(f"Saved to: {output_file}")
        print(f"Size: {len(pe_data)} bytes")
        
        # Print hex preview
        hex_preview = binascii.hexlify(pe_data[:64]).decode()
        print(f"Hex preview: {hex_preview}")
        
        # Print ASCII preview
        ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in pe_data[:64])
        print(f"ASCII preview: {ascii_preview}")
        print("-" * 80)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_dir>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    extract_pe(input_file, output_dir)

if __name__ == "__main__":
    main()
