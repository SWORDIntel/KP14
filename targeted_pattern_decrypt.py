#!/usr/bin/env python3
"""
Targeted Pattern-Based Decryption for KEYPLUG Malware
Specifically targeting the a2800a28 pattern identified in the encrypted payload
"""
import os
import sys
import binascii
import hashlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter

# The key pattern we identified
TARGET_PATTERN = bytes.fromhex("a2800a28")
KNOWN_KEYS = {
    "9e": b'\x9e',
    "d3": b'\xd3',
    "a5": b'\xa5',
    "a2800a28": bytes.fromhex("a2800a28")
}

def find_pattern_offsets(data, pattern):
    """Find all occurrences of a pattern in data"""
    offsets = []
    offset = 0
    while True:
        offset = data.find(pattern, offset)
        if offset == -1:
            break
        offsets.append(offset)
        offset += 1  # Overlapping search
    
    return offsets

def extract_sections_around_pattern(data, pattern, context_size=256):
    """Extract sections of data surrounding pattern occurrences"""
    offsets = find_pattern_offsets(data, pattern)
    sections = []
    
    for offset in offsets:
        start = max(0, offset - context_size)
        end = min(len(data), offset + len(pattern) + context_size)
        sections.append((offset, data[start:end]))
    
    return sections

def xor_with_pattern(data, pattern):
    """XOR data with repeating pattern"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ pattern[i % len(pattern)]
    
    return bytes(result)

def try_key_combinations(section, known_keys):
    """Try various combinations of known keys on a section"""
    results = []
    
    # Try single keys
    for key_name, key in known_keys.items():
        decrypted = xor_with_pattern(section, key)
        # Check if result looks promising
        score = score_result(decrypted)
        results.append((key_name, score, decrypted))
    
    # Try key combinations (concatenated)
    for key1_name, key1 in known_keys.items():
        for key2_name, key2 in known_keys.items():
            if key1 != key2:
                combined_key = key1 + key2
                combined_name = f"{key1_name}+{key2_name}"
                decrypted = xor_with_pattern(section, combined_key)
                score = score_result(decrypted)
                results.append((combined_name, score, decrypted))
    
    # Sort by score (higher is better)
    return sorted(results, key=lambda x: x[1], reverse=True)

def score_result(data):
    """Score a decryption result by potential validity"""
    score = 0
    
    # Check for MZ/PE signature
    if data[:2] == b'MZ':
        score += 10
        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if 0 < pe_offset < len(data) - 4:
                if data[pe_offset:pe_offset+4] == b'PE\0\0':
                    score += 20
        except:
            pass
    
    # Check for high concentration of printable ASCII
    printable_count = sum(32 <= b <= 126 for b in data)
    printable_ratio = printable_count / len(data)
    if printable_ratio > 0.7:
        score += 5
    
    # Check for common executable instructions (x86)
    common_opcodes = [b'\x55\x8b\xec', b'\x33\xc0', b'\x8b\xff', b'\xc3', b'\x90\x90\x90']
    for opcode in common_opcodes:
        if opcode in data:
            score += 3
    
    # Check for strings
    strings = find_strings(data)
    if len(strings) > 5:
        score += len(strings) // 5  # More strings = higher score
    
    # Check for low entropy (decrypted data often has lower entropy)
    entropy = calculate_entropy(data)
    if 0.6 <= entropy <= 0.85:
        score += 5
    
    return score

def find_strings(data, min_length=4):
    """Find printable ASCII strings in binary data"""
    strings = []
    current = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ""
    
    # Don't forget the last string
    if len(current) >= min_length:
        strings.append(current)
    
    return strings

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    counter = Counter(data)
    data_len = len(data)
    
    for count in counter.values():
        p_x = count / data_len
        entropy += -p_x * np.log2(p_x)
    
    return entropy / 8.0  # Normalize to [0,1]

def visualize_pattern_distribution(data, pattern):
    """Visualize the distribution of a pattern in the data"""
    offsets = find_pattern_offsets(data, pattern)
    
    if not offsets:
        print(f"Pattern {binascii.hexlify(pattern).decode()} not found in data")
        return
    
    # Calculate distances between consecutive occurrences
    distances = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
    
    # Plot the distribution
    plt.figure(figsize=(12, 6))
    
    # Plot 1: Pattern offsets
    plt.subplot(2, 1, 1)
    plt.plot(offsets, [1] * len(offsets), 'o', markersize=4)
    plt.xlabel('File Offset')
    plt.ylabel('Occurrence')
    plt.title(f'Pattern {binascii.hexlify(pattern).decode()} Offsets')
    plt.grid(True)
    
    # Plot 2: Distance between occurrences
    if distances:
        plt.subplot(2, 1, 2)
        plt.hist(distances, bins=30)
        plt.xlabel('Distance between Occurrences')
        plt.ylabel('Frequency')
        plt.title('Pattern Spacing Distribution')
        plt.grid(True)
    
    plt.tight_layout()
    return plt

def process_file(input_file, output_dir):
    """Process a file with targeted pattern-based decryption"""
    if not os.path.exists(input_file):
        print(f"Error: File {input_file} not found")
        return
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"Processing file: {input_file}")
    file_name = os.path.basename(input_file)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # 1. Find pattern occurrences
    pattern = TARGET_PATTERN
    pattern_offsets = find_pattern_offsets(data, pattern)
    
    if not pattern_offsets:
        print(f"Pattern {binascii.hexlify(pattern).decode()} not found in file")
        
        # Try to find pattern in XOR-decrypted versions of the file
        for key_name, key in KNOWN_KEYS.items():
            if key == pattern:
                continue  # Skip the pattern itself
            
            decrypted = xor_with_pattern(data, key)
            xor_offsets = find_pattern_offsets(decrypted, pattern)
            
            if xor_offsets:
                print(f"Pattern found after XOR decryption with key {key_name} at offsets: {xor_offsets[:10]}")
                
                # Visualize pattern distribution
                plt_fig = visualize_pattern_distribution(decrypted, pattern)
                if plt_fig:
                    plot_path = os.path.join(output_dir, f"{file_name}_pattern_xor_{key_name}.png")
                    plt_fig.savefig(plot_path)
                    plt_fig.close()
                    print(f"Pattern distribution plot saved to {plot_path}")
                
                # Extract and analyze sections around pattern
                sections = extract_sections_around_pattern(decrypted, pattern)
                
                for i, (offset, section) in enumerate(sections[:5]):  # Limit to first 5 occurrences
                    print(f"\nAnalyzing section around offset {offset} (XOR key: {key_name})")
                    
                    # Try decrypting the section with various keys
                    results = try_key_combinations(section, KNOWN_KEYS)
                    
                    print(f"Top 3 decryption results:")
                    for j, (key_desc, score, result) in enumerate(results[:3]):
                        # Generate output filename
                        output_name = f"{file_name}_xor_{key_name}_section_{offset}_decrypt_{key_desc}.bin"
                        output_path = os.path.join(output_dir, output_name)
                        
                        # Save decrypted data
                        with open(output_path, 'wb') as f:
                            f.write(result)
                        
                        print(f"[{j+1}] Key: {key_desc}, Score: {score}")
                        print(f"    Saved to: {output_path}")
                        
                        # Print preview
                        hex_preview = binascii.hexlify(result[:32]).decode()
                        ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result[:32])
                        print(f"    Hex: {hex_preview}")
                        print(f"    ASCII: {ascii_preview}")
                        
                        # Extract strings
                        strings = find_strings(result)
                        if strings:
                            print(f"    Strings: {', '.join(strings[:5])}" + 
                                 (f" (and {len(strings)-5} more)" if len(strings) > 5 else ""))
    else:
        print(f"Pattern found at {len(pattern_offsets)} offsets: {pattern_offsets[:10]}" + 
             (f" (and {len(pattern_offsets)-10} more)" if len(pattern_offsets) > 10 else ""))
        
        # Visualize pattern distribution
        plt_fig = visualize_pattern_distribution(data, pattern)
        if plt_fig:
            plot_path = os.path.join(output_dir, f"{file_name}_pattern_distribution.png")
            plt_fig.savefig(plot_path)
            plt_fig.close()
            print(f"Pattern distribution plot saved to {plot_path}")
        
        # Extract and analyze sections around pattern
        sections = extract_sections_around_pattern(data, pattern)
        
        for i, (offset, section) in enumerate(sections[:5]):  # Limit to first 5 occurrences
            print(f"\nAnalyzing section around offset {offset}")
            
            # Try decrypting the section with various keys
            results = try_key_combinations(section, KNOWN_KEYS)
            
            print(f"Top 3 decryption results:")
            for j, (key_desc, score, result) in enumerate(results[:3]):
                # Generate output filename
                output_name = f"{file_name}_section_{offset}_decrypt_{key_desc}.bin"
                output_path = os.path.join(output_dir, output_name)
                
                # Save decrypted data
                with open(output_path, 'wb') as f:
                    f.write(result)
                
                print(f"[{j+1}] Key: {key_desc}, Score: {score}")
                print(f"    Saved to: {output_path}")
                
                # Print preview
                hex_preview = binascii.hexlify(result[:32]).decode()
                ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result[:32])
                print(f"    Hex: {hex_preview}")
                print(f"    ASCII: {ascii_preview}")
                
                # Extract strings
                strings = find_strings(result)
                if strings:
                    print(f"    Strings: {', '.join(strings[:5])}" + 
                         (f" (and {len(strings)-5} more)" if len(strings) > 5 else ""))
    
    # Also try decrypting the whole file with the pattern as key
    decrypted_full = xor_with_pattern(data, pattern)
    output_name = f"{file_name}_full_decrypt_pattern.bin"
    output_path = os.path.join(output_dir, output_name)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_full)
    
    print(f"\nFull file decryption with pattern as key saved to: {output_path}")
    
    # Print preview
    hex_preview = binascii.hexlify(decrypted_full[:64]).decode()
    ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted_full[:64])
    print(f"Hex: {hex_preview}")
    print(f"ASCII: {ascii_preview}")
    
    # Additional approach: Try using pattern as key with sliding window
    print("\nApplying sliding window pattern decryption...")
    decrypted_sliding = sliding_pattern_decrypt(data, pattern)
    output_name = f"{file_name}_sliding_pattern_decrypt.bin"
    output_path = os.path.join(output_dir, output_name)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_sliding)
    
    print(f"Sliding pattern decryption saved to: {output_path}")
    
    # Print preview
    hex_preview = binascii.hexlify(decrypted_sliding[:64]).decode()
    ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted_sliding[:64])
    print(f"Hex: {hex_preview}")
    print(f"ASCII: {ascii_preview}")
    
    return pattern_offsets

def sliding_pattern_decrypt(data, pattern, window_size=1024, step=512):
    """Apply pattern-based decryption with a sliding window approach"""
    result = bytearray(data)
    
    # Apply different phase shifts of the pattern across the file
    for i in range(0, len(data), step):
        end = min(i + window_size, len(data))
        segment = data[i:end]
        
        # Apply pattern XOR with phase shift based on position
        for j in range(len(segment)):
            pattern_idx = (j + (i % len(pattern))) % len(pattern)
            result[i+j] = segment[j] ^ pattern[pattern_idx]
    
    return bytes(result)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Targeted Pattern-Based Decryption for KEYPLUG Malware")
    parser.add_argument("file", help="File to decrypt")
    parser.add_argument("-o", "--output-dir", default="pattern_decrypted", help="Output directory for decrypted files")
    parser.add_argument("-p", "--pattern", default="a2800a28", help="Hex pattern to target (default: a2800a28)")
    args = parser.parse_args()
    
    # Set target pattern if specified
    if args.pattern:
        global TARGET_PATTERN
        TARGET_PATTERN = bytes.fromhex(args.pattern)
    
    process_file(args.file, args.output_dir)

if __name__ == "__main__":
    main()
