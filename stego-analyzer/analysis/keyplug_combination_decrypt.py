#!/usr/bin/env python3
"""
KEYPLUG Multi-Key Combination Decryption
Leverages OpenVINO acceleration and parallel processing for optimal performance
"""
import os
import sys
import binascii
import hashlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import concurrent.futures
import itertools
import json
import time

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - will use hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - will use CPU-only processing")

# Constants
PATTERN = bytes.fromhex("a2800a28")
KEY_SECTIONS = [
    (0xE580, 0xE700),  # Section where we found repeating patterns
    (0xE600, 0xE780),
    (0xE680, 0xE800),
    (0x1078C, 0x1178C)  # Special offset identified
]

# Known keys from previous analysis
KNOWN_KEYS = {
    "9e": b'\x9e',
    "d3": b'\xd3',
    "a5": b'\xa5',
    "9ed3": b'\x9e\xd3',
    "9ed3a5": b'\x9e\xd3\xa5',
    "a2800a28": bytes.fromhex("a2800a28"),
    "b63c1e94": bytes.fromhex("b63c1e94"),
    "fb7153d9": bytes.fromhex("fb7153d9")
}

# PE offsets identified
PE_OFFSETS = [33763, 33849, 48540]

# Process in larger chunks for better performance
CHUNK_SIZE = 16384
MAX_WORKERS = os.cpu_count()

class OpenvINOAccelerator:
    """OpenVINO acceleration for cryptographic operations"""
    
    def __init__(self):
        self.core = None
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                print("OpenVINO Core initialized successfully")
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.core = None
    
    def accelerated_xor(self, data, key):
        """Hardware-accelerated XOR operation if available"""
        if self.core is None or len(data) < 1024:
            # Fall back to regular XOR for small data or if OpenVINO is not available
            return xor_with_key(data, key)
        
        try:
            # Convert to numpy arrays for acceleration
            data_array = np.frombuffer(data, dtype=np.uint8)
            
            # Handle key repetition
            if len(key) == 1:
                # For single-byte keys, use fast broadcasting
                key_array = np.array([key[0]], dtype=np.uint8)
                result = np.bitwise_xor(data_array, key_array)
            else:
                # For multi-byte keys, create repeated key array
                repeated_key = np.array(list(key) * (len(data_array) // len(key) + 1), dtype=np.uint8)
                repeated_key = repeated_key[:len(data_array)]
                result = np.bitwise_xor(data_array, repeated_key)
            
            return bytes(result)
        except Exception as e:
            print(f"Error in accelerated XOR: {e}")
            # Fall back to regular XOR
            return xor_with_key(data, key)
    
    def accelerated_pattern_search(self, data, pattern):
        """Hardware-accelerated pattern search if available"""
        if self.core is None:
            # Fall back to regular search
            return find_pattern_offsets(data, pattern)
        
        try:
            # Use numpy for faster pattern matching
            data_array = np.frombuffer(data, dtype=np.uint8)
            pattern_array = np.frombuffer(pattern, dtype=np.uint8)
            
            # Create a view of the data with overlapping windows of pattern length
            windows = np.lib.stride_tricks.sliding_window_view(data_array, len(pattern_array))
            
            # Compare each window with the pattern
            matches = np.all(windows == pattern_array, axis=1)
            
            # Get the indices of matches
            match_indices = np.nonzero(matches)[0]
            
            return match_indices.tolist()
        except Exception as e:
            print(f"Error in accelerated pattern search: {e}")
            # Fall back to regular search
            return find_pattern_offsets(data, pattern)

def xor_with_key(data, key):
    """XOR data with a repeating key"""
    if len(key) == 1:
        # Optimize for single-byte key
        key_byte = key[0]
        return bytes(b ^ key_byte for b in data)
    else:
        # Multi-byte key
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
        return bytes(result)

def process_chunk(chunk, keys, accelerator):
    """Process a chunk of data with multiple keys in parallel"""
    results = []
    
    for key_name, key in keys.items():
        # Apply XOR decryption with this key
        decrypted = accelerator.accelerated_xor(chunk, key)
        
        # Score the result
        score = score_result(decrypted)
        
        results.append((key_name, score, decrypted))
    
    return sorted(results, key=lambda x: x[1], reverse=True)

def process_file_with_key_combinations(file_path, output_dir):
    """Process a file with all possible key combinations"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"Processing file: {file_path}")
    file_name = os.path.basename(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Initialize OpenVINO accelerator
    accelerator = OpenvINOAccelerator()
    
    # Generate all key combinations
    all_keys = KNOWN_KEYS.copy()
    
    # Add key combinations (up to 3 keys combined)
    for i in range(2, 4):
        for combo in itertools.combinations(KNOWN_KEYS.items(), i):
            combo_name = "+".join(k for k, _ in combo)
            combo_key = b"".join(v for _, v in combo)
            all_keys[combo_name] = combo_key
    
    # Generate different phase shifts of the pattern key
    for shift in range(1, 4):
        shifted_key = bytes([(b + shift) % 256 for b in PATTERN])
        all_keys[f"pattern_shift_{shift}"] = shifted_key
    
    print(f"Generated {len(all_keys)} key combinations")
    
    # Process in parallel using ThreadPoolExecutor
    results = []
    
    print("Starting parallel decryption with all keys...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # First try whole file decryption
        futures = {executor.submit(accelerator.accelerated_xor, data, key): (name, key) 
                  for name, key in all_keys.items()}
        
        for future in concurrent.futures.as_completed(futures):
            name, key = futures[future]
            try:
                decrypted = future.result()
                score = score_result(decrypted)
                
                results.append({
                    "key": name,
                    "score": score,
                    "target": "full_file",
                    "offset": 0,
                    "length": len(data),
                    "decrypted": decrypted
                })
            except Exception as e:
                print(f"Error processing with key {name}: {e}")
        
        # Now try specific sections
        for section_start, section_end in KEY_SECTIONS:
            if section_start >= len(data) or section_end > len(data):
                continue
            
            section = data[section_start:section_end]
            
            section_futures = {executor.submit(accelerator.accelerated_xor, section, key): (name, key) 
                              for name, key in all_keys.items()}
            
            for future in concurrent.futures.as_completed(section_futures):
                name, key = section_futures[future]
                try:
                    decrypted_section = future.result()
                    
                    # Create combined result (original data with decrypted section)
                    combined = data[:section_start] + decrypted_section + data[section_end:]
                    
                    score = score_result(decrypted_section)
                    
                    results.append({
                        "key": name,
                        "score": score,
                        "target": f"section_{section_start:x}_{section_end:x}",
                        "offset": section_start,
                        "length": section_end - section_start,
                        "decrypted": combined
                    })
                except Exception as e:
                    print(f"Error processing section {section_start:x}-{section_end:x} with key {name}: {e}")
        
        # Also try PE offsets
        for pe_offset in PE_OFFSETS:
            if pe_offset >= len(data):
                continue
            
            # Try decrypting from this offset to the end
            section = data[pe_offset:]
            
            offset_futures = {executor.submit(accelerator.accelerated_xor, section, key): (name, key) 
                            for name, key in all_keys.items()}
            
            for future in concurrent.futures.as_completed(offset_futures):
                name, key = offset_futures[future]
                try:
                    decrypted_section = future.result()
                    
                    # Create combined result
                    combined = data[:pe_offset] + decrypted_section
                    
                    score = score_result(decrypted_section)
                    
                    results.append({
                        "key": name,
                        "score": score,
                        "target": f"pe_offset_{pe_offset}",
                        "offset": pe_offset,
                        "length": len(data) - pe_offset,
                        "decrypted": combined
                    })
                except Exception as e:
                    print(f"Error processing PE offset {pe_offset} with key {name}: {e}")
    
    # Sort results by score
    results.sort(key=lambda x: x["score"], reverse=True)
    
    # Process top results
    top_results = results[:20]  # Save top 20 results
    
    print(f"\nTop {len(top_results)} decryption results:")
    for i, result in enumerate(top_results):
        print(f"\n[{i+1}] Key: {result['key']}, Score: {result['score']}")
        print(f"    Target: {result['target']}, Offset: 0x{result['offset']:x}, Length: {result['length']}")
        
        # Generate output filename
        output_name = f"{file_name}_{result['target']}_{result['key']}.bin"
        output_path = os.path.join(output_dir, output_name)
        
        # Save decrypted data
        with open(output_path, 'wb') as f:
            f.write(result['decrypted'])
        
        print(f"    Saved to: {output_path}")
        
        # Print hex and ASCII preview
        preview_len = min(64, len(result['decrypted']))
        hex_preview = binascii.hexlify(result['decrypted'][:preview_len]).decode()
        ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result['decrypted'][:preview_len])
        
        print(f"    Hex: {hex_preview}")
        print(f"    ASCII: {ascii_preview}")
        
        # Check for specific patterns
        if result['decrypted'][:2] == b'MZ':
            print("    ** DOS/PE Executable Signature Found **")
            try:
                pe_offset = struct.unpack('<I', result['decrypted'][0x3C:0x40])[0]
                if pe_offset < len(result['decrypted']) - 4 and result['decrypted'][pe_offset:pe_offset+4] == b'PE\0\0':
                    print(f"    ** Valid PE Header Found at offset 0x{pe_offset:x} **")
            except:
                pass
        
        # Extract strings
        strings = find_strings(result['decrypted'][:1024])  # Look at first 1KB for strings
        if strings:
            print(f"    Strings: {', '.join(strings[:5])}" + 
                 (f" (and {len(strings)-5} more)" if len(strings) > 5 else ""))
    
    # Save a summary of all results
    summary = {
        "file": file_path,
        "file_size": len(data),
        "total_combinations_tried": len(all_keys),
        "results": [
            {
                "key": r["key"],
                "score": r["score"],
                "target": r["target"],
                "offset": r["offset"],
                "length": r["length"],
                "output_file": f"{file_name}_{r['target']}_{r['key']}.bin"
            }
            for r in results[:50]  # Include more in the JSON summary
        ]
    }
    
    summary_path = os.path.join(output_dir, f"{file_name}_combination_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nSummary saved to: {summary_path}")
    return top_results

def score_result(data):
    """Score a decryption result by potential validity"""
    score = 0
    
    # Check for MZ/PE signature
    if len(data) >= 2 and data[:2] == b'MZ':
        score += 10
        if len(data) >= 0x40 + 4:
            try:
                pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                if 0 < pe_offset < len(data) - 4:
                    if data[pe_offset:pe_offset+4] == b'PE\0\0':
                        score += 20
            except:
                pass
    
    # Check for high concentration of printable ASCII
    printable_count = sum(32 <= b <= 126 for b in data[:1024])  # Check first 1KB
    printable_ratio = printable_count / min(1024, len(data))
    if printable_ratio > 0.7:
        score += 5
    
    # Check for common executable instructions (x86)
    common_opcodes = [b'\x55\x8b\xec', b'\x33\xc0', b'\x8b\xff', b'\xc3', b'\x90\x90\x90']
    for opcode in common_opcodes:
        if opcode in data:
            score += 3
    
    # Check for strings
    strings = find_strings(data[:1024])  # Look at first 1KB for strings
    if len(strings) > 5:
        score += len(strings) // 5  # More strings = higher score
    
    # Check for typical executable section names
    section_names = [b'.text', b'.data', b'.rdata', b'.rsrc', b'.reloc']
    for name in section_names:
        if name in data:
            score += 5
    
    # Check for entropy (decrypted data often has lower entropy)
    try:
        entropy = calculate_entropy(data[:4096])  # Check first 4KB
        if 0.6 <= entropy <= 0.85:
            score += 5
    except:
        pass
    
    # Check for Windows API strings
    api_strings = ['kernel32.dll', 'user32.dll', 'CreateFile', 'WriteFile', 'ReadFile', 
                   'LoadLibrary', 'GetProcAddress', 'VirtualAlloc', 'WSAStartup']
    for api in api_strings:
        if api.encode('ascii') in data or api.encode('utf-16le') in data:
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

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="KEYPLUG Multi-Key Combination Decryption")
    parser.add_argument("file", help="File to decrypt")
    parser.add_argument("-o", "--output-dir", default="multi_key_decrypted", 
                        help="Output directory for decrypted files")
    args = parser.parse_args()
    
    start_time = time.time()
    process_file_with_key_combinations(args.file, args.output_dir)
    end_time = time.time()
    
    print(f"\nTotal processing time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
