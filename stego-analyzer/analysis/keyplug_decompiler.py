#!/usr/bin/env python3
"""
KEYPLUG Decompiler
A tool for decrypting and analyzing APT-41's KEYPLUG malware payloads
Attempts to recover source code from encrypted payloads
"""

import os
import sys
import binascii
import struct
import hashlib
import re
import math
import argparse
from pathlib import Path
from collections import defaultdict

# ANSI Colors for terminal output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# Known XOR keys used by APT-41's KEYPLUG
KNOWN_XOR_KEYS = [
    # Single-byte keys
    "9e", "d3", "a5", "00", "ff", "aa", "55", 
    # Multi-byte keys
    "0a61200d", "410d200d", "4100200d",
    # Other common keys
    "41414141", "00000000", "ffffffff", "12345678", "87654321", "deadbeef"
]

def calculate_entropy(data, base=2):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    counter = defaultdict(int)
    for byte in data:
        counter[byte] += 1
    
    total_bytes = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / total_bytes
        entropy -= probability * math.log(probability, base)
    
    return entropy

def xor_decrypt(data, key_hex):
    """Perform XOR decryption with a hex key."""
    key_bytes = bytes.fromhex(key_hex)
    key_len = len(key_bytes)
    
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[i % key_len]
    
    return bytes(result)

def detect_xor_key(data, sample_size=256, top_n=5):
    """Try to detect the XOR key used to encrypt the data."""
    if len(data) < sample_size:
        sample_size = len(data)
    
    results = []
    
    # Try all single-byte keys
    for key in range(256):
        key_hex = f"{key:02x}"
        decrypted = xor_decrypt(data[:sample_size], key_hex)
        
        # Calculate metrics to determine if this is a good key
        ascii_ratio = sum(32 <= b <= 126 for b in decrypted) / sample_size
        null_ratio = sum(b == 0 for b in decrypted) / sample_size
        entropy = calculate_entropy(decrypted)
        
        # Detect PE headers
        has_pe = b'MZ' in decrypted[:2] or b'PE\x00\x00' in decrypted
        
        # Detect script code
        script_markers = [
            b'function', b'var ', b'let ', b'const ', 
            b'class ', b'import ', b'#include', 
            b'def ', b'if ', b'while ', b'for '
        ]
        has_script = any(marker in decrypted for marker in script_markers)
        
        score = 0
        if has_pe:
            score += 20
        if has_script:
            score += 15
        if ascii_ratio > 0.7:
            score += 10
        if null_ratio < 0.1:
            score += 5
        if 3.5 < entropy < 6.5:
            score += 10
        
        results.append({
            "key": key_hex,
            "score": score,
            "ascii_ratio": ascii_ratio,
            "null_ratio": null_ratio,
            "entropy": entropy,
            "has_pe": has_pe,
            "has_script": has_script
        })
    
    # Sort by score (highest first)
    results.sort(key=lambda x: x["score"], reverse=True)
    
    # Return top N results
    return results[:top_n]

def brute_force_decrypt(data, output_dir):
    """Attempt to decrypt data using various methods."""
    results = []
    
    # Try known XOR keys first
    for key in KNOWN_XOR_KEYS:
        try:
            decrypted = xor_decrypt(data, key)
            md5 = hashlib.md5(decrypted).hexdigest()
            output_file = output_dir / f"decrypted_known_{key}_{md5[:8]}.bin"
            
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            is_pe = decrypted[:2] == b'MZ'
            is_script = False
            
            # Check for script signatures
            script_signatures = {
                b'#!/usr/bin': ('sh', '.sh'),
                b'#!/bin/sh': ('sh', '.sh'),
                b'#!/usr/bin/env python': ('python', '.py'),
                b'import ': ('python', '.py'),
                b'function ': ('javascript', '.js'),
                b'var ': ('javascript', '.js'),
                b'<?php': ('php', '.php'),
                b'<html': ('html', '.html'),
                b'#include': ('c', '.c')
            }
            
            for sig, (lang, ext) in script_signatures.items():
                if sig in decrypted[:1024]:
                    is_script = True
                    script_file = output_dir / f"extracted_script_{lang}_{md5[:8]}{ext}"
                    with open(script_file, 'wb') as f:
                        f.write(decrypted)
                    break
            
            results.append({
                "method": "known_xor",
                "key": key,
                "output_file": str(output_file),
                "md5": md5,
                "entropy": calculate_entropy(decrypted),
                "is_pe": is_pe,
                "is_script": is_script
            })
        except:
            pass
    
    # Try detected XOR keys
    detected_keys = detect_xor_key(data)
    
    for key_info in detected_keys:
        key = key_info["key"]
        if key in [r["key"] for r in results]:
            continue  # Skip keys we've already tried
            
        try:
            decrypted = xor_decrypt(data, key)
            md5 = hashlib.md5(decrypted).hexdigest()
            output_file = output_dir / f"decrypted_detected_{key}_{md5[:8]}.bin"
            
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            is_pe = decrypted[:2] == b'MZ'
            is_script = False
            
            # Check for script signatures
            script_signatures = {
                b'#!/usr/bin': ('sh', '.sh'),
                b'#!/bin/sh': ('sh', '.sh'),
                b'#!/usr/bin/env python': ('python', '.py'),
                b'import ': ('python', '.py'),
                b'function ': ('javascript', '.js'),
                b'var ': ('javascript', '.js'),
                b'<?php': ('php', '.php'),
                b'<html': ('html', '.html'),
                b'#include': ('c', '.c')
            }
            
            for sig, (lang, ext) in script_signatures.items():
                if sig in decrypted[:1024]:
                    is_script = True
                    script_file = output_dir / f"extracted_script_{lang}_{md5[:8]}{ext}"
                    with open(script_file, 'wb') as f:
                        f.write(decrypted)
                    break
            
            results.append({
                "method": "detected_xor",
                "key": key,
                "output_file": str(output_file),
                "md5": md5,
                "entropy": calculate_entropy(decrypted),
                "is_pe": is_pe,
                "is_script": is_script,
                "score": key_info["score"]
            })
        except:
            pass
    
    return results

def extract_readable_strings(data, min_length=4):
    """Extract readable ASCII strings from binary data."""
    strings = []
    current = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # ASCII printable
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ""
    
    # Don't forget the last string
    if len(current) >= min_length:
        strings.append(current)
    
    return strings

def extract_potential_code(strings):
    """Identify potential code snippets from strings."""
    code_patterns = [
        (r'function\s+\w+\s*\(', 'JavaScript'),
        (r'var\s+\w+\s*=', 'JavaScript'),
        (r'let\s+\w+\s*=', 'JavaScript'),
        (r'const\s+\w+\s*=', 'JavaScript'),
        (r'class\s+\w+', 'JavaScript/Python/C++'),
        (r'def\s+\w+\s*\(', 'Python'),
        (r'import\s+\w+', 'Python/JavaScript'),
        (r'from\s+\w+\s+import', 'Python'),
        (r'#include', 'C/C++'),
        (r'public\s+class', 'Java'),
        (r'private\s+\w+\s+\w+\s*\(', 'C#/Java'),
        (r'if\s*\(.+\)\s*{', 'C-style'),
        (r'while\s*\(.+\)\s*{', 'C-style'),
        (r'for\s*\(.+\)\s*{', 'C-style')
    ]
    
    code_snippets = []
    
    for string in strings:
        for pattern, language in code_patterns:
            if re.search(pattern, string):
                code_snippets.append({
                    "snippet": string,
                    "language": language
                })
                break
    
    return code_snippets

def extract_pe_info(data):
    """Extract basic information from a PE file."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None
    
    try:
        # Get PE header offset
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        
        # Get basic PE info
        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
        num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
        timestamp = struct.unpack("<I", data[pe_offset+8:pe_offset+12])[0]
        
        machine_types = {
            0x014c: "x86",
            0x0200: "IA64",
            0x8664: "x64"
        }
        
        machine_type = machine_types.get(machine, f"Unknown ({hex(machine)})")
        
        return {
            "pe_offset": pe_offset,
            "machine": machine_type,
            "num_sections": num_sections,
            "timestamp": timestamp
        }
    except:
        return None

def analyze_payload(payload_path, output_dir=None):
    """Analyze a KEYPLUG payload and attempt to extract source code."""
    payload_path = Path(payload_path)
    
    if output_dir:
        output_dir = Path(output_dir)
    else:
        output_dir = payload_path.parent / f"{payload_path.stem}_code"
    
    output_dir.mkdir(exist_ok=True, parents=True)
    
    print(f"{ANSI_BLUE}[*] Analyzing {payload_path.name}...{ANSI_RESET}")
    
    with open(payload_path, 'rb') as f:
        data = f.read()
    
    md5 = hashlib.md5(data).hexdigest()
    entropy = calculate_entropy(data)
    
    print(f"{ANSI_BLUE}[*] File size: {len(data)} bytes{ANSI_RESET}")
    print(f"{ANSI_BLUE}[*] MD5: {md5}{ANSI_RESET}")
    print(f"{ANSI_BLUE}[*] Entropy: {entropy:.2f}{ANSI_RESET}")
    
    # Check if the file is already a PE
    pe_info = extract_pe_info(data)
    
    if pe_info:
        print(f"{ANSI_GREEN}[+] File is a PE executable{ANSI_RESET}")
        print(f"{ANSI_GREEN}[+] Machine type: {pe_info['machine']}{ANSI_RESET}")
        print(f"{ANSI_GREEN}[+] Number of sections: {pe_info['num_sections']}{ANSI_RESET}")
        
        # Extract strings from PE
        strings = extract_readable_strings(data)
        strings_file = output_dir / f"{payload_path.stem}_strings.txt"
        
        with open(strings_file, 'w') as f:
            for string in strings:
                f.write(f"{string}\n")
        
        print(f"{ANSI_GREEN}[+] Extracted {len(strings)} strings to {strings_file}{ANSI_RESET}")
        
        # Extract potential code snippets
        code_snippets = extract_potential_code(strings)
        
        if code_snippets:
            code_file = output_dir / f"{payload_path.stem}_code_snippets.txt"
            
            with open(code_file, 'w') as f:
                for snippet in code_snippets:
                    f.write(f"Language: {snippet['language']}\n")
                    f.write(f"{snippet['snippet']}\n\n")
                    f.write("-" * 50 + "\n\n")
            
            print(f"{ANSI_GREEN}[+] Extracted {len(code_snippets)} code snippets to {code_file}{ANSI_RESET}")
    else:
        print(f"{ANSI_YELLOW}[!] File is not a PE executable, attempting decryption...{ANSI_RESET}")
        
        # Attempt to decrypt the payload
        decrypt_results = brute_force_decrypt(data, output_dir)
        
        if decrypt_results:
            print(f"{ANSI_GREEN}[+] Found {len(decrypt_results)} possible decryptions{ANSI_RESET}")
            
            for i, result in enumerate(decrypt_results):
                print(f"{ANSI_GREEN}[+] Decryption #{i+1}: {Path(result['output_file']).name}{ANSI_RESET}")
                print(f"{ANSI_GREEN}[+]   Method: {result['method']}, Key: {result['key']}{ANSI_RESET}")
                print(f"{ANSI_GREEN}[+]   MD5: {result['md5']}{ANSI_RESET}")
                print(f"{ANSI_GREEN}[+]   Entropy: {result['entropy']:.2f}{ANSI_RESET}")
                
                if result['is_pe']:
                    print(f"{ANSI_GREEN}[+]   Type: PE executable{ANSI_RESET}")
                elif result['is_script']:
                    print(f"{ANSI_GREEN}[+]   Type: Script{ANSI_RESET}")
                
                # If it's a good candidate, analyze it further
                if result['is_pe'] or result['is_script'] or result.get('score', 0) > 20:
                    with open(result['output_file'], 'rb') as f:
                        decrypted_data = f.read()
                    
                    # Extract strings
                    strings = extract_readable_strings(decrypted_data)
                    strings_file = output_dir / f"{Path(result['output_file']).stem}_strings.txt"
                    
                    with open(strings_file, 'w') as f:
                        for string in strings:
                            f.write(f"{string}\n")
                    
                    print(f"{ANSI_GREEN}[+]   Extracted {len(strings)} strings to {strings_file}{ANSI_RESET}")
                    
                    # Extract potential code snippets
                    code_snippets = extract_potential_code(strings)
                    
                    if code_snippets:
                        code_file = output_dir / f"{Path(result['output_file']).stem}_code_snippets.txt"
                        
                        with open(code_file, 'w') as f:
                            for snippet in code_snippets:
                                f.write(f"Language: {snippet['language']}\n")
                                f.write(f"{snippet['snippet']}\n\n")
                                f.write("-" * 50 + "\n\n")
                        
                        print(f"{ANSI_GREEN}[+]   Extracted {len(code_snippets)} code snippets to {code_file}{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}[!] No successful decryptions found{ANSI_RESET}")
            
            # Extract strings anyway
            strings = extract_readable_strings(data)
            strings_file = output_dir / f"{payload_path.stem}_strings.txt"
            
            with open(strings_file, 'w') as f:
                for string in strings:
                    f.write(f"{string}\n")
            
            print(f"{ANSI_YELLOW}[!] Extracted {len(strings)} strings to {strings_file}{ANSI_RESET}")
    
    # Generate report
    report_file = output_dir / f"{payload_path.stem}_analysis_report.txt"
    
    with open(report_file, 'w') as f:
        f.write(f"Analysis Report for {payload_path.name}\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("File Information:\n")
        f.write(f"  Size: {len(data)} bytes\n")
        f.write(f"  MD5: {md5}\n")
        f.write(f"  Entropy: {entropy:.2f}\n\n")
        
        if pe_info:
            f.write("PE Information:\n")
            f.write(f"  Machine type: {pe_info['machine']}\n")
            f.write(f"  Number of sections: {pe_info['num_sections']}\n")
            f.write(f"  Timestamp: {pe_info['timestamp']}\n\n")
        
        strings = extract_readable_strings(data)
        f.write(f"Extracted {len(strings)} strings\n")
        
        code_snippets = extract_potential_code(strings)
        if code_snippets:
            f.write(f"Found {len(code_snippets)} potential code snippets\n\n")
            
            for i, snippet in enumerate(code_snippets[:10]):  # Show top 10
                f.write(f"Snippet #{i+1} ({snippet['language']}):\n")
                f.write(f"{snippet['snippet'][:200]}...\n\n")
        
        f.write("\nDecryption Attempts:\n")
        
        decrypt_results = brute_force_decrypt(data, output_dir)
        for i, result in enumerate(decrypt_results):
            f.write(f"Attempt #{i+1}:\n")
            f.write(f"  Method: {result['method']}, Key: {result['key']}\n")
            f.write(f"  Output file: {Path(result['output_file']).name}\n")
            f.write(f"  MD5: {result['md5']}\n")
            f.write(f"  Entropy: {result['entropy']:.2f}\n")
            f.write(f"  Is PE: {result['is_pe']}\n")
            f.write(f"  Is Script: {result['is_script']}\n")
            if 'score' in result:
                f.write(f"  Score: {result['score']}\n")
            f.write("\n")
    
    print(f"{ANSI_GREEN}[+] Analysis report saved to: {report_file}{ANSI_RESET}")
    return output_dir, report_file

def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Decompiler - Extract source code from KEYPLUG payloads')
    parser.add_argument('file', help='Path to the payload file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    args = parser.parse_args()
    
    try:
        output_dir, report_file = analyze_payload(args.file, args.output)
        print(f"{ANSI_GREEN}[+] Analysis complete!{ANSI_RESET}")
        print(f"{ANSI_GREEN}[+] Results saved to: {output_dir}{ANSI_RESET}")
    except Exception as e:
        print(f"{ANSI_RED}[!] Error: {str(e)}{ANSI_RESET}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
