#!/usr/bin/env python3
"""
KEYPLUG Advanced Analysis Tool
Performs custom pattern detection and multi-stage decryption on KEYPLUG payloads
"""

import os
import sys
import struct
import hashlib
import binascii
import math
import re
import argparse
from pathlib import Path
from collections import defaultdict

try:
    from Crypto.Cipher import ARC4
    RC4_AVAILABLE = True
except ImportError:
    RC4_AVAILABLE = False
    print("Warning: PyCryptodome not available, RC4 decryption disabled")

# ANSI Colors
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# Known file signatures to detect
FILE_SIGNATURES = [
    (b'MZ', "DOS/PE Executable"),
    (b'PK\x03\x04', "ZIP Archive"),
    (b'\x7fELF', "ELF Executable"),
    (b'\x1f\x8b\x08', "GZIP Archive"),
    (b'KEYP', "KEYPLUG Marker"),
    (b'RC4', "RC4 Encryption"),
    (b'%PDF', "PDF Document"),
    (b'\xff\xd8\xff', "JPEG Image")
]

# APT-41 KEYPLUG specific patterns
KEYPLUG_PATTERNS = [
    (b'KEYP', "KEYPLUG Marker"),
    (b'CONFIG', "Configuration Block"),
    (b'RC4', "RC4 Encryption"),
    (b'cmd.exe', "Command Execution"),
    (b'powershell', "PowerShell Execution"),
    (b'rundll32', "DLL Execution"),
    (b'regsvr32', "DLL Registration"),
    (b'http://', "HTTP URL"),
    (b'https://', "HTTPS URL"),
    (b'VirtualAlloc', "Memory Allocation"),
    (b'CreateProcess', "Process Creation"),
]

# Known XOR keys used by APT-41 KEYPLUG
SINGLE_BYTE_XOR_KEYS = [0x9e, 0xd3, 0xa5]
MULTI_BYTE_XOR_KEYS = [
    bytes.fromhex("0a61200d"),
    bytes.fromhex("410d200d"),
    bytes.fromhex("4100200d"),
]

# Interesting byte offsets mentioned in the report
INTERESTING_OFFSETS = [
    0xBEB5, 0x1078C, 0x19CED, 0x22863, 0x228B9, 0x2621C,  # From payload 2
    0x1A0B1, 0x26889  # From payload 3
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

def create_entropy_map(data, window_size=256, step=128):
    """Generate an entropy map of the data."""
    results = []
    for i in range(0, len(data) - window_size, step):
        window = data[i:i+window_size]
        entropy = calculate_entropy(window)
        results.append((i, entropy))
    return results

def scan_for_signatures(data):
    """Scan for known file signatures."""
    results = []
    
    # Check for file signatures
    for signature, description in FILE_SIGNATURES:
        positions = []
        for i in range(len(data) - len(signature) + 1):
            if data[i:i+len(signature)] == signature:
                positions.append(i)
        
        if positions:
            results.append({
                "signature": signature,
                "description": description,
                "positions": positions
            })
    
    return results

def scan_for_custom_patterns(data):
    """Scan for KEYPLUG-specific patterns."""
    results = []
    
    # Check for KEYPLUG patterns
    for pattern, description in KEYPLUG_PATTERNS:
        positions = []
        for i in range(len(data) - len(pattern) + 1):
            if data[i:i+len(pattern)] == pattern:
                positions.append(i)
        
        if positions:
            results.append({
                "pattern": pattern,
                "description": description,
                "positions": positions
            })
    
    # Check interesting offsets mentioned in the report
    for offset in INTERESTING_OFFSETS:
        if offset < len(data) - 2:
            # Look for MZ header at this offset
            if data[offset:offset+2] == b'MZ':
                results.append({
                    "pattern": b'MZ',
                    "description": f"MZ at reported offset",
                    "positions": [offset]
                })
    
    return results

def xor_decrypt(data, key):
    """Decrypt data using XOR with the given key."""
    if isinstance(key, int):
        # Single byte key
        return bytes([b ^ key for b in data])
    else:
        # Multi-byte key
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def rc4_decrypt(data, key):
    """Decrypt data using RC4 with the given key."""
    if not RC4_AVAILABLE:
        return None
    
    try:
        cipher = ARC4.new(key)
        return cipher.decrypt(data)
    except:
        return None

def detect_interesting_sections(data):
    """Detect potentially interesting sections based on entropy."""
    entropy_map = create_entropy_map(data)
    
    # Find sections with entropy changes
    interesting_sections = []
    
    prev_entropy = entropy_map[0][1] if entropy_map else 0
    for i, (offset, entropy) in enumerate(entropy_map[1:], 1):
        # Look for significant entropy changes
        if abs(entropy - prev_entropy) > 1.0:
            interesting_sections.append({
                "start_offset": entropy_map[i-1][0],
                "end_offset": offset + 256,
                "entropy_before": prev_entropy,
                "entropy_after": entropy
            })
        
        prev_entropy = entropy
    
    return interesting_sections

def multi_stage_decrypt(data, output_dir):
    """Perform multi-stage decryption attempts."""
    results = []
    
    # Stage 1: Try single-byte XOR keys
    for key in SINGLE_BYTE_XOR_KEYS:
        try:
            decrypted = xor_decrypt(data, key)
            if decrypted:
                signatures = scan_for_signatures(decrypted)
                if signatures:
                    # Found potential file signature after decryption
                    output_file = output_dir / f"stage1_xor_{key:02x}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    
                    results.append({
                        "stage": 1,
                        "method": "xor",
                        "key": f"{key:02x}",
                        "signatures": signatures,
                        "file": str(output_file)
                    })
        except:
            pass
    
    # Stage 2: Try multi-byte XOR keys
    for key in MULTI_BYTE_XOR_KEYS:
        try:
            decrypted = xor_decrypt(data, key)
            if decrypted:
                signatures = scan_for_signatures(decrypted)
                if signatures:
                    # Found potential file signature after decryption
                    key_hex = key.hex()
                    output_file = output_dir / f"stage2_xor_{key_hex}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    
                    results.append({
                        "stage": 2,
                        "method": "xor",
                        "key": key_hex,
                        "signatures": signatures,
                        "file": str(output_file)
                    })
        except:
            pass
    
    # Stage 3: Try RC4 decryption with known keys
    if RC4_AVAILABLE:
        for key in [bytes([0x9e]), bytes([0xd3]), bytes([0xa5]), 
                   bytes.fromhex("0a61200d"), bytes.fromhex("410d200d")]:
            try:
                decrypted = rc4_decrypt(data, key)
                if decrypted:
                    signatures = scan_for_signatures(decrypted)
                    if signatures:
                        # Found potential file signature after decryption
                        key_hex = key.hex()
                        output_file = output_dir / f"stage3_rc4_{key_hex}.bin"
                        with open(output_file, 'wb') as f:
                            f.write(decrypted)
                        
                        results.append({
                            "stage": 3,
                            "method": "rc4",
                            "key": key_hex,
                            "signatures": signatures,
                            "file": str(output_file)
                        })
            except:
                pass
    
    # Stage 4: Try decryption at specific offsets
    interesting_sections = detect_interesting_sections(data)
    
    for section in interesting_sections:
        start = section["start_offset"]
        end = section["end_offset"]
        section_data = data[start:end]
        
        # Try XOR decryption on this section
        for key in SINGLE_BYTE_XOR_KEYS:
            try:
                decrypted_section = xor_decrypt(section_data, key)
                if decrypted_section:
                    signatures = scan_for_signatures(decrypted_section)
                    if signatures:
                        # Reconstruct full file with decrypted section
                        full_decrypted = data[:start] + decrypted_section + data[end:]
                        output_file = output_dir / f"stage4_section_xor_{start:x}_{end:x}_{key:02x}.bin"
                        with open(output_file, 'wb') as f:
                            f.write(full_decrypted)
                        
                        results.append({
                            "stage": 4,
                            "method": "section_xor",
                            "key": f"{key:02x}",
                            "section": f"{start:x}-{end:x}",
                            "signatures": signatures,
                            "file": str(output_file)
                        })
            except:
                pass
    
    # Stage 5: Try XOR decryption at reported offsets
    for offset in INTERESTING_OFFSETS:
        if offset + 1024 < len(data):
            section_data = data[offset:offset+1024]
            
            # Try XOR decryption on this section
            for key in SINGLE_BYTE_XOR_KEYS:
                try:
                    decrypted_section = xor_decrypt(section_data, key)
                    if decrypted_section:
                        signatures = scan_for_signatures(decrypted_section)
                        if signatures:
                            # Reconstruct full file with decrypted section
                            full_decrypted = data[:offset] + decrypted_section + data[offset+1024:]
                            output_file = output_dir / f"stage5_offset_xor_{offset:x}_{key:02x}.bin"
                            with open(output_file, 'wb') as f:
                                f.write(full_decrypted)
                            
                            results.append({
                                "stage": 5,
                                "method": "offset_xor",
                                "key": f"{key:02x}",
                                "offset": f"{offset:x}",
                                "signatures": signatures,
                                "file": str(output_file)
                            })
                except:
                    pass
    
    return results

def analyze_file(file_path, output_dir=None):
    """Analyze a file for patterns and perform multi-stage decryption."""
    file_path = Path(file_path)
    
    if output_dir:
        output_dir = Path(output_dir)
    else:
        output_dir = file_path.parent / f"{file_path.stem}_advanced"
    
    output_dir.mkdir(exist_ok=True, parents=True)
    
    print(f"{ANSI_BLUE}[*] Analyzing {file_path.name}...{ANSI_RESET}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Basic file info
    file_size = len(data)
    file_md5 = hashlib.md5(data).hexdigest()
    file_entropy = calculate_entropy(data)
    
    print(f"{ANSI_BLUE}[*] File size: {file_size} bytes{ANSI_RESET}")
    print(f"{ANSI_BLUE}[*] MD5: {file_md5}{ANSI_RESET}")
    print(f"{ANSI_BLUE}[*] Entropy: {file_entropy:.2f}{ANSI_RESET}")
    
    # Step 1: Scan for known file signatures
    print(f"{ANSI_BLUE}[*] Scanning for file signatures...{ANSI_RESET}")
    signatures = scan_for_signatures(data)
    
    if signatures:
        for sig in signatures:
            print(f"{ANSI_GREEN}[+] Found signature: {sig['description']}{ANSI_RESET}")
            for pos in sig['positions'][:5]:  # Show first 5 positions
                print(f"{ANSI_GREEN}[+]   at offset: 0x{pos:X}{ANSI_RESET}")
            if len(sig['positions']) > 5:
                print(f"{ANSI_GREEN}[+]   and {len(sig['positions']) - 5} more...{ANSI_RESET}")
    else:
        print(f"{ANSI_YELLOW}[!] No file signatures found{ANSI_RESET}")
    
    # Step 2: Scan for custom patterns
    print(f"{ANSI_BLUE}[*] Scanning for KEYPLUG patterns...{ANSI_RESET}")
    custom_patterns = scan_for_custom_patterns(data)
    
    if custom_patterns:
        for pattern in custom_patterns:
            print(f"{ANSI_GREEN}[+] Found pattern: {pattern['description']}{ANSI_RESET}")
            for pos in pattern['positions'][:5]:  # Show first 5 positions
                print(f"{ANSI_GREEN}[+]   at offset: 0x{pos:X}{ANSI_RESET}")
            if len(pattern['positions']) > 5:
                print(f"{ANSI_GREEN}[+]   and {len(pattern['positions']) - 5} more...{ANSI_RESET}")
    else:
        print(f"{ANSI_YELLOW}[!] No KEYPLUG patterns found{ANSI_RESET}")
    
    # Step 3: Generate entropy map
    print(f"{ANSI_BLUE}[*] Generating entropy map...{ANSI_RESET}")
    entropy_map = create_entropy_map(data)
    
    # Save entropy map to file
    entropy_map_file = output_dir / f"{file_path.stem}_entropy_map.txt"
    with open(entropy_map_file, 'w') as f:
        f.write(f"Offset,Entropy\n")
        for offset, entropy in entropy_map:
            f.write(f"0x{offset:X},{entropy:.2f}\n")
    
    print(f"{ANSI_GREEN}[+] Entropy map saved to {entropy_map_file}{ANSI_RESET}")
    
    # Find interesting sections based on entropy
    interesting_sections = detect_interesting_sections(data)
    
    if interesting_sections:
        print(f"{ANSI_GREEN}[+] Found {len(interesting_sections)} interesting sections{ANSI_RESET}")
        for i, section in enumerate(interesting_sections):
            print(f"{ANSI_GREEN}[+] Section #{i+1}: 0x{section['start_offset']:X} - 0x{section['end_offset']:X} (Entropy change: {section['entropy_before']:.2f} -> {section['entropy_after']:.2f}){ANSI_RESET}")
    else:
        print(f"{ANSI_YELLOW}[!] No interesting sections found{ANSI_RESET}")
    
    # Step 4: Perform multi-stage decryption
    print(f"{ANSI_BLUE}[*] Performing multi-stage decryption...{ANSI_RESET}")
    decryption_results = multi_stage_decrypt(data, output_dir)
    
    if decryption_results:
        print(f"{ANSI_GREEN}[+] Found {len(decryption_results)} potential decryptions{ANSI_RESET}")
        for result in decryption_results:
            print(f"{ANSI_GREEN}[+] Stage {result['stage']} ({result['method']}): {Path(result['file']).name}{ANSI_RESET}")
            for sig in result['signatures']:
                print(f"{ANSI_GREEN}[+]   Found: {sig['description']}{ANSI_RESET}")
    else:
        print(f"{ANSI_YELLOW}[!] No successful decryptions found{ANSI_RESET}")
    
    # Generate report
    report_file = output_dir / f"{file_path.stem}_advanced_analysis.txt"
    with open(report_file, 'w') as f:
        f.write(f"Advanced Analysis Report for {file_path.name}\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("File Information:\n")
        f.write(f"  Size: {file_size} bytes\n")
        f.write(f"  MD5: {file_md5}\n")
        f.write(f"  Entropy: {file_entropy:.2f}\n\n")
        
        f.write("File Signatures:\n")
        if signatures:
            for sig in signatures:
                f.write(f"  {sig['description']}:\n")
                for pos in sig['positions'][:10]:
                    f.write(f"    Offset: 0x{pos:X}\n")
                if len(sig['positions']) > 10:
                    f.write(f"    And {len(sig['positions']) - 10} more...\n")
        else:
            f.write("  No file signatures found\n")
        f.write("\n")
        
        f.write("Custom Patterns:\n")
        if custom_patterns:
            for pattern in custom_patterns:
                f.write(f"  {pattern['description']}:\n")
                for pos in pattern['positions'][:10]:
                    f.write(f"    Offset: 0x{pos:X}\n")
                if len(pattern['positions']) > 10:
                    f.write(f"    And {len(pattern['positions']) - 10} more...\n")
        else:
            f.write("  No custom patterns found\n")
        f.write("\n")
        
        f.write("Interesting Sections:\n")
        if interesting_sections:
            for i, section in enumerate(interesting_sections):
                f.write(f"  Section #{i+1}:\n")
                f.write(f"    Range: 0x{section['start_offset']:X} - 0x{section['end_offset']:X}\n")
                f.write(f"    Entropy Change: {section['entropy_before']:.2f} -> {section['entropy_after']:.2f}\n")
        else:
            f.write("  No interesting sections found\n")
        f.write("\n")
        
        f.write("Multi-Stage Decryption Results:\n")
        if decryption_results:
            for i, result in enumerate(decryption_results):
                f.write(f"  Result #{i+1}:\n")
                f.write(f"    Stage: {result['stage']}\n")
                f.write(f"    Method: {result['method']}\n")
                f.write(f"    Key: {result['key']}\n")
                if 'section' in result:
                    f.write(f"    Section: {result['section']}\n")
                if 'offset' in result:
                    f.write(f"    Offset: {result['offset']}\n")
                f.write(f"    Output File: {Path(result['file']).name}\n")
                f.write("    Signatures Found:\n")
                for sig in result['signatures']:
                    f.write(f"      {sig['description']}: {len(sig['positions'])} occurrences\n")
                f.write("\n")
        else:
            f.write("  No successful decryptions found\n")
    
    print(f"{ANSI_GREEN}[+] Analysis report saved to: {report_file}{ANSI_RESET}")
    return output_dir, report_file

def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Advanced Analysis Tool')
    parser.add_argument('file', help='Path to the payload file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for analysis results')
    args = parser.parse_args()
    
    try:
        output_dir, report_file = analyze_file(args.file, args.output)
        print(f"{ANSI_GREEN}[+] Analysis complete!{ANSI_RESET}")
        print(f"{ANSI_GREEN}[+] Results saved to: {output_dir}{ANSI_RESET}")
    except Exception as e:
        print(f"{ANSI_RED}[!] Error: {str(e)}{ANSI_RESET}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
