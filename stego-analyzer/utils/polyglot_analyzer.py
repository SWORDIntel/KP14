#!/usr/bin/env python3
"""
Polyglot File Analyzer
A tool to analyze polyglot files, particularly ODG files with hidden content

This tool can:
1. Identify where the legitimate file structure ends
2. Extract any appended content
3. Analyze the extracted content
"""

import os
import sys
import binascii
import struct
import argparse
import hashlib
import zlib
import zipfile
import io
import re
import math
from pathlib import Path
from collections import defaultdict

# ANSI Colors for terminal output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

def calculate_entropy(data, base=2):
    """
    Calculate Shannon entropy of data.
    Args:
        data (bytes): Data to calculate entropy for
        base (int): Logarithmic base (2 for bits, 10 for decimal)
    Returns:
        float: Shannon entropy value
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    counter = defaultdict(int)
    for byte in data:
        counter[byte] += 1
    
    # Calculate entropy
    total_bytes = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / total_bytes
        entropy -= probability * math.log(probability, base)
    
    return entropy

def find_embedded_pe(data):
    """
    Detect embedded PE files within binary data.
    Args:
        data (bytes): Binary data to scan
    Returns:
        list: List of tuples (offset, size) for potential PE files
    """
    results = []
    
    # Look for MZ header followed by PE signature
    mz_offsets = [match.start() for match in re.finditer(b'MZ', data)]
    
    for offset in mz_offsets:
        # Check minimum size
        if offset + 64 > len(data):
            continue
        
        # Check for PE header
        try:
            pe_offset_pos = offset + 0x3C
            if pe_offset_pos + 4 > len(data):
                continue
                
            pe_offset = struct.unpack("<I", data[pe_offset_pos:pe_offset_pos+4])[0]
            pe_header_pos = offset + pe_offset
            
            if pe_header_pos + 4 > len(data):
                continue
                
            pe_sig = data[pe_header_pos:pe_header_pos+4]
            
            if pe_sig == b'PE\x00\x00':
                # Estimate PE file size (simplified)
                size = min(5 * 1024 * 1024, len(data) - offset)  # Limit to 5MB or remaining data
                results.append((offset, size))
        except:
            continue
    
    return results

def extract_network_indicators(data):
    """
    Extract potential network indicators from binary data.
    Args:
        data (bytes): Binary data to scan
    Returns:
        dict: Dictionary of network indicators by type
    """
    results = {
        "domains": [],
        "urls": [],
        "ips": []
    }
    
    # URL pattern
    url_pattern = rb'https?://[^\s"\'>]{4,255}'
    results["urls"] = [match.group(0).decode('utf-8', errors='replace') 
                       for match in re.finditer(url_pattern, data)]
    
    # Domain pattern
    domain_pattern = rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    # Filter out domains that are part of URLs
    domains = [match.group(0).decode('utf-8', errors='replace') 
               for match in re.finditer(domain_pattern, data)]
    results["domains"] = [d for d in domains if not any(d in url for url in results["urls"])]
    
    # IP pattern
    ip_pattern = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    results["ips"] = [match.group(0).decode('utf-8', errors='replace') 
                      for match in re.finditer(ip_pattern, data)]
    
    return results

def check_known_signatures(data):
    """
    Check for known malware signatures in the data.
    Args:
        data (bytes): Binary data to scan
    Returns:
        list: List of detected signatures
    """
    signatures = []
    
    # Check for common malware markers
    markers = [
        (b"This program cannot be run in DOS mode", "DOS stub text"),
        (b"cmd.exe", "Command shell reference"),
        (b"powershell", "PowerShell reference"),
        (b"rundll32", "RunDLL32 reference"),
        (b"regsvr32", "RegSvr32 reference"),
        (b"CreateProcess", "Process creation API"),
        (b"VirtualAlloc", "Memory allocation API"),
        (b"WSASocket", "Socket API"),
        (b"HTTP/1.", "HTTP protocol reference"),
        (b"Mozilla/5.0", "User-Agent string"),
        (b"RC4", "RC4 encryption reference")
    ]
    
    for marker, description in markers:
        if marker in data:
            signatures.append(description)
    
    return signatures

def perform_xor_decryption(data, key_hex):
    """
    Perform XOR decryption with a hex key.
    Args:
        data (bytes): Data to decrypt
        key_hex (str): Hexadecimal key (e.g. "0A1B2C3D")
    Returns:
        bytes: Decrypted data
    """
    # Convert hex key to bytes
    key_bytes = bytes.fromhex(key_hex)
    key_len = len(key_bytes)
    
    # Perform XOR decryption
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[i % key_len]
    
    return bytes(result)

def try_common_xor_keys(data, sample_size=1024):
    """
    Try common XOR keys to decrypt data.
    Args:
        data (bytes): Data to decrypt
        sample_size (int): Size of data sample to analyze
    Returns:
        list: List of possible decryption results with metadata
    """
    common_keys = [
        "00", "FF", "AA", "55",                 # Common single-byte keys
        "9e", "d3", "a5",                       # Common APT keys
        "0a61200d", "410d200d", "4100200d",     # Multi-byte keys
        "41414141", "00000000", "ffffffff",     # Common patterns
        "12345678", "87654321", "deadbeef"      # Other common keys
    ]
    
    results = []
    sample = data[:min(sample_size, len(data))]
    
    for key in common_keys:
        try:
            decrypted = perform_xor_decryption(sample, key)
            pe_marker = b'MZ' in decrypted and b'PE\x00\x00' in decrypted
            readable_text = sum(32 <= b <= 126 for b in decrypted) / len(decrypted) > 0.7
            ascii_marker = sum(0 <= b <= 127 for b in decrypted) / len(decrypted) > 0.9
            entropy = calculate_entropy(decrypted)
            
            # Check if decryption looks promising
            is_promising = pe_marker or readable_text or (entropy < 6.8 and ascii_marker)
            
            if is_promising:
                # Decrypt the entire data if the sample looks promising
                full_decrypted = perform_xor_decryption(data, key)
                results.append({
                    "key": key,
                    "data": full_decrypted,
                    "entropy": entropy,
                    "contains_pe": pe_marker,
                    "readable_text": readable_text
                })
        except:
            continue
    
    return results

def find_zip_end(file_data):
    """
    Find the end of the ZIP structure in a file.
    Args:
        file_data (bytes): Complete file data
    Returns:
        int: Position where the ZIP structure ends, or -1 if not found
    """
    # Look for End of Central Directory signature (0x06054b50)
    end_sig = b'\x50\x4b\x05\x06'
    
    # Start from the end and search backwards
    pos = file_data.rfind(end_sig)
    
    if pos == -1:
        return -1
    
    # Read the central directory size and offset
    if pos + 20 > len(file_data):
        return -1
    
    # Extract size of the central directory and its offset
    central_dir_size = struct.unpack("<I", file_data[pos+12:pos+16])[0]
    central_dir_offset = struct.unpack("<I", file_data[pos+16:pos+20])[0]
    
    # Calculate where the zip file should end
    zip_end = pos + 22  # End of central directory record size
    
    # Check if there's a comment
    if pos + 22 <= len(file_data):
        comment_length = struct.unpack("<H", file_data[pos+20:pos+22])[0]
        zip_end += comment_length
    
    return zip_end

def analyze_polyglot(file_path, output_dir=None):
    """
    Analyze a polyglot file and extract embedded content.
    Args:
        file_path (str): Path to the file to analyze
        output_dir (str): Directory to save extracted content
    Returns:
        dict: Analysis results
    """
    file_path = Path(file_path)
    
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)
    else:
        output_dir = file_path.parent / f"{file_path.stem}_extracted"
        output_dir.mkdir(exist_ok=True, parents=True)
    
    results = {
        "file": {
            "name": file_path.name,
            "size": file_path.stat().st_size,
            "md5": "",
            "sha256": ""
        },
        "structure": {
            "is_polyglot": False,
            "container_format": "",
            "container_end": 0,
            "hidden_content_start": 0,
            "hidden_content_size": 0
        },
        "hidden_content": {
            "md5": "",
            "sha256": "",
            "entropy": 0.0,
            "extracted_file": "",
            "indicators": [],
            "contains_pe": False,
            "network_indicators": {},
            "possible_decryptions": []
        }
    }
    
    # Calculate file hashes
    with open(file_path, 'rb') as f:
        file_data = f.read()
        results["file"]["md5"] = hashlib.md5(file_data).hexdigest()
        results["file"]["sha256"] = hashlib.sha256(file_data).hexdigest()
    
    # Analyze file structure
    if file_path.suffix.lower() == '.odg':
        results["structure"]["container_format"] = "OpenDocument Drawing (ZIP)"
        
        # Try to find where the ZIP structure ends
        zip_end = find_zip_end(file_data)
        
        if zip_end > 0 and zip_end < len(file_data):
            results["structure"]["is_polyglot"] = True
            results["structure"]["container_end"] = zip_end
            results["structure"]["hidden_content_start"] = zip_end
            
            # Extract hidden content
            hidden_data = file_data[zip_end:]
            results["structure"]["hidden_content_size"] = len(hidden_data)
            
            # Save hidden content
            hidden_file = output_dir / f"{file_path.stem}_hidden.bin"
            with open(hidden_file, 'wb') as f:
                f.write(hidden_data)
            
            results["hidden_content"]["extracted_file"] = str(hidden_file)
            results["hidden_content"]["md5"] = hashlib.md5(hidden_data).hexdigest()
            results["hidden_content"]["sha256"] = hashlib.sha256(hidden_data).hexdigest()
            results["hidden_content"]["entropy"] = calculate_entropy(hidden_data)
            
            # Check for signatures
            results["hidden_content"]["indicators"] = check_known_signatures(hidden_data)
            
            # Check for embedded PE files
            pe_files = find_embedded_pe(hidden_data)
            if pe_files:
                results["hidden_content"]["contains_pe"] = True
                
                # Extract PE files
                for i, (offset, size) in enumerate(pe_files):
                    pe_data = hidden_data[offset:offset+size]
                    pe_file = output_dir / f"{file_path.stem}_embedded_pe_{i}.bin"
                    with open(pe_file, 'wb') as f:
                        f.write(pe_data)
            
            # Extract network indicators
            results["hidden_content"]["network_indicators"] = extract_network_indicators(hidden_data)
            
            # Try decryption with common XOR keys
            decryption_results = try_common_xor_keys(hidden_data)
            for i, result in enumerate(decryption_results):
                decrypted_file = output_dir / f"{file_path.stem}_decrypted_xor_{result['key']}.bin"
                with open(decrypted_file, 'wb') as f:
                    f.write(result["data"])
                
                # Don't store the full data in the results to keep it manageable
                result_copy = result.copy()
                del result_copy["data"]
                result_copy["file"] = str(decrypted_file)
                
                results["hidden_content"]["possible_decryptions"].append(result_copy)
    
    # Generate report
    report_file = output_dir / f"{file_path.stem}_analysis_report.txt"
    with open(report_file, 'w') as f:
        f.write(f"Analysis Report for {file_path.name}\n")
        f.write("="*50 + "\n\n")
        
        f.write("File Information:\n")
        f.write(f"  Name: {results['file']['name']}\n")
        f.write(f"  Size: {results['file']['size']} bytes\n")
        f.write(f"  MD5: {results['file']['md5']}\n")
        f.write(f"  SHA256: {results['file']['sha256']}\n\n")
        
        f.write("Structure Analysis:\n")
        f.write(f"  Container Format: {results['structure']['container_format']}\n")
        f.write(f"  Is Polyglot: {results['structure']['is_polyglot']}\n")
        
        if results["structure"]["is_polyglot"]:
            f.write(f"  Container End Position: 0x{results['structure']['container_end']:X}\n")
            f.write(f"  Hidden Content Start: 0x{results['structure']['hidden_content_start']:X}\n")
            f.write(f"  Hidden Content Size: {results['structure']['hidden_content_size']} bytes\n\n")
            
            f.write("Hidden Content Analysis:\n")
            f.write(f"  Extracted File: {results['hidden_content']['extracted_file']}\n")
            f.write(f"  MD5: {results['hidden_content']['md5']}\n")
            f.write(f"  SHA256: {results['hidden_content']['sha256']}\n")
            f.write(f"  Entropy: {results['hidden_content']['entropy']:.2f}\n")
            f.write(f"  Contains PE: {results['hidden_content']['contains_pe']}\n\n")
            
            if results["hidden_content"]["indicators"]:
                f.write("Suspicious Indicators:\n")
                for indicator in results["hidden_content"]["indicators"]:
                    f.write(f"  - {indicator}\n")
                f.write("\n")
            
            if results["hidden_content"]["network_indicators"]:
                f.write("Network Indicators:\n")
                for indicator_type, indicators in results["hidden_content"]["network_indicators"].items():
                    if indicators:
                        f.write(f"  {indicator_type.capitalize()}:\n")
                        for indicator in indicators:
                            f.write(f"    - {indicator}\n")
                f.write("\n")
            
            if results["hidden_content"]["possible_decryptions"]:
                f.write("Possible Decryptions:\n")
                for i, decryption in enumerate(results["hidden_content"]["possible_decryptions"]):
                    f.write(f"  Decryption {i+1}:\n")
                    f.write(f"    XOR Key: {decryption['key']}\n")
                    f.write(f"    Output File: {decryption['file']}\n")
                    f.write(f"    Entropy: {decryption['entropy']:.2f}\n")
                    f.write(f"    Contains PE: {decryption['contains_pe']}\n")
                    f.write(f"    Readable Text: {decryption['readable_text']}\n\n")
    
    return results, str(report_file)

def main():
    parser = argparse.ArgumentParser(description='Polyglot File Analyzer')
    parser.add_argument('file', help='Path to the file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    args = parser.parse_args()
    
    try:
        print(f"{ANSI_BLUE}[*] Analyzing {args.file}...{ANSI_RESET}")
        results, report_file = analyze_polyglot(args.file, args.output)
        
        if results["structure"]["is_polyglot"]:
            print(f"{ANSI_GREEN}[+] Polyglot file detected!{ANSI_RESET}")
            print(f"{ANSI_GREEN}[+] Hidden content size: {results['structure']['hidden_content_size']} bytes{ANSI_RESET}")
            print(f"{ANSI_GREEN}[+] Extracted to: {results['hidden_content']['extracted_file']}{ANSI_RESET}")
            
            if results["hidden_content"]["indicators"]:
                print(f"{ANSI_YELLOW}[!] Suspicious indicators found: {len(results['hidden_content']['indicators'])}{ANSI_RESET}")
            
            if results["hidden_content"]["contains_pe"]:
                print(f"{ANSI_RED}[!] Embedded PE file detected!{ANSI_RESET}")
            
            if results["hidden_content"]["possible_decryptions"]:
                print(f"{ANSI_CYAN}[+] Found {len(results['hidden_content']['possible_decryptions'])} possible decryptions{ANSI_RESET}")
            
            print(f"{ANSI_GREEN}[+] Analysis report saved to: {report_file}{ANSI_RESET}")
        else:
            print(f"{ANSI_YELLOW}[!] No polyglot structure detected{ANSI_RESET}")
    
    except Exception as e:
        print(f"{ANSI_RED}[!] Error: {str(e)}{ANSI_RESET}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
