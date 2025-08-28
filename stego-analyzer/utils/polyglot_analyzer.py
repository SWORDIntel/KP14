#!/usr/bin/env python3
"""
Polyglot File Analyzer
A tool to analyze polyglot files, particularly ODG files with hidden content

This tool can:
1. Identify where the legitimate file structure ends
2. Extract any appended content
3. Analyze the extracted content
"""

import sys
import struct
import argparse
import hashlib
import zipfile
import re
import math
from pathlib import Path
from collections import defaultdict
import binascii # Added back

# ANSI Colors for terminal output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# Known XOR keys used by APT-41's KEYPLUG (example, can be expanded)
KNOWN_XOR_KEYS = [
    "9e", "d3", "a5",
    "0a61200d", "410d200d", "4100200d",
    "41414141", "00000000", "ffffffff", "12345678", "87654321", "deadbeef"
]


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
    
    counter = defaultdict(int)
    for byte in data:
        counter[byte] += 1
    
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
    mz_offsets = [match.start() for match in re.finditer(b'MZ', data)]
    
    for offset in mz_offsets:
        if offset + 64 > len(data):
            continue
        try:
            pe_offset_pos = offset + 0x3C
            if pe_offset_pos + 4 > len(data):
                continue
            pe_header_offset_in_mz = struct.unpack("<I", data[pe_offset_pos:pe_offset_pos+4])[0]
            pe_header_pos = offset + pe_header_offset_in_mz
            
            if pe_header_pos + 4 > len(data):
                continue
            pe_sig = data[pe_header_pos:pe_header_pos+4]
            
            if pe_sig == b'PE\x00\x00':
                size = min(5 * 1024 * 1024, len(data) - offset)
                results.append((offset, size))
        except Exception:  # Catch any struct.unpack or other errors
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
    try:
        payload_str = data.decode('utf-8', errors='ignore')
        url_pattern = r'https?://[^\s"\'>]{4,255}'
        results["urls"] = re.findall(url_pattern, payload_str)

        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        all_domains = re.findall(domain_pattern, payload_str)
        results["domains"] = [d for d in all_domains if not any(d in url for url in results["urls"])]

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        results["ips"] = re.findall(ip_pattern, payload_str)
    except Exception as e:
        print(f"{ANSI_RED}[!] Error extracting network indicators: {str(e)}{ANSI_RESET}")
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
    keyplug_markers = [
        (b"KEYP", "KEYPLUG marker"), (b"RC4", "RC4 encryption reference"),
        (b"cmd.exe", "Command shell reference"), (b"powershell", "PowerShell reference"),
        (b"rundll32", "RunDLL32 reference"), (b"regsvr32", "RegSvr32 reference"),
        (b"VirtualAlloc", "Memory allocation API"), (b"CreateProcess", "Process creation API"),
        (b"WSASocket", "Socket API"), (b"http", "HTTP protocol reference")
    ]
    for marker, description in keyplug_markers:
        if marker in data:
            signatures.append(description)
    return signatures

def perform_xor_decryption(data, key_hex):
    """
    Perform XOR decryption with a hex key.
    Args:
        data (bytes): Data to decrypt
        key_hex (str): Hexadecimal key
    Returns:
        bytes: Decrypted data
    """
    key_bytes = bytes.fromhex(key_hex)
    key_len = len(key_bytes)
    return bytes([data[i] ^ key_bytes[i % key_len] for i in range(len(data))])

def try_common_xor_keys(data, sample_size=1024):
    """
    Try common XOR keys to decrypt data.
    Args:
        data (bytes): Data to decrypt
        sample_size (int): Size of data sample to analyze
    Returns:
        list: List of possible decryption results with metadata
    """
    results = []
    sample = data[:min(sample_size, len(data))]
    for key_hex in KNOWN_XOR_KEYS:
        try:
            decrypted = perform_xor_decryption(sample, key_hex)
            pe_marker = b'MZ' in decrypted[:1024] and b'PE\x00\x00' in decrypted # Check PE in first 1KB
            readable_text = sum(32 <= b <= 126 for b in decrypted[:1024]) / min(1024, len(decrypted)) > 0.7
            entropy = calculate_entropy(decrypted)
            
            if pe_marker or readable_text or (entropy < 6.8 and (sum(b==0 for b in decrypted[:1024])/min(1024,len(decrypted))) < 0.2)): # Avoid mostly nulls
                full_decrypted = perform_xor_decryption(data, key_hex)
                results.append({
                    "key": key_hex, "data": full_decrypted, "entropy": entropy,
                    "contains_pe": pe_marker, "readable_text": readable_text
                })
        except Exception as e: # Catch specific errors if possible, e.g., ValueError for bad hex
            print(f"{ANSI_RED}[!] Error decrypting with key {key_hex}: {str(e)}{ANSI_RESET}")
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
    end_sig = b'\x50\x4b\x05\x06'
    pos = file_data.rfind(end_sig)
    if pos == -1: return -1
    if pos + 22 > len(file_data): return -1 # EOCD record is 22 bytes minimum
    comment_length = struct.unpack("<H", file_data[pos+20:pos+22])[0]
    return pos + 22 + comment_length

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
    else:
        output_dir = file_path.parent / f"{file_path.stem}_extracted"
    output_dir.mkdir(exist_ok=True, parents=True)
    
    results = {
        "file": {"name": file_path.name, "size": 0, "md5": "", "sha256": ""},
        "structure": {"is_polyglot": False, "container_format": "", "container_end": 0, "hidden_content_start": 0, "hidden_content_size": 0},
        "hidden_content": {"md5": "", "sha256": "", "entropy": 0.0, "extracted_file": "", "indicators": [], "contains_pe": False, "network_indicators": {}, "possible_decryptions": []}
    }
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        results["file"]["size"] = len(file_data)
        results["file"]["md5"] = hashlib.md5(file_data).hexdigest()
        results["file"]["sha256"] = hashlib.sha256(file_data).hexdigest()

        if file_path.suffix.lower() == '.odg':
            results["structure"]["container_format"] = "OpenDocument Drawing (ZIP)"
            zip_end = find_zip_end(file_data)
            if 0 < zip_end < len(file_data):
                results["structure"]["is_polyglot"] = True
                results["structure"]["container_end"] = zip_end
                results["structure"]["hidden_content_start"] = zip_end
                hidden_data = file_data[zip_end:]
                results["structure"]["hidden_content_size"] = len(hidden_data)
                
                hidden_file = output_dir / f"{file_path.stem}_hidden.bin"
                with open(hidden_file, 'wb') as f_hidden: f_hidden.write(hidden_data)
                
                hc = results["hidden_content"]
                hc["extracted_file"] = str(hidden_file)
                hc["md5"] = hashlib.md5(hidden_data).hexdigest()
                hc["sha256"] = hashlib.sha256(hidden_data).hexdigest()
                hc["entropy"] = calculate_entropy(hidden_data)
                hc["indicators"] = check_known_signatures(hidden_data)
                
                pe_files = find_embedded_pe(hidden_data)
                if pe_files:
                    hc["contains_pe"] = True
                    for i, (offset, size) in enumerate(pe_files):
                        pe_data = hidden_data[offset:offset+size]
                        pe_file_path = output_dir / f"{file_path.stem}_embedded_pe_{i}.bin"
                        with open(pe_file_path, 'wb') as f_pe: f_pe.write(pe_data)

                hc["network_indicators"] = extract_network_indicators(hidden_data)
                decryption_results = try_common_xor_keys(hidden_data)
                for i, result in enumerate(decryption_results):
                    dec_file_path = output_dir / f"{file_path.stem}_decrypted_xor_{result['key']}.bin"
                    with open(dec_file_path, 'wb') as f_dec: f_dec.write(result["data"])
                    result_copy = result.copy(); del result_copy["data"]; result_copy["file"] = str(dec_file_path)
                    hc["possible_decryptions"].append(result_copy)
        
        report_file_path = output_dir / f"{file_path.stem}_analysis_report.txt"
        with open(report_file_path, 'w') as f_report:
            f_report.write(f"Analysis Report for {results['file']['name']}\n==================================================\n\n")
            f_report.write(f"File Information:\n  Name: {results['file']['name']}\n  Size: {results['file']['size']} bytes\n  MD5: {results['file']['md5']}\n\n")
            f_report.write(f"Structure Analysis:\n  Container Format: {results['structure']['container_format']}\n  Is Polyglot: {results['structure']['is_polyglot']}\n")
            if results["structure"]["is_polyglot"]:
                f_report.write(f"  Container End: 0x{results['structure']['container_end']:X}\n  Hidden Content Start: 0x{results['structure']['hidden_content_start']:X}\n  Hidden Content Size: {results['structure']['hidden_content_size']} bytes\n\n")
                hc = results["hidden_content"]
                f_report.write(f"Hidden Content Analysis:\n  Extracted File: {hc['extracted_file']}\n  MD5: {hc['md5']}\n  Entropy: {hc['entropy']:.2f}\n  Contains PE: {hc['contains_pe']}\n\n")
                if hc["indicators"]: f_report.write(f"Suspicious Indicators:\n" + "\n".join([f"  - {ind}" for ind in hc["indicators"]]) + "\n\n")
                if any(hc["network_indicators"].values()):
                    f_report.write("Network Indicators:\n")
                    for ind_type, inds in hc["network_indicators"].items():
                        if inds: f_report.write(f"  {ind_type.capitalize()}:\n" + "\n".join([f"    - {i}" for i in inds]) + "\n")
                    f_report.write("\n")
                if hc["possible_decryptions"]:
                    f_report.write("Possible Decryptions:\n")
                    for i, dec in enumerate(hc["possible_decryptions"]):
                        f_report.write(f"  Attempt {i+1}:\n    XOR Key: {dec['key']}\n    Output File: {dec['file']}\n    Entropy: {dec['entropy']:.2f}\n    Contains PE: {dec['contains_pe']}\n    Readable Text: {dec['readable_text']}\n\n")
            else: f_report.write("No polyglot structure detected or no hidden content found.\n")
        print(f"{ANSI_GREEN}[+] Analysis report saved to: {report_file_path}{ANSI_RESET}")
        return results, str(report_file_path)

    except Exception as e_main: # Changed bare except
        print(f"{ANSI_RED}[!] Error analyzing ODG file {file_path}: {str(e_main)}{ANSI_RESET}")
        return None, None

def main():
    parser = argparse.ArgumentParser(description='Polyglot File Analyzer')
    parser.add_argument('file', help='Path to the file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    args = parser.parse_args()
    
    try:
        print(f"{ANSI_BLUE}[*] Analyzing {args.file} for KEYPLUG payloads...{ANSI_RESET}")
        results, report_file = analyze_polyglot(args.file, args.output)
        
        if results and results["structure"]["is_polyglot"]: # Check results is not None
            print(f"{ANSI_GREEN}[+] Polyglot file detected!{ANSI_RESET}")
            print("Hidden content size: {} bytes".format(results['structure']['hidden_content_size']))
            print("Extracted to: {}".format(results['hidden_content']['extracted_file']))
            
            if results["hidden_content"]["indicators"]:
                print(f"{ANSI_YELLOW}[!] Suspicious indicators found: {len(results['hidden_content']['indicators'])}{ANSI_RESET}")
            
            if results["hidden_content"]["contains_pe"]:
                print(f"{ANSI_RED}[!] Embedded PE file detected!{ANSI_RESET}")
            
            if results["hidden_content"]["possible_decryptions"]:
                print("Found {} possible decryptions".format(len(results['hidden_content']['possible_decryptions'])))
            
            print("Analysis report saved to: {}".format(report_file))
        elif results: # If results is not None, but not polyglot
            print(f"{ANSI_YELLOW}[!] No polyglot structure detected in {args.file}{ANSI_RESET}")
        else: # If results is None (error during analysis)
             print(f"{ANSI_RED}[!] Analysis failed for {args.file}{ANSI_RESET}")

    except Exception as e_global: # Changed bare except
        print(f"{ANSI_RED}[!] Error: {str(e_global)}{ANSI_RESET}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
