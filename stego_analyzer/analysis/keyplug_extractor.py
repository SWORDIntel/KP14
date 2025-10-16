#!/usr/bin/env python3
"""
KEYPLUG Extractor
A specialized tool for extracting and analyzing APT-41's KEYPLUG malware payloads from ODG files
Based on the analysis report and known KEYPLUG techniques
"""

import sys
import struct
import hashlib
import zipfile
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
    "9e", "d3", "a5",
    # Multi-byte keys
    "0a61200d", "410d200d", "4100200d",
    # Other common keys
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

def extract_jpeg_payload(jpeg_data, method="forced_heuristic"):
    """
    Extract hidden payload from JPEG data using various methods.
    Args:
        jpeg_data (bytes): JPEG file data
        method (str): Detection method to use
    Returns:
        bytes: Extracted payload data or None if not found
    """
    if method == "forced_heuristic":
        # Check for valid JPEG
        if not jpeg_data.startswith(b'\xFF\xD8'):
            return None
        
        # Find the EOI marker
        eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
        
        if eoi_pos == -1:
            return None
        
        # Extract data after EOI marker
        payload = jpeg_data[eoi_pos + 2:]
        
        # If no payload found, use a more aggressive method to find hidden data within JPEG
        if not payload:
            # Look for potential malicious code injection points
            # Common injection points include after APP markers, after COM markers, etc.
            markers = [
                b'\xFF\xE0', b'\xFF\xE1', b'\xFF\xE2', b'\xFF\xE3',
                b'\xFF\xE4', b'\xFF\xE5', b'\xFF\xE6', b'\xFF\xE7',
                b'\xFF\xE8', b'\xFF\xE9', b'\xFF\xEA', b'\xFF\xEB',
                b'\xFF\xEC', b'\xFF\xED', b'\xFF\xEE', b'\xFF\xEF',
                b'\xFF\xFE'
            ]
            
            for marker in markers:
                pos = jpeg_data.find(marker)
                if pos != -1:
                    # Get the length of the segment
                    if pos + 2 < len(jpeg_data):
                        length = struct.unpack('>H', jpeg_data[pos+2:pos+4])[0]
                        end_pos = pos + 2 + length
                        
                        # Check if there's unexpected data after the segment
                        if end_pos < len(jpeg_data) and jpeg_data[end_pos:end_pos+2] not in [b'\xFF\xD9'] + markers:
                            # Extract a chunk of data after this segment
                            payload = jpeg_data[end_pos:end_pos+1024]
                            if calculate_entropy(payload) > 7.0:
                                # Extract all data from this position to the end
                                payload = jpeg_data[end_pos:]
                                break
            
            # If still no payload, use a brute force approach to find high-entropy data
            if not payload:
                # Scan for high-entropy regions
                window_size = 1024
                step = 512
                highest_entropy = 0
                highest_entropy_pos = 0
                
                for i in range(0, len(jpeg_data) - window_size, step):
                    window = jpeg_data[i:i+window_size]
                    entropy = calculate_entropy(window)
                    
                    if entropy > highest_entropy:
                        highest_entropy = entropy
                        highest_entropy_pos = i
                
                if highest_entropy > 7.0:
                    payload = jpeg_data[highest_entropy_pos:]
        
        return payload
    
    return None

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
        except Exception as ex:
            # Log the exception or handle it more gracefully
            print(f"{ANSI_RED}[!] Error processing potential PE file at offset {offset}: {str(ex)}{ANSI_RESET}")
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

def check_for_keyplug_patterns(data):
    """
    Check for patterns specific to KEYPLUG malware.
    Args:
        data (bytes): Binary data to scan
    Returns:
        list: List of detected patterns
    """
    patterns = []
    
    # Look for KEYPLUG markers
    keyplug_markers = [
        (b"KEYP", "KEYPLUG marker"),
        (b"RC4", "RC4 encryption reference"),
        (b"cmd.exe", "Command shell reference"),
        (b"powershell", "PowerShell reference"),
        (b"rundll32", "RunDLL32 reference"),
        (b"regsvr32", "RegSvr32 reference"),
        (b"VirtualAlloc", "Memory allocation API"),
        (b"CreateProcess", "Process creation API"),
        (b"WSASocket", "Socket API"),
        (b"http", "HTTP protocol reference")
    ]
    
    for marker, description in keyplug_markers:
        if marker in data:
            patterns.append(description)
    
    return patterns

def analyze_odg_file(odg_path, output_dir=None):
    """
    Analyze an ODG file for KEYPLUG malware.
    Args:
        odg_path (str): Path to the ODG file
        output_dir (str): Directory to save extracted content
    Returns:
        dict: Analysis results
    """
    odg_path = Path(odg_path)
    
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)
    else:
        output_dir = odg_path.parent / f"{odg_path.stem}_keyplug_extracted"
        output_dir.mkdir(exist_ok=True, parents=True)
    
    results = {
        "file": {
            "name": odg_path.name,
            "size": odg_path.stat().st_size,
            "md5": hashlib.md5(open(odg_path, 'rb').read()).hexdigest()
        },
        "payloads": []
    }
    
    try:
        # Extract the ODG file (which is a ZIP file)
        temp_dir = output_dir / "odg_contents"
        temp_dir.mkdir(exist_ok=True)
        
        with zipfile.ZipFile(odg_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Look for image files in the Pictures directory
        pictures_dir = temp_dir / "Pictures"
        if pictures_dir.exists():
            jpeg_files = list(pictures_dir.glob("*.jpg")) + list(pictures_dir.glob("*.jpeg"))
            
            print(f"{ANSI_BLUE}[*] Found {len(jpeg_files)} JPEG files in ODG{ANSI_RESET}")
            
            for jpeg_file in jpeg_files:
                jpeg_data = open(jpeg_file, 'rb').read()
                jpeg_md5 = hashlib.md5(jpeg_data).hexdigest()
                
                print(f"{ANSI_BLUE}[*] Analyzing {jpeg_file.name} (MD5: {jpeg_md5}){ANSI_RESET}")
                
                # Extract payload
                payload = extract_jpeg_payload(jpeg_data)
                
                if payload and len(payload) > 0:
                    payload_md5 = hashlib.md5(payload).hexdigest()
                    payload_sha1 = hashlib.sha1(payload).hexdigest()
                    payload_sha256 = hashlib.sha256(payload).hexdigest()
                    payload_entropy = calculate_entropy(payload)
                    
                    # Save the payload
                    payload_file = output_dir / f"{jpeg_file.stem}_forced_{payload_md5[:8]}.bin"
                    with open(payload_file, 'wb') as f:
                        f.write(payload)
                    
                    print(f"{ANSI_GREEN}[+] Extracted payload: {payload_file.name} ({len(payload)} bytes){ANSI_RESET}")
                    print(f"{ANSI_GREEN}[+] MD5: {payload_md5}{ANSI_RESET}")
                    print(f"{ANSI_GREEN}[+] Entropy: {payload_entropy:.2f}{ANSI_RESET}")
                    
                    # Check for KEYPLUG patterns
                    keyplug_patterns = check_for_keyplug_patterns(payload)
                    
                    if keyplug_patterns:
                        print(f"{ANSI_YELLOW}[!] Found KEYPLUG patterns: {', '.join(keyplug_patterns)}{ANSI_RESET}")
                    
                    # Find embedded PE files
                    pe_files = find_embedded_pe(payload)
                    
                    if pe_files:
                        print(f"{ANSI_RED}[!] Found {len(pe_files)} embedded PE files{ANSI_RESET}")
                        
                        # Extract PE files
                        for i, (offset, size) in enumerate(pe_files):
                            pe_data = payload[offset:offset+size]
                            pe_file = output_dir / f"{jpeg_file.stem}_pe_{i}.bin"
                            with open(pe_file, 'wb') as f:
                                f.write(pe_data)
                            
                            print(f"{ANSI_RED}[!] Extracted PE file: {pe_file.name} ({len(pe_data)} bytes){ANSI_RESET}")
                    
                    # Extract network indicators
                    network_indicators = extract_network_indicators(payload)
                    
                    if any(network_indicators.values()):
                        print(f"{ANSI_YELLOW}[!] Found network indicators{ANSI_RESET}")
                        if network_indicators["domains"]:
                            print(f"{ANSI_YELLOW}[!] Domains: {', '.join(network_indicators['domains'])}{ANSI_RESET}")
                        if network_indicators["urls"]:
                            print(f"{ANSI_YELLOW}[!] URLs: {', '.join(network_indicators['urls'])}{ANSI_RESET}")
                        if network_indicators["ips"]:
                            print(f"{ANSI_YELLOW}[!] IPs: {', '.join(network_indicators['ips'])}{ANSI_RESET}")
                    
                    # Try to decrypt the payload with known XOR keys
                    decrypted_files = []
                    
                    for i, key in enumerate(KNOWN_XOR_KEYS):
                        try:
                            decrypted = perform_xor_decryption(payload, key)
                            decrypted_md5 = hashlib.md5(decrypted).hexdigest()
                            decrypted_entropy = calculate_entropy(decrypted)
                            
                            # Check if decryption looks promising
                            has_pe = b'MZ' in decrypted[:1024]
                            has_text = sum(32 <= b <= 126 for b in decrypted[:1024]) / min(1024, len(decrypted)) > 0.7
                            
                            if has_pe or has_text or decrypted_entropy < 7.0:
                                # Save the decrypted payload
                                decrypted_file = output_dir / f"{jpeg_file.stem}_decrypted_xor_{key}.bin"
                                with open(decrypted_file, 'wb') as f:
                                    f.write(decrypted)
                                
                                print(f"{ANSI_CYAN}[+] Possible decryption with key {key}: {decrypted_file.name}{ANSI_RESET}")
                                print(f"{ANSI_CYAN}[+] Decrypted MD5: {decrypted_md5}{ANSI_RESET}")
                                print(f"{ANSI_CYAN}[+] Decrypted Entropy: {decrypted_entropy:.2f}{ANSI_RESET}")
                                
                                if has_pe:
                                    print(f"{ANSI_RED}[!] Decrypted data contains PE header{ANSI_RESET}")
                                
                                decrypted_files.append({
                                    "key": key,
                                    "file": str(decrypted_file),
                                    "md5": decrypted_md5,
                                    "entropy": decrypted_entropy,
                                    "has_pe": has_pe,
                                    "has_text": has_text
                                })
                        except Exception as ex_decrypt:
                            print(f"{ANSI_RED}[!] Error decrypting with key {key}: {str(ex_decrypt)}{ANSI_RESET}")
                    
                    # Store payload information
                    payload_info = {
                        "source": {
                            "jpeg_file": jpeg_file.name,
                            "jpeg_md5": jpeg_md5,
                            "location": f"Pictures/{jpeg_file.name}",
                            "detection_method": "forced_heuristic"
                        },
                        "payload": {
                            "file": str(payload_file),
                            "size": len(payload),
                            "md5": payload_md5,
                            "sha1": payload_sha1,
                            "sha256": payload_sha256,
                            "entropy": payload_entropy,
                            "patterns": keyplug_patterns,
                            "embedded_pe": [{"offset": offset, "size": size} for offset, size in pe_files],
                            "network_indicators": network_indicators,
                            "decryption_attempts": decrypted_files
                        }
                    }
                    
                    results["payloads"].append(payload_info)
                else:
                    print(f"{ANSI_YELLOW}[!] No payload found in {jpeg_file.name}{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}[!] No Pictures directory found in ODG file{ANSI_RESET}")
        
        # Generate analysis report
        report_file = output_dir / f"{odg_path.stem}_keyplug_analysis.txt"
        with open(report_file, 'w') as f:
            f.write(f"KEYPLUG Analysis Report for {odg_path.name}\n")
            f.write("="*60 + "\n\n")
            
            f.write("File Information:\n")
            f.write(f"  Name: {results['file']['name']}\n")
            f.write(f"  Size: {results['file']['size']} bytes\n")
            f.write(f"  MD5: {results['file']['md5']}\n\n")
            
            if results["payloads"]:
                f.write(f"Found {len(results['payloads'])} hidden payloads\n\n")
                
                for i, payload in enumerate(results["payloads"]):
                    f.write(f"Payload #{i+1}\n")
                    f.write("-"*40 + "\n\n")
                    
                    f.write("Source:\n")
                    f.write(f"  JPEG File: {payload['source']['jpeg_file']}\n")
                    f.write(f"  JPEG MD5: {payload['source']['jpeg_md5']}\n")
                    f.write(f"  Location: {payload['source']['location']}\n")
                    f.write(f"  Detection Method: {payload['source']['detection_method']}\n\n")
                    
                    f.write("Payload Details:\n")
                    f.write(f"  Payload File: {Path(payload['payload']['file']).name}\n")
                    f.write(f"  Size: {payload['payload']['size']} bytes\n")
                    f.write(f"  MD5: {payload['payload']['md5']}\n")
                    f.write(f"  SHA1: {payload['payload']['sha1']}\n")
                    f.write(f"  SHA256: {payload['payload']['sha256']}\n")
                    f.write(f"  Entropy: {payload['payload']['entropy']:.2f}\n\n")
                    
                    if payload['payload']['patterns']:
                        f.write("KEYPLUG Patterns Found:\n")
                        for pattern in payload['payload']['patterns']:
                            f.write(f"  - {pattern}\n")
                        f.write("\n")
                    
                    if payload['payload']['embedded_pe']:
                        f.write(f"Embedded PE Files ({len(payload['payload']['embedded_pe'])}):\n")
                        for j, pe in enumerate(payload['payload']['embedded_pe']):
                            f.write(f"  PE #{j+1}: Offset 0x{pe['offset']:X}, Size {pe['size']} bytes\n")
                        f.write("\n")
                    
                    if any(payload['payload']['network_indicators'].values()):
                        f.write("Network Indicators:\n")
                        if payload['payload']['network_indicators']['domains']:
                            f.write(f"  Domains: {', '.join(payload['payload']['network_indicators']['domains'])}\n")
                        if payload['payload']['network_indicators']['urls']:
                            f.write(f"  URLs: {', '.join(payload['payload']['network_indicators']['urls'])}\n")
                        if payload['payload']['network_indicators']['ips']:
                            f.write(f"  IPs: {', '.join(payload['payload']['network_indicators']['ips'])}\n")
                        f.write("\n")
                    
                    if payload['payload']['decryption_attempts']:
                        f.write(f"Decryption Attempts ({len(payload['payload']['decryption_attempts'])}):\n")
                        for j, attempt in enumerate(payload['payload']['decryption_attempts']):
                            f.write(f"  Attempt #{j+1}:\n")
                            f.write(f"    XOR Key: {attempt['key']}\n")
                            f.write(f"    Output File: {Path(attempt['file']).name}\n")
                            f.write(f"    MD5: {attempt['md5']}\n")
                            f.write(f"    Entropy: {attempt['entropy']:.2f}\n")
                            f.write(f"    Contains PE: {attempt['has_pe']}\n")
                            f.write(f"    Contains Text: {attempt['has_text']}\n\n")
                    
                    f.write("\n")
            else:
                f.write("No payloads found in ODG file\n")
        
        print(f"{ANSI_GREEN}[+] Analysis report saved to: {report_file}{ANSI_RESET}")
        
        return results, str(report_file)
    
    except Exception as e:
        print(f"{ANSI_RED}[!] Error analyzing ODG file: {str(e)}{ANSI_RESET}")
        return None, None

def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Extractor - A tool for extracting APT-41 KEYPLUG malware from ODG files')
    parser.add_argument('file', help='Path to the ODG file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    args = parser.parse_args()
    
    try:
        print(f"{ANSI_BLUE}[*] Analyzing {args.file} for KEYPLUG payloads...{ANSI_RESET}")
        results, report_file = analyze_odg_file(args.file, args.output)
        
        if results and results["payloads"]:
            print(f"{ANSI_GREEN}[+] Analysis complete! Found {len(results['payloads'])} payloads{ANSI_RESET}")
            print(f"{ANSI_GREEN}[+] Report saved to: {report_file}{ANSI_RESET}")
        else:
            print(f"{ANSI_YELLOW}[!] No KEYPLUG payloads found in {args.file}{ANSI_RESET}")
        
    except Exception as e:
        print(f"{ANSI_RED}[!] Error: {str(e)}{ANSI_RESET}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
