#!/usr/bin/env python3
"""
KEYPLUG-ANALYZER: Comprehensive Analysis Tool for KEYPLUG Extracted Payloads
Performs in-depth analysis of potentially malicious content extracted by KEYPLUG tool
Project: QUANTUM SHIELD
Author: John
Version: 1.1
"""

import os
import sys
import re
import json
import math
import binascii
import hashlib
import subprocess
import shutil
import struct
import tempfile
import argparse
import time
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict
import concurrent.futures

# Optional imports with fallbacks
try:
    import matplotlib.pyplot as plt
    import numpy as np
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from capstone import *
    DISASM_AVAILABLE = True
except ImportError:
    DISASM_AVAILABLE = False

# Configure basic logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("keyplug_analyzer.log")
    ]
)
logger = logging.getLogger("keyplug_analyzer")

# ANSI Colors for terminal output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_MAGENTA = "\033[95m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"
# Configuration for analysis
APT41_CONFIG = {
    "markers": [
        b"KEYP", b"RC4", b"http", b"MZ", b"PE\x00\x00",
        b"cmd.exe", b"powershell", b"rundll32", b"regsvr32"
    ],
    "xor_keys": [
        "9e", "d3", "a5", "0a61200d", "410d200d", "4100200d",
        "41414141", "00000000", "ffffffff", "12345678", "87654321",
        "deadbeef"
    ],
    "url_pattern": rb'https?://[^\s"\'>]{4,255}',
    "domain_pattern": rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
    "ip_pattern": rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "cmd_pattern": rb'(?:cmd\.exe|powershell|bash|wget|curl|certutil|bitsadmin|rundll32)',
    "api_pattern": rb'(?:CreateProcess|VirtualAlloc|WriteProcessMemory|ResumeThread|WSASocket|connect|InternetOpen|HttpSendRequest)',
    "pe_header_pattern": rb'MZ[\x00-\xff]{60}PE\x00\x00',
    "config_header_patterns": [
        rb'KEYP[\x00-\xff]{4}',
        rb'CONFIG[\x00-\xff]{4}',
        rb'RC4[\x00-\xff]{4}'
    ],
    "entropy_threshold": 7.0,
    "window_size": 256,
    "max_pe_size": 5 * 1024 * 1024,  # 5 MB maximum PE size to extract
    "interesting_sections": ["UPX", ".text", ".data", ".rdata", ".rsrc", ".reloc"],
    # KEYPLUG directory structure patterns
    "keyplug_dir_patterns": {
        "payload_dirs": ["payload", "payloads", "odg_scan_output"],
        "decrypted_dirs": ["decrypted"],
        "extract_dirs": ["odg_contents"],
        "payload_file_patterns": ["*_payload.bin", "*.bin", "*_forced_*.bin", "*_pattern_*.bin"]
    }
}

class APT41YaraRules:
    """Class for managing APT-41 specific YARA rules."""
    RULES_TEXT = """
rule APT41_KEYPLUG_Payload {
    meta:
        description = "Detects KEYPLUG payload based on known patterns"
        author = "John"
        reference = "Manual analysis of KEYPLUG payloads"
        confidence = "high"
        date = "2025-05-21"
    strings:
        $keyplug = "KEYP" nocase
        $config_marker = { 4B 45 59 50 [1-4] 00 00 }
        $rc4_marker = "RC4"
        $obfuscation = { 66 83 ?? ?? 66 81 ?? ?? }
        $api_hash = { B8 ?? ?? ?? ?? 31 ?? ?? ?? 66 ?? ?? ?? 50 }
        $persistence = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        any of them
}

rule APT41_Config_Block {
    meta:
        description = "Detects potential APT41 config blocks"
        author = "John"
        reference = "Manual analysis of KEYPLUG payloads"
        confidence = "medium"
    strings:
        $cfg1 = { 4B 45 59 50 [0-4] 00 00 }
        $cfg2 = { 43 4F 4E 46 [0-4] 00 00 }
        $url_marker = "http" nocase
        $ip_block = { 25 (64|30|31|32|33|34|35|36|37|38|39) 2E 25 (64|30|31|32|33|34|35|36|37|38|39) }
        
    condition:
        any of ($cfg*) and any of ($url_marker, $ip_block)
}

rule Suspicious_PE_In_Data {
    meta:
        description = "Detects embedded PE files within data blocks"
        author = "John"
        confidence = "medium"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $section1 = ".text"
        $section2 = ".data"
        $section3 = ".rdata"
        $section4 = ".rsrc"
        $injection = { 68 ?? ?? ?? ?? FF 75 ?? FF 55 }
    condition:
        $mz at 0 and $pe and 2 of ($section*) or
        $mz and $pe and $injection
}

rule Shellcode_Patterns {
    meta:
        description = "Detects shellcode patterns common in APT41 payloads"
        author = "John"
        confidence = "medium"
    strings:
        $api_resolve = { 31 C0 64 8B ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? 18 8B ?? 20 }
        $fs_access = { 64 A1 ?? ?? ?? ?? }
        $stack_strings = { C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 }
        $syscall = { B8 ?? ?? ?? ?? CD 80 }
        $find_kernel32 = { 31 ?? 64A1 ?? ?? ?? ?? }
        $jumps = { EB ?? FF 25 ?? ?? ?? ?? E9 }
    condition:
        2 of them
}

rule XOR_Encrypted_PE {
    meta:
        description = "Detects XOR encrypted PE files"
        author = "John"
        confidence = "medium"
    strings:
        // Patterns that might indicate XOR'd MZ header
        $xor_mz_1 = { 1? 1? }
        $xor_mz_2 = { 2? 2? }
        $xor_mz_3 = { 3? 3? }
        $xor_mz_4 = { 4? 4? }
        $xor_mz_5 = { 5? 5? }
        $xor_mz_6 = { 6? 6? }
        // High entropy indicators
        $random_data = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    condition:
        filesize > 1KB and
        ((filesize < 5MB and any of ($xor_mz_*)) or
        (filesize < 10MB and $random_data and uint32(0) != 0x905A4D))
}
"""

    @classmethod
    def create_ruleset(cls):
        """
        Create YARA ruleset from embedded rules.
        Returns:
            yara.Rules: Compiled YARA rules object or None if YARA is not available
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA module not available. Install with: pip install yara-python")
            return None
        try:
            # Create temp file for our embedded rules
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(cls.RULES_TEXT)
                embedded_rules_file = f.name
            # Compile the embedded rules
            compiled_rules = yara.compile(filepath=embedded_rules_file)
            # Clean up the temp file
            try:
                os.unlink(embedded_rules_file)
            except:
                pass
            return compiled_rules
        except Exception as e:
            logger.error(f"Failed to create YARA ruleset: {e}")
            return None
class CryptoAnalyzer:
    """Utility class for analyzing and potentially decrypting encrypted content."""
    @staticmethod
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
            
        # Count byte occurrences
        counter = Counter(data)
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * math.log(probability, base)
        return entropy
    
    @staticmethod
    def entropy_scan(data, window_size=256, step=128):
        """
        Scan data with sliding window to find entropy transitions.
        Args:
            data (bytes): Data to scan
            window_size (int): Size of sliding window
            step (int): Step size between windows
        Returns:
            list: List of (position, entropy) tuples
        """
        results = []
        if len(data) <= window_size:
            return [(0, CryptoAnalyzer.calculate_entropy(data))]
        
        for i in range(0, len(data) - window_size, step):
            window_data = data[i:i+window_size]
            entropy = CryptoAnalyzer.calculate_entropy(window_data)
            results.append((i, entropy))
        return results

    @staticmethod
    def perform_xor_decryption(data, key_hex):
        """
        Perform XOR decryption with a hex key.
        Args:
            data (bytes): Data to decrypt
            key_hex (str): Hexadecimal key (e.g. "0A1B2C3D")
        Returns:
            bytes: Decrypted data
        """
        key_bytes = bytes.fromhex(key_hex)
        result = bytearray(len(data))
        
        for i in range(len(data)):
            result[i] = data[i] ^ key_bytes[i % len(key_bytes)]
            
        return bytes(result)
    
    @staticmethod
    def detect_possible_xor_keys(data, sample_size=256, threshold=0.7):
        """
        Try to detect possible XOR keys that might have been used to encrypt the data.
        Args:
            data (bytes): Encrypted data
            sample_size (int): Size of data sample to analyze
            threshold (float): Threshold for key detection (0.0-1.0)
        Returns:
            list: List of possible XOR keys (hex strings)
        """
        # Only analyze a sample of the data for performance
        if len(data) <= sample_size:
            sample = data
        else:
            # Take samples from beginning and middle of file
            sample1 = data[:sample_size//2]
            midpoint = len(data)//2
            sample2 = data[midpoint:midpoint+sample_size//2]
            sample = sample1 + sample2

        # Common byte values we might expect in clean data
        expected_bytes = [0x00, ord('\n'), ord('\r'), ord(' '), ord('.'), ord(',')]
        
        # ASCII ranges
        lower_ascii = range(ord('a'), ord('z')+1)
        upper_ascii = range(ord('A'), ord('Z')+1)
        digits = range(ord('0'), ord('9')+1)
        
        # Scoring for keys
        key_scores = defaultdict(int)
        
        # Try single-byte keys first (most common in simple malware)
        for key in range(1, 256):
            key_bytes = bytes([key])
            decrypted = bytes(b ^ key for b in sample)
            
            # Calculate score based on resulting decrypted data
            text_score = 0
            control_chars = 0
            null_bytes = 0
            ascii_chars = 0
            
            for b in decrypted:
                if b in expected_bytes:
                    text_score += 1
                elif b in range(1, 32):  # Control characters
                    control_chars += 1
                elif b == 0:
                    null_bytes += 1
                elif b in lower_ascii or b in upper_ascii or b in digits:
                    ascii_chars += 1
            
            # Normalized score
            normalized_score = (text_score * 2 + ascii_chars) / len(sample)
            penalty = (control_chars - null_bytes) / len(sample)
            final_score = normalized_score - penalty
            
            if final_score > threshold:
                key_scores[key_bytes.hex()] = final_score
        
        # Get top keys by score
        sorted_keys = sorted(key_scores.items(), key=lambda x: x[1], reverse=True)
        return [k for k, score in sorted_keys[:5]]  # Return top 5

    @staticmethod
    def detect_embedded_pe(data, max_pes=5, min_pe_size=256):
        """
        Detect embedded PE files within binary data.
        Args:
            data (bytes): Binary data to scan
            max_pes (int): Maximum number of PE files to extract
            min_pe_size (int): Minimum size of valid PE file
        Returns:
            list: List of tuples (offset, size, pe_data)
        """
        results = []
        
        # Find all "MZ" occurrences
        mz_positions = [m.start() for m in re.finditer(b'MZ', data)]
        
        for pos in mz_positions:
            # Skip if too close to end of file to be a valid PE
            if pos + 0x40 >= len(data):
                continue
                
            try:
                # Check if a valid PE header follows the MZ header
                pe_offset_pos = pos + 0x3C
                if pe_offset_pos + 4 > len(data):
                    continue
                    
                pe_offset = struct.unpack("<I", data[pe_offset_pos:pe_offset_pos+4])[0]
                pe_header_pos = pos + pe_offset
                
                if pe_header_pos + 4 > len(data):
                    continue
                    
                pe_header = data[pe_header_pos:pe_header_pos+4]
                
                if pe_header == b'PE\x00\x00':
                    # Found valid PE header
                    # Try to determine size of PE
                    section_count_pos = pe_header_pos + 6
                    if section_count_pos + 2 > len(data):
                        continue
                        
                    section_count = struct.unpack("<H", data[section_count_pos:section_count_pos+2])[0]
                    pe_size = APT41_CONFIG["max_pe_size"]  # Default max size
                    
                    # Extract to separate file
                    pe_data = data[pos:pos+pe_size]
                    
                    # Only add if PE is large enough to be valid
                    if len(pe_data) >= min_pe_size:
                        results.append((pos, len(pe_data), pe_data))
                        
                        # Limit number of PEs to extract
                        if len(results) >= max_pes:
                            break
            except:
                # Skip invalid headers
                continue
                
        return results
class NetworkAnalyzer:
    """Utility class for extracting and analyzing network indicators."""
    
    @staticmethod
    def extract_network_indicators(data):
        """
        Extract network indicators from binary data.
        Args:
            data (bytes): Binary data to scan
        Returns:
            dict: Dictionary of network indicators by type
        """
        results = {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": []
        }
        
        # Extract URLs
        for match in re.finditer(APT41_CONFIG["url_pattern"], data):
            url = match.group(0).decode('latin1', errors='replace')
            if url not in results["urls"]:
                results["urls"].append(url)
        
        # Extract domains
        for match in re.finditer(APT41_CONFIG["domain_pattern"], data):
            domain = match.group(0).decode('latin1', errors='replace')
            if domain not in results["domains"] and not any(domain in url for url in results["urls"]):
                results["domains"].append(domain)
        
        # Extract IPs
        for match in re.finditer(APT41_CONFIG["ip_pattern"], data):
            ip = match.group(0).decode('latin1', errors='replace')
            if ip not in results["ips"]:
                results["ips"].append(ip)
        
        # Look for potential email addresses
        email_pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for match in re.finditer(email_pattern, data):
            email = match.group(0).decode('latin1', errors='replace')
            if email not in results["emails"]:
                results["emails"].append(email)
                
        return results
    
    @staticmethod
    def analyze_domains(domains):
        """
        Analyze extracted domains for patterns and signs of maliciousness.
        Args:
            domains (list): List of extracted domains
        Returns:
            dict: Analysis results
        """
        results = {
            "dga_likely": [],
            "suspicious_tlds": [],
            "high_entropy": []
        }
        
        for domain in domains:
            # Check for DGA-like patterns (high entropy, unusual character distribution)
            domain_name = domain.split('.')[0]
            entropy = CryptoAnalyzer.calculate_entropy(domain_name.encode())
            
            if entropy > 4.0:  # High entropy often indicates DGA
                results["high_entropy"].append(domain)
            
            # Check for suspicious TLDs
            suspicious_tlds = [".xyz", ".top", ".club", ".info", ".biz", ".cc", ".tk"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                results["suspicious_tlds"].append(domain)
            
            # Check for random-looking patterns
            consonant_sequences = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain_name, re.IGNORECASE)
            if consonant_sequences:
                results["dga_likely"].append(domain)
        
        return results
class PEAnalyzer:
    """Utility class for analyzing PE files."""
    
    @staticmethod
    def extract_pe_info(pe_data):
        """
        Extract basic information from a PE file.
        Args:
            pe_data (bytes): PE file data
        Returns:
            dict: PE file information
        """
        try:
            if not pe_data or len(pe_data) < 64:
                return {"error": "Invalid PE data"}
                
            result = {
                "headers": {},
                "sections": [],
                "imports": [],
                "exports": [],
                "resources": [],
                "compilation_time": None,
                "entropy": CryptoAnalyzer.calculate_entropy(pe_data),
                "suspicious_indicators": []
            }
            
            # Try to extract PE header information
            if pe_data[:2] != b'MZ':
                return {"error": "Not a valid PE file (missing MZ signature)"}
            
            # Get PE header offset
            pe_offset = struct.unpack("<I", pe_data[0x3C:0x40])[0]
            if pe_offset + 24 > len(pe_data) or pe_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {"error": "Invalid PE header"}
                
            # Get machine type
            machine_type = struct.unpack("<H", pe_data[pe_offset+4:pe_offset+6])[0]
            result["headers"]["machine_type"] = machine_type
            
            # Get number of sections
            num_sections = struct.unpack("<H", pe_data[pe_offset+6:pe_offset+8])[0]
            result["headers"]["num_sections"] = num_sections
            
            # Get timestamp
            timestamp = struct.unpack("<I", pe_data[pe_offset+8:pe_offset+12])[0]
            result["compilation_time"] = timestamp
            
            # Extract basic headers info
            optional_header_size = struct.unpack("<H", pe_data[pe_offset+20:pe_offset+22])[0]
            result["headers"]["characteristics"] = struct.unpack("<H", pe_data[pe_offset+22:pe_offset+24])[0]
            
            # Check for suspicious indicators
            if result["entropy"] > 7.0:
                result["suspicious_indicators"].append("High file entropy")
            
            if num_sections > 8:
                result["suspicious_indicators"].append(f"Unusually high section count ({num_sections})")
            
            # Super basic section info
            section_table_offset = pe_offset + 24 + optional_header_size
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(pe_data):
                    break
                
                section_name = pe_data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
                section_vsize = struct.unpack("<I", pe_data[section_offset+8:section_offset+12])[0]
                section_vaddr = struct.unpack("<I", pe_data[section_offset+12:section_offset+16])[0]
                section_rsize = struct.unpack("<I", pe_data[section_offset+16:section_offset+20])[0]
                section_raddr = struct.unpack("<I", pe_data[section_offset+20:section_offset+24])[0]
                
                result["sections"].append({
                    "name": section_name,
                    "virtual_size": section_vsize,
                    "virtual_addr": section_vaddr,
                    "raw_size": section_rsize,
                    "raw_addr": section_raddr
                })
                
                # Check for suspicious section names
                if section_name not in [".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata"]:
                    result["suspicious_indicators"].append(f"Unusual section name: {section_name}")
                
                # Check for execute+write sections
                section_chars = struct.unpack("<I", pe_data[section_offset+36:section_offset+40])[0]
                if section_chars & 0x20000000 and section_chars & 0x80000000:
                    result["suspicious_indicators"].append(f"Section {section_name} is both executable and writeable")
            
            return result
        except Exception as e:
            return {"error": f"PE analysis failed: {str(e)}"}
    
    @staticmethod
    def extract_strings_from_pe(pe_data, min_length=6):
        """
        Extract strings from PE file sections with section context.
        Args:
            pe_data (bytes): PE file data
            min_length (int): Minimum string length
        Returns:
            dict: Strings by section
        """
        result = {
            "headers": [],
            "sections": {}
        }
        
        try:
            # Check for valid PE
            if not pe_data or len(pe_data) < 64 or pe_data[:2] != b'MZ':
                return {"error": "Invalid PE data"}
            
            # Get PE header offset
            pe_offset = struct.unpack("<I", pe_data[0x3C:0x40])[0]
            if pe_offset + 24 > len(pe_data) or pe_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {"error": "Invalid PE header"}
            
            # Extract strings from PE headers
            current_str = ""
            for byte in pe_data[:pe_offset+24]:
                if 32 <= byte <= 126:  # ASCII printable range
                    current_str += chr(byte)
                else:
                    if len(current_str) >= min_length:
                        result["headers"].append(current_str)
                    current_str = ""
                    
            # Get number of sections and section table info
            num_sections = struct.unpack("<H", pe_data[pe_offset+6:pe_offset+8])[0]
            optional_header_size = struct.unpack("<H", pe_data[pe_offset+20:pe_offset+22])[0]
            section_table_offset = pe_offset + 24 + optional_header_size
            
            # Extract strings from each section
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(pe_data):
                    break
                
                section_name = pe_data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
                section_rsize = struct.unpack("<I", pe_data[section_offset+16:section_offset+20])[0]
                section_raddr = struct.unpack("<I", pe_data[section_offset+20:section_offset+24])[0]
                
                # Skip sections with no raw data
                if section_rsize == 0 or section_raddr + section_rsize > len(pe_data):
                    continue
                
                # Extract strings from this section
                section_data = pe_data[section_raddr:section_raddr+section_rsize]
                section_strings = []
                
                current_str = ""
                for byte in section_data:
                    if 32 <= byte <= 126:
                        current_str += chr(byte)
                    else:
                        if len(current_str) >= min_length:
                            section_strings.append(current_str)
                        current_str = ""
                
                if section_strings:
                    result["sections"][section_name] = section_strings
            
            return result
        except Exception as e:
            return {"error": f"String extraction failed: {str(e)}"}
class PEAnalyzer:
    """Utility class for analyzing PE files."""
    
    @staticmethod
    def extract_pe_info(pe_data):
        """
        Extract basic information from a PE file.
        Args:
            pe_data (bytes): PE file data
        Returns:
            dict: PE file information
        """
        try:
            if not pe_data or len(pe_data) < 64:
                return {"error": "Invalid PE data"}
                
            result = {
                "headers": {},
                "sections": [],
                "imports": [],
                "exports": [],
                "resources": [],
                "compilation_time": None,
                "entropy": CryptoAnalyzer.calculate_entropy(pe_data),
                "suspicious_indicators": []
            }
            
            # Try to extract PE header information
            if pe_data[:2] != b'MZ':
                return {"error": "Not a valid PE file (missing MZ signature)"}
            
            # Get PE header offset
            pe_offset = struct.unpack("<I", pe_data[0x3C:0x40])[0]
            if pe_offset + 24 > len(pe_data) or pe_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {"error": "Invalid PE header"}
                
            # Get machine type
            machine_type = struct.unpack("<H", pe_data[pe_offset+4:pe_offset+6])[0]
            result["headers"]["machine_type"] = machine_type
            
            # Get number of sections
            num_sections = struct.unpack("<H", pe_data[pe_offset+6:pe_offset+8])[0]
            result["headers"]["num_sections"] = num_sections
            
            # Get timestamp
            timestamp = struct.unpack("<I", pe_data[pe_offset+8:pe_offset+12])[0]
            result["compilation_time"] = timestamp
            
            # Extract basic headers info
            optional_header_size = struct.unpack("<H", pe_data[pe_offset+20:pe_offset+22])[0]
            result["headers"]["characteristics"] = struct.unpack("<H", pe_data[pe_offset+22:pe_offset+24])[0]
            
            # Check for suspicious indicators
            if result["entropy"] > 7.0:
                result["suspicious_indicators"].append("High file entropy")
            
            if num_sections > 8:
                result["suspicious_indicators"].append(f"Unusually high section count ({num_sections})")
            
            # Super basic section info
            section_table_offset = pe_offset + 24 + optional_header_size
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(pe_data):
                    break
                
                section_name = pe_data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
                section_vsize = struct.unpack("<I", pe_data[section_offset+8:section_offset+12])[0]
                section_vaddr = struct.unpack("<I", pe_data[section_offset+12:section_offset+16])[0]
                section_rsize = struct.unpack("<I", pe_data[section_offset+16:section_offset+20])[0]
                section_raddr = struct.unpack("<I", pe_data[section_offset+20:section_offset+24])[0]
                
                result["sections"].append({
                    "name": section_name,
                    "virtual_size": section_vsize,
                    "virtual_addr": section_vaddr,
                    "raw_size": section_rsize,
                    "raw_addr": section_raddr
                })
                
                # Check for suspicious section names
                if section_name not in [".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata"]:
                    result["suspicious_indicators"].append(f"Unusual section name: {section_name}")
                
                # Check for execute+write sections
                section_chars = struct.unpack("<I", pe_data[section_offset+36:section_offset+40])[0]
                if section_chars & 0x20000000 and section_chars & 0x80000000:
                    result["suspicious_indicators"].append(f"Section {section_name} is both executable and writeable")
            
            return result
        except Exception as e:
            return {"error": f"PE analysis failed: {str(e)}"}
    
    @staticmethod
    def extract_strings_from_pe(pe_data, min_length=6):
        """
        Extract strings from PE file sections with section context.
        Args:
            pe_data (bytes): PE file data
            min_length (int): Minimum string length
        Returns:
            dict: Strings by section
        """
        result = {
            "headers": [],
            "sections": {}
        }
        
        try:
            # Check for valid PE
            if not pe_data or len(pe_data) < 64 or pe_data[:2] != b'MZ':
                return {"error": "Invalid PE data"}
            
            # Get PE header offset
            pe_offset = struct.unpack("<I", pe_data[0x3C:0x40])[0]
            if pe_offset + 24 > len(pe_data) or pe_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {"error": "Invalid PE header"}
            
            # Extract strings from PE headers
            current_str = ""
            for byte in pe_data[:pe_offset+24]:
                if 32 <= byte <= 126:  # ASCII printable range
                    current_str += chr(byte)
                else:
                    if len(current_str) >= min_length:
                        result["headers"].append(current_str)
                    current_str = ""
                    
            # Get number of sections and section table info
            num_sections = struct.unpack("<H", pe_data[pe_offset+6:pe_offset+8])[0]
            optional_header_size = struct.unpack("<H", pe_data[pe_offset+20:pe_offset+22])[0]
            section_table_offset = pe_offset + 24 + optional_header_size
            
            # Extract strings from each section
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(pe_data):
                    break
                
                section_name = pe_data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
                section_rsize = struct.unpack("<I", pe_data[section_offset+16:section_offset+20])[0]
                section_raddr = struct.unpack("<I", pe_data[section_offset+20:section_offset+24])[0]
                
                # Skip sections with no raw data
                if section_rsize == 0 or section_raddr + section_rsize > len(pe_data):
                    continue
                
                # Extract strings from this section
                section_data = pe_data[section_raddr:section_raddr+section_rsize]
                section_strings = []
                
                current_str = ""
                for byte in section_data:
                    if 32 <= byte <= 126:
                        current_str += chr(byte)
                    else:
                        if len(current_str) >= min_length:
                            section_strings.append(current_str)
                        current_str = ""
                
                if section_strings:
                    result["sections"][section_name] = section_strings
            
            return result
        except Exception as e:
            return {"error": f"String extraction failed: {str(e)}"}
class DisassemblyAnalyzer:
    """Utility class for analyzing disassembled code."""
    
    @staticmethod
    def find_api_patterns(data, start_offset=0):
        """
        Look for API call patterns in binary data.
        Args:
            data (bytes): Binary data
            start_offset (int): Starting offset for analysis
        Returns:
            list: Found API call patterns
        """
        if not DISASM_AVAILABLE:
            return {"error": "Capstone disassembly engine not available"}
        
        try:
            results = []
            
            # Initialize disassembler for x86/x64
            md32 = Cs(CS_ARCH_X86, CS_MODE_32)
            md64 = Cs(CS_ARCH_X86, CS_MODE_64)
            
            # Check for both 32-bit and 64-bit code patterns
            for mode, md in [("x86", md32), ("x64", md64)]:
                # Disassemble a chunk of code
                for chunk_start in range(start_offset, len(data) - 1024, 512):
                    chunk = data[chunk_start:chunk_start + 1024]
                    
                    try:
                        last_insns = []
                        api_pattern = []
                        
                        for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(chunk, chunk_start)):
                            insn = f"{mnemonic} {op_str}".strip()
                            
                            # Keep track of last 5 instructions for context
                            last_insns.append((address, insn))
                            if len(last_insns) > 5:
                                last_insns.pop(0)
                            
                            # Look for API calls
                            call_patterns = ["call", "jmp"]
                            if any(mnemonic.startswith(p) for p in call_patterns):
                                # Check for various API calling patterns
                                if "ptr" in op_str:
                                    api_pattern = list(last_insns)
                                    api_pattern.append((address, insn))
                                    results.append({
                                        "offset": chunk_start,
                                        "arch": mode,
                                        "pattern": api_pattern,
                                        "context": last_insns
                                    })
                            
                            # Look for syscall/sysenter
                            if mnemonic in ["syscall", "sysenter"]:
                                results.append({
                                    "offset": address,
                                    "arch": mode,
                                    "pattern": "system_call",
                                    "context": last_insns
                                })
                    except Exception as e:
                        # Skip errors in disassembly
                        continue
            
            return results
        except Exception as e:
            return {"error": f"Disassembly analysis failed: {str(e)}"}


class ConfigExtractor:
    """Utility class for extracting embedded configuration data."""
    
    @staticmethod
    def find_config_patterns(data):
        """
        Search for potential APT41 config blocks.
        Args:
            data (bytes): Binary data to search
        Returns:
            list: Potential config blocks with metadata
        """
        results = []
        
        # Search for config header patterns
        for pattern in APT41_CONFIG["config_header_patterns"]:
            for match in re.finditer(pattern, data):
                start_pos = match.start()
                pattern_bytes = match.group(0)
                
                # Determine a reasonable size for config (up to 1KB after header)
                max_config_size = 1024
                end_pos = min(start_pos + max_config_size, len(data))
                
                config_data = data[start_pos:end_pos]
                
                # Check for C2 URLs, IPs, or other indicators within this block
                network_indicators = NetworkAnalyzer.extract_network_indicators(config_data)
                
                # Only include if there are network indicators (likely a real config)
                if any(network_indicators.values()):
                    results.append({
                        "offset": start_pos,
                        "size": len(config_data),
                        "header": pattern_bytes.hex(),
                        "data": config_data.hex(),
                        "indicators": network_indicators
                    })
        
        return results
    
    @staticmethod
    def decode_potential_configs(data, default_xor_keys=None):
        """
        Try to decode potential config blocks using common encryption schemes.
        Args:
            data (bytes): Binary data containing potential configs
            default_xor_keys (list): List of hex XOR keys to try
        Returns:
            list: Decoded config data with metadata
        """
        results = []
        
        # Default XOR keys to try
        if default_xor_keys is None:
            default_xor_keys = APT41_CONFIG["xor_keys"]
        
        # First identify potential config blocks
        potential_configs = ConfigExtractor.find_config_patterns(data)
        
        # For each potential config block
        for config in potential_configs:
            config_data = bytes.fromhex(config["data"])
            decoded_configs = []
            
            # Try decoding with XOR keys
            for key_hex in default_xor_keys:
                try:
                    decoded = CryptoAnalyzer.perform_xor_decryption(config_data, key_hex)
                    
                    # Check if decoding produced meaningful data
                    network_indicators = NetworkAnalyzer.extract_network_indicators(decoded)
                    
                    if any(len(indics) > 0 for indics in network_indicators.values()):
                        decoded_configs.append({
                            "key": key_hex,
                            "method": "xor",
                            "decoded": decoded.hex(),
                            "indicators": network_indicators
                        })
                except:
                    continue
            
            # Add decoding results to the config
            if decoded_configs:
                config["decoded"] = decoded_configs
                results.append(config)
        
        return results
class DisassemblyAnalyzer:
    """Utility class for analyzing disassembled code."""
    
    @staticmethod
    def find_api_patterns(data, start_offset=0):
        """
        Look for API call patterns in binary data.
        Args:
            data (bytes): Binary data
            start_offset (int): Starting offset for analysis
        Returns:
            list: Found API call patterns
        """
        if not DISASM_AVAILABLE:
            return {"error": "Capstone disassembly engine not available"}
        
        try:
            results = []
            
            # Initialize disassembler for x86/x64
            md32 = Cs(CS_ARCH_X86, CS_MODE_32)
            md64 = Cs(CS_ARCH_X86, CS_MODE_64)
            
            # Check for both 32-bit and 64-bit code patterns
            for mode, md in [("x86", md32), ("x64", md64)]:
                # Disassemble a chunk of code
                for chunk_start in range(start_offset, len(data) - 1024, 512):
                    chunk = data[chunk_start:chunk_start + 1024]
                    
                    try:
                        last_insns = []
                        api_pattern = []
                        
                        for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(chunk, chunk_start)):
                            insn = f"{mnemonic} {op_str}".strip()
                            
                            # Keep track of last 5 instructions for context
                            last_insns.append((address, insn))
                            if len(last_insns) > 5:
                                last_insns.pop(0)
                            
                            # Look for API calls
                            call_patterns = ["call", "jmp"]
                            if any(mnemonic.startswith(p) for p in call_patterns):
                                # Check for various API calling patterns
                                if "ptr" in op_str:
                                    api_pattern = list(last_insns)
                                    api_pattern.append((address, insn))
                                    results.append({
                                        "offset": chunk_start,
                                        "arch": mode,
                                        "pattern": api_pattern,
                                        "context": last_insns
                                    })
                            
                            # Look for syscall/sysenter
                            if mnemonic in ["syscall", "sysenter"]:
                                results.append({
                                    "offset": address,
                                    "arch": mode,
                                    "pattern": "system_call",
                                    "context": last_insns
                                })
                    except Exception as e:
                        # Skip errors in disassembly
                        continue
            
            return results
        except Exception as e:
            return {"error": f"Disassembly analysis failed: {str(e)}"}


class ConfigExtractor:
    """Utility class for extracting embedded configuration data."""
    
    @staticmethod
    def find_config_patterns(data):
        """
        Search for potential APT41 config blocks.
        Args:
            data (bytes): Binary data to search
        Returns:
            list: Potential config blocks with metadata
        """
        results = []
        
        # Search for config header patterns
        for pattern in APT41_CONFIG["config_header_patterns"]:
            for match in re.finditer(pattern, data):
                start_pos = match.start()
                pattern_bytes = match.group(0)
                
                # Determine a reasonable size for config (up to 1KB after header)
                max_config_size = 1024
                end_pos = min(start_pos + max_config_size, len(data))
                
                config_data = data[start_pos:end_pos]
                
                # Check for C2 URLs, IPs, or other indicators within this block
                network_indicators = NetworkAnalyzer.extract_network_indicators(config_data)
                
                # Only include if there are network indicators (likely a real config)
                if any(network_indicators.values()):
                    results.append({
                        "offset": start_pos,
                        "size": len(config_data),
                        "header": pattern_bytes.hex(),
                        "data": config_data.hex(),
                        "indicators": network_indicators
                    })
        
        return results
    
    @staticmethod
    def decode_potential_configs(data, default_xor_keys=None):
        """
        Try to decode potential config blocks using common encryption schemes.
        Args:
            data (bytes): Binary data containing potential configs
            default_xor_keys (list): List of hex XOR keys to try
        Returns:
            list: Decoded config data with metadata
        """
        results = []
        
        # Default XOR keys to try
        if default_xor_keys is None:
            default_xor_keys = APT41_CONFIG["xor_keys"]
        
        # First identify potential config blocks
        potential_configs = ConfigExtractor.find_config_patterns(data)
        
        # For each potential config block
        for config in potential_configs:
            config_data = bytes.fromhex(config["data"])
            decoded_configs = []
            
            # Try decoding with XOR keys
            for key_hex in default_xor_keys:
                try:
                    decoded = CryptoAnalyzer.perform_xor_decryption(config_data, key_hex)
                    
                    # Check if decoding produced meaningful data
                    network_indicators = NetworkAnalyzer.extract_network_indicators(decoded)
                    
                    if any(len(indics) > 0 for indics in network_indicators.values()):
                        decoded_configs.append({
                            "key": key_hex,
                            "method": "xor",
                            "decoded": decoded.hex(),
                            "indicators": network_indicators
                        })
                except:
                    continue
            
            # Add decoding results to the config
            if decoded_configs:
                config["decoded"] = decoded_configs
                results.append(config)
        
        return results
class PayloadAnalyzer:
    """Main class for analyzing KEYPLUG payloads."""
    
    def __init__(self, output_dir="keyplug_analysis", report_dir="keyplug_reports", yara_rules=None):
        """
        Initialize the payload analyzer.
        Args:
            output_dir (str): Directory to save analysis artifacts
            report_dir (str): Directory to save reports
            yara_rules (yara.Rules): YARA rules for scanning
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Load YARA rules if available
        self.yara_rules = yara_rules or (APT41YaraRules.create_ruleset() if YARA_AVAILABLE else None)
        
        # Initialize processed files cache
        self.processed_files_cache = set()
        self._load_processed_files_cache()
        
    def _load_processed_files_cache(self):
        """Load MD5 hashes of already processed files from cache file."""
        cache_file = self.report_dir / "processed_files.txt"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                for line in f:
                    self.processed_files_cache.add(line.strip())
    
    def _save_processed_files_cache(self):
        """Save MD5 hashes of processed files to cache file."""
        cache_file = self.report_dir / "processed_files.txt"
        with open(cache_file, 'w') as f:
            for file_hash in self.processed_files_cache:
                f.write(f"{file_hash}\n")
                
    def find_keyplug_payloads(self, base_dir):
        """
        Find all KEYPLUG extracted payloads from a base directory.
        Args:
            base_dir (str): Base directory to search in
        Returns:
            list: List of potential payload files
        """
        base_dir = Path(base_dir)
        payload_files = []
        
        if not base_dir.exists() or not base_dir.is_dir():
            logger.warning(f"Base directory not found: {base_dir}")
            return []
            
        # First search for possible KEYPLUG output directories
        potential_payload_dirs = []
        
        # Check current directory
        for pattern in APT41_CONFIG["keyplug_dir_patterns"]["payload_dirs"]:
            if (base_dir / pattern).exists() and (base_dir / pattern).is_dir():
                potential_payload_dirs.append(base_dir / pattern)
                
        # Check subdirectories (in case it's the parent folder of multiple scans)
        for subdir in base_dir.iterdir():
            if not subdir.is_dir():
                continue
                
            # Check if this subdir or any of its subdirs might be a KEYPLUG output dir
            for pattern in APT41_CONFIG["keyplug_dir_patterns"]["payload_dirs"]:
                if (subdir / pattern).exists() and (subdir / pattern).is_dir():
                    potential_payload_dirs.append(subdir / pattern)
                    
            # Also check for the pattern in the directory name itself
            for pattern in APT41_CONFIG["keyplug_dir_patterns"]["payload_dirs"]:
                if pattern.lower() in subdir.name.lower():
                    potential_payload_dirs.append(subdir)
                    
        # Now look in all potential dirs for files matching payload patterns
        for payload_dir in potential_payload_dirs:
            for pattern in APT41_CONFIG["keyplug_dir_patterns"]["payload_file_patterns"]:
                payload_files.extend(payload_dir.glob(pattern))
                
        # Look in decrypted directories too
        for payload_dir in potential_payload_dirs:
            parent_dir = payload_dir.parent
            
            for decrypted_pattern in APT41_CONFIG["keyplug_dir_patterns"]["decrypted_dirs"]:
                decrypted_dir = parent_dir / decrypted_pattern
                if decrypted_dir.exists() and decrypted_dir.is_dir():
                    for file_pattern in APT41_CONFIG["keyplug_dir_patterns"]["payload_file_patterns"]:
                        payload_files.extend(decrypted_dir.glob(file_pattern))
                        
        # Remove duplicates and sort
        unique_payloads = list(set(payload_files))
        unique_payloads.sort()
        
        logger.info(f"Found {len(unique_payloads)} potential KEYPLUG payload files")
        return unique_payloads
    def analyze_file(self, file_path, force=False):
        """
        Perform comprehensive analysis on a file.
        Args:
            file_path (str): Path to the file to analyze
            force (bool): Force analysis even if file was previously analyzed
        Returns:
            dict: Analysis results
        """
        file_path = Path(file_path)
        
        # Check if file exists
        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}
        
        # Calculate file MD5 hash
        try:
            with open(file_path, 'rb') as f:
                file_md5 = hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}
            
        # Check if already processed (unless force=True)
        if not force and file_md5 in self.processed_files_cache:
            logger.info(f"Skipping already analyzed file: {file_path} (MD5: {file_md5})")
            return {"status": "skipped", "reason": "already_analyzed", "md5": file_md5, "file": str(file_path)}
        
        logger.info(f"Analyzing file: {file_path}")
        
        # Init results
        results = {
            "timestamp": datetime.now().isoformat(),
            "file": {
                "name": file_path.name,
                "path": str(file_path),
                "size": file_path.stat().size,
            },
            "basic_analysis": {},
            "network_indicators": {},
            "detected_pe": [],
            "yara_matches": [],
            "entropy_analysis": {},
            "decryptions": [],
            "config": {},
            "executive_summary": [],
            "conclusion": {}
        }
        
        try:
            # Calculate file hashes
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Hash calculation
            results["file"]["md5"] = hashlib.md5(data).hexdigest()
            results["file"]["sha1"] = hashlib.sha1(data).hexdigest()
            results["file"]["sha256"] = hashlib.sha256(data).hexdigest()
            
            # Get file type if magic is available
            if MAGIC_AVAILABLE:
                mime = magic.Magic(mime=True)
                results["file"]["mime_type"] = mime.from_file(str(file_path))
                
                mime_desc = magic.Magic()
                results["file"]["file_type"] = mime_desc.from_file(str(file_path))
            else:
                # Fallback: Simple file type detection
                if data.startswith(b'MZ'):
                    results["file"]["file_type"] = "PE executable"
                elif data.startswith(b'\x7FELF'):
                    results["file"]["file_type"] = "ELF executable"
                elif data.startswith(b'PK\x03\x04'):
                    results["file"]["file_type"] = "Zip archive"
                else:
                    results["file"]["file_type"] = "Unknown binary data"
            
            # Basic analysis
            results["basic_analysis"]["entropy"] = CryptoAnalyzer.calculate_entropy(data)
            results["basic_analysis"]["is_encrypted"] = results["basic_analysis"]["entropy"] > APT41_CONFIG["entropy_threshold"]
            
            # Entropy scan for interesting sections
            entropy_segments = CryptoAnalyzer.entropy_scan(data, APT41_CONFIG["window_size"])
            results["entropy_analysis"]["segments"] = [(offset, round(entropy, 2)) for offset, entropy in entropy_segments]
            
            # Find high entropy segments (potential encrypted/compressed data)
            high_entropy_segments = [(offset, entropy) for offset, entropy in entropy_segments if entropy > APT41_CONFIG["entropy_threshold"]]
            results["entropy_analysis"]["high_entropy_segments"] = [(offset, round(entropy, 2)) for offset, entropy in high_entropy_segments]
                        # Find entropy transitions (potential encrypted/plaintext boundaries)
            transitions = []
            if len(entropy_segments) > 1:
                for i in range(1, len(entropy_segments)):
                    prev_entropy = entropy_segments[i-1][1]
                    curr_entropy = entropy_segments[i][1]
                    entropy_delta = abs(curr_entropy - prev_entropy)
                    if entropy_delta > 1.5:  # Significant entropy change
                        transitions.append({
                            "offset": entropy_segments[i][0],
                            "from_entropy": round(prev_entropy, 2),
                            "to_entropy": round(curr_entropy, 2),
                            "delta": round(entropy_delta, 2)
                        })
            results["entropy_analysis"]["transitions"] = transitions
            
            # Network indicators analysis
            results["network_indicators"] = NetworkAnalyzer.extract_network_indicators(data)
            
            if results["network_indicators"]["domains"]:
                results["network_indicators"]["domain_analysis"] = NetworkAnalyzer.analyze_domains(
                    results["network_indicators"]["domains"]
                )
            
            # Try to identify PE files embedded in the data
            embedded_pes = CryptoAnalyzer.detect_embedded_pe(data)
            
            # Save and analyze embedded PEs
            for i, (offset, size, pe_data) in enumerate(embedded_pes):
                # Hash the PE for identification
                pe_hash = hashlib.md5(pe_data).hexdigest()
                pe_filename = f"embedded_pe_{i+1}_{pe_hash[:8]}.bin"
                pe_path = self.output_dir / pe_filename
                
                # Save the PE file
                with open(pe_path, 'wb') as f:
                    f.write(pe_data)
                
                # Analyze the PE
                pe_info = PEAnalyzer.extract_pe_info(pe_data)
                pe_strings = PEAnalyzer.extract_strings_from_pe(pe_data)
                
                # Add to results
                results["detected_pe"].append({
                    "offset": offset,
                    "size": size,
                    "md5": pe_hash,
                    "file": str(pe_path),
                    "info": pe_info,
                    "strings": pe_strings
                })
            
            # YARA scanning (if available)
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(data=data)
                    for match in matches:
                        match_data = {
                            "rule": match.rule,
                            "meta": match.meta,
                            "tags": match.tags,
                            "strings": []
                        }
                        
                        # Include matched strings with context
                        if hasattr(match, 'strings'):
                            for string_id, offset, string_bytes in match.strings:
                                # Get a bit of context around each match
                                context_start = max(0, offset - 16)
                                context_end = min(len(data), offset + len(string_bytes) + 16)
                                context_bytes = data[context_start:context_end]
                                
                                match_data["strings"].append({
                                    "id": string_id,
                                    "offset": offset,
                                    "bytes": string_bytes.hex(),
                                    "bytes_ascii": string_bytes.decode('latin1', errors='replace'),
                                    "context": context_bytes.hex(),
                                    "context_ascii": context_bytes.decode('latin1', errors='replace')
                                })
                        
                        results["yara_matches"].append(match_data)
                except Exception as e:
                    results["yara_matches"] = [{"error": f"YARA scanning error: {str(e)}"}]
                    # Try XOR decryption with different keys
            logger.info("Attempting XOR decryption with different keys")
            
            # First try to automatically detect possible XOR keys
            detected_keys = CryptoAnalyzer.detect_possible_xor_keys(data)
            results["detected_xor_keys"] = detected_keys
            
            # Try both detected keys and default keys from APT41_CONFIG
            all_keys = detected_keys + APT41_CONFIG["xor_keys"]
            
            # Try decryption with different keys
            successful_decryptions = []
            
            for key_hex in all_keys:
                try:
                    # Only try each key once
                    if key_hex in [d["key"] for d in successful_decryptions]:
                        continue
                    
                    decrypted = CryptoAnalyzer.perform_xor_decryption(data, key_hex)
                    
                    # Check if decryption produced meaningful data
                    decryption_score = 0
                    decryption_reasons = []
                    
                    # Look for PE headers in decrypted data
                    if decrypted.startswith(b'MZ'):
                        decryption_score += 10
                        decryption_reasons.append("Found decrypted PE header")
                    
                    # Look for common text patterns
                    text_patterns = [b"http:", b"www.", b"<?xml", b"</html>", b"#include", b"Command", b"windows", b"kernel32"]
                    for pattern in text_patterns:
                        if pattern in decrypted:
                            decryption_score += 5
                            decryption_reasons.append(f"Found text pattern: {pattern.decode('ascii', errors='replace')}")
                    
                    # Look for PE headers anywhere in the decrypted data
                    if b'MZ' in decrypted and b'PE\x00\x00' in decrypted:
                        pe_index = decrypted.find(b'MZ')
                        decryption_score += 10
                        decryption_reasons.append(f"Found embedded PE at offset {pe_index}")
                    
                    # Check entropy - should become either lower (plaintext) or higher (compressed)
                    decrypted_entropy = CryptoAnalyzer.calculate_entropy(decrypted)
                    entropy_delta = abs(decrypted_entropy - results["basic_analysis"]["entropy"])
                    if entropy_delta > 0.5:
                        decryption_score += 3
                        decryption_reasons.append(f"Significant entropy change: {entropy_delta:.2f}")
                    
                    # Network indicators in decrypted data
                    network_indicators = NetworkAnalyzer.extract_network_indicators(decrypted)
                    if any(indicators for indicators in network_indicators.values()):
                        decryption_score += 10
                        indicator_count = sum(len(indicators) for indicators in network_indicators.values())
                        decryption_reasons.append(f"Found {indicator_count} network indicators")
                    
                    # Save promising decryptions
                    if decryption_score > 5:
                        # Generate a unique filename
                        decrypted_hash = hashlib.md5(decrypted).hexdigest()[:8]
                        decrypted_filename = f"decrypted_{file_path.stem}_{key_hex}_{decrypted_hash}.bin"
                        decrypted_path = self.output_dir / decrypted_filename
                        
                        # Save the decrypted file
                        with open(decrypted_path, 'wb') as f:
                            f.write(decrypted)
                        
                        successful_decryptions.append({
                            "key": key_hex,
                            "entropy": round(decrypted_entropy, 2),
                            "score": decryption_score,
                            "reasons": decryption_reasons,
                            "file": str(decrypted_path),
                            "network_indicators": network_indicators
                        })
                except Exception as e:
                    logger.debug(f"Error during decryption with key {key_hex}: {e}")
                    continue
            
            # Sort decryptions by score
            results["decryptions"] = sorted(successful_decryptions, key=lambda x: x["score"], reverse=True)
            
            # Config extraction
            results["config"]["patterns"] = ConfigExtractor.find_config_patterns(data)
            
            # Try to decode configs in both original and decrypted files
            results["config"]["decoded"] = ConfigExtractor.decode_potential_configs(data)
            
            # If we have successful decryptions, look for configs there too
            for decryption in results["decryptions"]:
                try:
                    with open(decryption["file"], 'rb') as f:
                        decrypted_data = f.read()
                        
                    config_results = ConfigExtractor.find_config_patterns(decrypted_data)
                    
                    if config_results:
                        decryption["configs"] = config_results
                except:
                    continue
                    # Generate an executive summary from the findings
            results["executive_summary"] = PayloadAnalyzer._generate_executive_summary(results)
            
            # Generate a conclusion
            results["conclusion"] = PayloadAnalyzer._generate_conclusion(results)
            
            # Add to processed files cache
            self.processed_files_cache.add(file_md5)
            self._save_processed_files_cache()
            
            # Save the full analysis results
            report_file = self.report_dir / f"analysis_{results['file']['md5']}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Generate human-readable report
            md_report = self._generate_markdown_report(results)
            md_report_file = self.report_dir / f"analysis_{results['file']['md5']}.md"
            with open(md_report_file, 'w') as f:
                f.write(md_report)
            
            logger.info(f"Analysis complete - Reports saved to {report_file} and {md_report_file}")
            
            return results
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            return {"error": f"Analysis failed: {str(e)}"}

    @staticmethod
    def _generate_executive_summary(results):
        """
        Generate an executive summary of the analysis.
        Args:
            results (dict): Analysis results
        Returns:
            list: Key findings as bullet points
        """
        summary = []
        
        # Check for high entropy (encryption)
        if results["basic_analysis"]["entropy"] > 7.5:
            summary.append(f"File exhibits very high entropy ({results['basic_analysis']['entropy']:.2f}), indicating encryption or compression")
        
        # Check for YARA rule matches
        if results["yara_matches"]:
            for match in results["yara_matches"]:
                try:
                    rule = match["rule"]
                    confidence = match["meta"].get("confidence", "unknown")
                    summary.append(f"Matched YARA rule: {rule} (confidence: {confidence})")
                except:
                    continue
        
        # Check for embedded PE files
        if results["detected_pe"]:
            summary.append(f"Detected {len(results['detected_pe'])} embedded PE files")
            for pe in results["detected_pe"]:
                try:
                    if "suspicious_indicators" in pe["info"] and pe["info"]["suspicious_indicators"]:
                        indicators = '; '.join(pe["info"]["suspicious_indicators"][:3])
                        summary.append(f"Suspicious indicators in embedded PE: {indicators}")
                except:
                    continue
        
        # Check for network indicators
        if any(indicators for indicators in results["network_indicators"].values()):
            c2_count = len(results["network_indicators"]["urls"]) + len(results["network_indicators"]["domains"]) + len(results["network_indicators"]["ips"])
            if c2_count > 0:
                summary.append(f"Identified {c2_count} potential C2 indicators")
                
                # List top 3 domains/URLs
                all_c2 = results["network_indicators"]["urls"] + results["network_indicators"]["domains"] + results["network_indicators"]["ips"]
                if all_c2:
                    c2_list = ', '.join(all_c2[:3])
                    summary.append(f"Notable C2 indicators: {c2_list}")
        
        # Check for successful decryption
        if results["decryptions"]:
            best_decryption = results["decryptions"][0]
            summary.append(f"Successfully decrypted payload using key: {best_decryption['key']}")
        
        # Check for config blocks
        if results["config"]["patterns"]:
            summary.append(f"Identified {len(results['config']['patterns'])} potential configuration blocks")
        
        # Add default finding if nothing else is found
        if not summary:
            summary.append("No significant malware indicators detected")
        
        return summary
            @staticmethod
    def _generate_conclusion(results):
        """
        Generate a conclusion about the analyzed file.
        Args:
            results (dict): Analysis results
        Returns:
            dict: Conclusion data including threat assessment and attribution
        """
        conclusion = {
            "threat_level": "unknown",
            "confidence": 0.0,
            "apt41_probability": 0.0,
            "classification": [],
            "attribution": [],
            "recommendations": []
        }
        
        # Indicators for threat level assessment
        indicators = {
            "yara_matches": bool(results["yara_matches"]),
            "embedded_pe": bool(results["detected_pe"]),
            "c2_indicators": any(indicators for indicators in results["network_indicators"].values()),
            "config_blocks": bool(results["config"]["patterns"] or results["config"]["decoded"]),
            "high_entropy": results["basic_analysis"].get("entropy", 0) > 7.5,
            "successful_decryption": bool(results["decryptions"])
        }
        
        # Count positive indicators
        positive_count = sum(1 for indicator in indicators.values() if indicator)
        
        # Set threat level
        if positive_count >= 4:
            conclusion["threat_level"] = "high"
            conclusion["confidence"] = 0.9
        elif positive_count >= 2:
            conclusion["threat_level"] = "medium"
            conclusion["confidence"] = 0.7
        elif positive_count >= 1:
            conclusion["threat_level"] = "low"
            conclusion["confidence"] = 0.5
        else:
            conclusion["threat_level"] = "minimal"
            conclusion["confidence"] = 0.3
        
        # Classification of malware
        if indicators["embedded_pe"]:
            conclusion["classification"].append("dropper")
        if indicators["config_blocks"]:
            conclusion["classification"].append("backdoor")
        if indicators["c2_indicators"]:
            conclusion["classification"].append("remote_access")
        if indicators["high_entropy"] and indicators["successful_decryption"]:
            conclusion["classification"].append("encrypted")
        
        # If no classification, add generic
        if not conclusion["classification"]:
            conclusion["classification"].append("generic")
        
        # Check for APT41 attribution
        apt41_indicators = 0
        
        # Check YARA matches for APT41
        for match in results["yara_matches"]:
            try:
                rule_name = match["rule"]
                if "APT41" in rule_name:
                    apt41_indicators += 2
            except:
                continue
        
        # Check for KEYP markers
        if any("KEYP" in str(pattern) for pattern in results["config"]["patterns"]):
            apt41_indicators += 1
        
        # Check for RC4 encryption references
        if results["config"]["decoded"] and any("RC4" in str(decoded) for decoded in results["config"]["decoded"]):
            apt41_indicators += 1
        
        # Calculate APT41 probability
        if apt41_indicators >= 3:
            conclusion["apt41_probability"] = 0.9
            conclusion["attribution"].append("APT41")
        elif apt41_indicators >= 1:
            conclusion["apt41_probability"] = 0.6
            conclusion["attribution"].append("possible APT41")
        
        # Add recommendations based on findings
        if conclusion["threat_level"] in ["medium", "high"]:
            conclusion["recommendations"].append("Submit sample to professional malware analysis service")
            conclusion["recommendations"].append("Check system for indicators of compromise")
            conclusion["recommendations"].append("Investigate source of the suspected malware")
        
        if indicators["c2_indicators"]:
            conclusion["recommendations"].append("Block identified C2 domains and IPs")
            conclusion["recommendations"].append("Monitor for suspicious network traffic to similar domains")
        
        if conclusion["apt41_probability"] > 0.5:
            conclusion["recommendations"].append("Employ APT41-specific hunting techniques across the enterprise")
        
        return conclusion

     def batch_analyze(self, directory, pattern="*.bin", force=False):
        """
        Analyze multiple files matching a pattern in a directory.
        Args:
            directory (str): Directory to scan
            pattern (str): Glob pattern for files to analyze
            force (bool): Force analysis even for previously analyzed files
        Returns:
            list: List of analysis results
        """
        directory = Path(directory)
        files = list(directory.glob(pattern))

        if not files:
            logger.warning(f"No files matching '{pattern}' found in {directory}")
            return []

        logger.info(f"Found {len(files)} files to analyze in {directory}")

        results = []

        # Analyze each file
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as executor:
            future_to_file = {
                executor.submit(self.analyze_file, file, force): file
                for file in files
            }

            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Completed analysis of {file}")
                except Exception as e:
                    logger.error(f"Error analyzing {file}: {e}")
                    results.append({"file": str(file), "error": str(e)})

        # Generate summary report
        self._generate_batch_summary(results)

        return results

    def _generate_batch_summary(self, results):
        """
        Generate a summary of batch analysis.
        Args:
            results (list): List of analysis results
        Returns:
            None
        """
        summary_file = self.report_dir / "batch_summary.md"

        # Filter out skipped files from the summary count
        filtered_results = [
            r for r in results
            if not ("status" in r and r["status"] == "skipped")
        ]

        with open(summary_file, 'w') as f:
            f.write("# KEYPLUG Batch Analysis Summary\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Files Analyzed:** {len(filtered_results)}\n\n")

            # Count files by threat level
            threat_levels = {
                "high": 0, "medium": 0, "low": 0,
                "minimal": 0, "unknown": 0, "error": 0
            }
            for result in filtered_results:
                if "error" in result:
                    threat_levels["error"] += 1
                else:
                    lvl = result.get("conclusion", {}).get("threat_level", "unknown")
                    threat_levels[lvl] += 1

            # Write threat level summary
            f.write("## Threat Level Summary\n\n")
            f.write("| Threat Level | Count |\n")
            f.write("|--------------|-------|\n")
            for lvl, cnt in threat_levels.items():
                f.write(f"| {lvl.capitalize()} | {cnt} |\n")

            # Write file details table
            f.write("\n## Analyzed Files\n\n")
            f.write("| Filename | MD5 | Threat | Classification | Notable Findings |\n")
            f.write("|----------|-----|--------|----------------|------------------|\n")
            for result in filtered_results:
                if "error" in result:
                    fname = result.get("file", "Unknown")
                    f.write(f"| {fname} | Error | Error | Error | {result['error']} |\n")
                elif result.get("status") == "skipped":
                    continue
                else:
                    fname = result["file"].get("name", "Unknown")
                    fhash = result["file"].get("md5", "Unknown")
                    threat = result["conclusion"].get("threat_level", "unknown").capitalize()
                    cls = ', '.join(result["conclusion"].get("classification", ["Unknown"]))
                    top = (result.get("executive_summary") or ["No findings"])[0]
                    f.write(f"| {fname} | {fhash} | {threat} | {cls} | {top} |\n")

            # Potential APT41 attribution
            apt41 = [
                r for r in filtered_results
                if r.get("conclusion", {}).get("apt41_probability", 0) > 0.5
            ]
            if apt41:
                f.write("\n## Potential APT41 Attribution\n\n")
                f.write("| Filename | MD5 | APT41 Probability |\n")
                f.write("|----------|-----|-------------------|\n")
                for r in apt41:
                    n = r["file"].get("name", "Unknown")
                    h = r["file"].get("md5", "Unknown")
                    p = r["conclusion"]["apt41_probability"] * 100
                    f.write(f"| {n} | {h} | {p:.0f}% |\n")

            # Conclusion
            f.write("\n## Conclusion\n\n")
            f.write(
                f"Analyzed {len(filtered_results)} files with the following distribution of threat levels:\n\n"
            )
            for lvl, cnt in threat_levels.items():
                if cnt:
                    f.write(f"- **{lvl.capitalize()}:** {cnt} files\n")
            if apt41:
                f.write(f"\nFound {len(apt41)} files with potential APT41 attribution.\n")

        logger.info(f"Batch summary saved to {summary_file}")        

    def monitor_and_analyze(self, base_dir, interval=None, force=False):
        """
        Monitor a directory for KEYPLUG payloads and analyze them.
        Args:
            base_dir (str): Base directory to monitor
            interval (int): If provided, continuously monitor every interval seconds
            force (bool): Force analysis even for previously analyzed files
        Returns:
            dict: Summary of analysis results
        """
        base_dir = Path(base_dir)
        
        # Function to perform one scan
        def perform_scan():
            # Find all potential payload files
            payload_files = self.find_keyplug_payloads(base_dir)
            
            # Filter out already processed files (unless force=True)
            if not force:
                unprocessed_files = []
                for file_path in payload_files:
                    try:
                        with open(file_path, 'rb') as f:
                            file_md5 = hashlib.md5(f.read()).hexdigest()
                        
                        if file_md5 not in self.processed_files_cache:
                            unprocessed_files.append(file_path)
                    except Exception as e:
                        logger.warning(f"Error hashing file {file_path}: {e}")
                        # Include it anyway to be safe
                        unprocessed_files.append(file_path)
                        
                logger.info(f"Found {len(unprocessed_files)} new files out of {len(payload_files)} total")
                payload_files = unprocessed_files
                
            if not payload_files:
                logger.info("No new payloads to analyze")
                return {"analyzed": 0, "skipped": 0, "errors": 0, "files": []}
                
            # Analyze each file
            results = []
            analyzed = 0
            skipped = 0
            errors = 0
            
            for file_path in payload_files:
                try:
                    result = self.analyze_file(file_path, force)
                    results.append(result)
                    
                    if "status" in result and result["status"] == "skipped":
                        skipped += 1
                        logger.info(f"Skipped {file_path}")
                    elif "error" in result:
                        errors += 1
                        logger.error(f"Error analyzing {file_path}: {result['error']}")
                    else:
                        analyzed += 1
                        logger.info(f"Analyzed {file_path}")
                except Exception as e:
                    errors += 1
                    logger.error(f"Error processing {file_path}: {e}")
            
            # Generate batch summary if any files were analyzed
            if analyzed > 0:
                self._generate_batch_summary(results)
                
            return {
                "analyzed": analyzed,
                "skipped": skipped, 
                "errors": errors,
                "files": [str(f) for f in payload_files]
            }
        
        # Perform first scan
        scan_results = perform_scan()
        
        # If interval is provided, continue monitoring
        if interval:
            try:
                logger.info(f"Monitoring {base_dir} for new payloads every {interval} seconds. Press Ctrl+C to stop.")
                
                while True:
                    time.sleep(interval)
                    logger.info(f"Performing scheduled scan of {base_dir}")
                    scan_results = perform_scan()
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                
        return scan_results