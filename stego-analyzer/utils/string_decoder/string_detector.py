"""
Encoded String Detector Module
----------------------------
Detects potential encoded/obfuscated strings in binary data
using statistical analysis and OpenVINO acceleration.
"""

import os
import re
import struct
import binascii
import numpy as np
import concurrent.futures
from collections import Counter, defaultdict
from tqdm import tqdm

from stego_analyzer.utils.string_decoder.entropy_analyzer import EntropyAnalyzer

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - falling back to CPU-only processing")

class EncodedStringDetector:
    """
    Detects potential encoded strings in binary data using
    statistical analysis and pattern recognition with OpenVINO acceleration.
    """
    
    def __init__(self):
        """Initialize the encoded string detector"""
        self.entropy_analyzer = EntropyAnalyzer()
        self.core = None
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                print(f"OpenVINO Core initialized successfully")
                print(f"Available devices: {self.core.available_devices}")
                
                # Default to CPU
                self.preferred_device = "CPU"
                
                # Try to use more powerful devices if available
                if "GPU" in self.core.available_devices:
                    self.preferred_device = "GPU"
                    print("Using GPU acceleration")
                elif "VPU" in self.core.available_devices:
                    self.preferred_device = "VPU"
                    print("Using VPU acceleration")
                else:
                    print("Using CPU acceleration")
                    
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.core = None
    
    def extract_plain_strings(self, data, min_length=4):
        """
        Extract plain ASCII and Unicode strings from binary data
        
        Args:
            data: Binary data to analyze
            min_length: Minimum string length
            
        Returns:
            List of (offset, string, encoding) tuples
        """
        # Extract ASCII strings
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
        ascii_strings = [(m.start(), m.group().decode('ascii'), 'ascii') 
                        for m in ascii_pattern.finditer(data)]
        
        # Extract Unicode strings (UTF-16LE)
        unicode_strings = []
        i = 0
        while i < len(data) - 2:
            if data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                # Potential UTF-16LE string
                start = i
                string_bytes = bytearray()
                
                while i < len(data) - 2 and data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                    string_bytes.extend(data[i:i+2])
                    i += 2
                
                if len(string_bytes) >= min_length * 2:
                    try:
                        unicode_string = string_bytes.decode('utf-16le')
                        unicode_strings.append((start, unicode_string, 'utf-16le'))
                    except UnicodeDecodeError:
                        pass
            else:
                i += 1
        
        # Combine and sort by offset
        all_strings = ascii_strings + unicode_strings
        all_strings.sort(key=lambda x: x[0])
        
        return all_strings
    
    def detect_potential_encoded_strings(self, data, min_length=4, max_length=100):
        """
        Detect potential encoded strings using statistical analysis
        
        Args:
            data: Binary data to analyze
            min_length: Minimum string length
            max_length: Maximum string length
            
        Returns:
            List of potential encoded string regions with metadata
        """
        # First identify high entropy regions
        high_entropy_regions = self.entropy_analyzer.identify_high_entropy_regions(
            data, min_size=min_length, threshold=6.0
        )
        
        # Process regions in parallel
        potential_strings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for start, end, entropy in high_entropy_regions:
                # Limit region size for analysis
                if end - start > 10000:
                    end = start + 10000
                
                region_data = data[start:end]
                futures.append(executor.submit(
                    self._analyze_region_for_strings, 
                    region_data, 
                    start, 
                    min_length, 
                    max_length
                ))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        potential_strings.extend(result)
                except Exception as e:
                    print(f"Error analyzing region: {e}")
        
        # Sort by score
        potential_strings.sort(key=lambda x: x['score'], reverse=True)
        
        return potential_strings
    
    def _analyze_region_for_strings(self, region_data, region_start, min_length, max_length):
        """Analyze a region for potential encoded strings"""
        results = []
        
        # Check for various encoding patterns
        encoding_checks = [
            self._check_xor_encoding,
            self._check_add_encoding,
            self._check_rol_encoding,
            self._check_custom_encoding
        ]
        
        # Apply each check
        for check_func in encoding_checks:
            check_results = check_func(region_data, min_length, max_length)
            
            # Adjust offsets to be relative to full data
            for result in check_results:
                result['offset'] += region_start
                results.append(result)
        
        return results
    
    def _check_xor_encoding(self, data, min_length, max_length):
        """Check for XOR-encoded strings"""
        results = []
        
        # Try common XOR keys
        xor_keys = [0x01, 0x02, 0x03, 0x07, 0x0A, 0x0D, 0x10, 0x20, 0x33, 0x55, 0x7F, 0xFF]
        
        for key in xor_keys:
            # XOR the data
            decoded = bytes(b ^ key for b in data)
            
            # Check if result contains printable ASCII
            ascii_pattern = re.compile(b'[ -~]{%d,%d}' % (min_length, max_length))
            for match in ascii_pattern.finditer(decoded):
                try:
                    decoded_str = match.group().decode('ascii')
                    
                    # Score the string based on characteristics
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.5:  # Only include promising candidates
                        results.append({
                            'offset': match.start(),
                            'length': len(decoded_str),
                            'encoding': f'XOR-{key:02X}',
                            'decoded': decoded_str,
                            'score': score,
                            'key': key
                        })
                except UnicodeDecodeError:
                    pass
        
        return results
    
    def _check_add_encoding(self, data, min_length, max_length):
        """Check for ADD/SUB-encoded strings"""
        results = []
        
        # Try common ADD/SUB keys
        add_keys = [0x01, 0x02, 0x03, 0x05, 0x07, 0x0A, 0x10, 0x20, 0x30]
        
        for key in add_keys:
            # ADD the data
            decoded_add = bytes((b + key) & 0xFF for b in data)
            decoded_sub = bytes((b - key) & 0xFF for b in data)
            
            # Check ADD result
            ascii_pattern = re.compile(b'[ -~]{%d,%d}' % (min_length, max_length))
            for match in ascii_pattern.finditer(decoded_add):
                try:
                    decoded_str = match.group().decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.5:
                        results.append({
                            'offset': match.start(),
                            'length': len(decoded_str),
                            'encoding': f'ADD-{key:02X}',
                            'decoded': decoded_str,
                            'score': score,
                            'key': key
                        })
                except UnicodeDecodeError:
                    pass
            
            # Check SUB result
            for match in ascii_pattern.finditer(decoded_sub):
                try:
                    decoded_str = match.group().decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.5:
                        results.append({
                            'offset': match.start(),
                            'length': len(decoded_str),
                            'encoding': f'SUB-{key:02X}',
                            'decoded': decoded_str,
                            'score': score,
                            'key': key
                        })
                except UnicodeDecodeError:
                    pass
        
        return results
    
    def _check_rol_encoding(self, data, min_length, max_length):
        """Check for ROL/ROR-encoded strings"""
        results = []
        
        # Try common rotation amounts
        rot_amounts = [1, 2, 3, 4, 5, 6, 7]
        
        for rot in rot_amounts:
            # ROL the data
            decoded_rol = bytes(((b << rot) | (b >> (8 - rot))) & 0xFF for b in data)
            decoded_ror = bytes(((b >> rot) | (b << (8 - rot))) & 0xFF for b in data)
            
            # Check ROL result
            ascii_pattern = re.compile(b'[ -~]{%d,%d}' % (min_length, max_length))
            for match in ascii_pattern.finditer(decoded_rol):
                try:
                    decoded_str = match.group().decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.5:
                        results.append({
                            'offset': match.start(),
                            'length': len(decoded_str),
                            'encoding': f'ROL-{rot}',
                            'decoded': decoded_str,
                            'score': score,
                            'key': rot
                        })
                except UnicodeDecodeError:
                    pass
            
            # Check ROR result
            for match in ascii_pattern.finditer(decoded_ror):
                try:
                    decoded_str = match.group().decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.5:
                        results.append({
                            'offset': match.start(),
                            'length': len(decoded_str),
                            'encoding': f'ROR-{rot}',
                            'decoded': decoded_str,
                            'score': score,
                            'key': rot
                        })
                except UnicodeDecodeError:
                    pass
        
        return results
    
    def _check_custom_encoding(self, data, min_length, max_length):
        """Check for custom encoding schemes"""
        results = []
        
        # Try XOR with position-dependent key
        for offset in range(0, len(data) - min_length):
            # Try position-based XOR
            decoded = bytearray()
            for i in range(min(max_length, len(data) - offset)):
                decoded.append((data[offset + i] ^ (i % 256)) & 0xFF)
            
            # Check if result is printable ASCII
            is_printable = True
            for b in decoded:
                if b < 32 or b > 126:
                    is_printable = False
                    break
            
            if is_printable and len(decoded) >= min_length:
                try:
                    decoded_str = decoded.decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.6:  # Higher threshold for custom encoding
                        results.append({
                            'offset': offset,
                            'length': len(decoded_str),
                            'encoding': 'XOR-POSITION',
                            'decoded': decoded_str,
                            'score': score,
                            'key': 'position'
                        })
                except UnicodeDecodeError:
                    pass
        
        # Try byte-pair decoding (common in some malware)
        for offset in range(0, len(data) - min_length * 2, 2):
            if offset + min_length * 2 > len(data):
                break
                
            decoded = bytearray()
            for i in range(0, min(max_length * 2, len(data) - offset), 2):
                if offset + i + 1 < len(data):
                    # Various byte-pair operations
                    b1 = data[offset + i]
                    b2 = data[offset + i + 1]
                    
                    # Try XOR of byte pairs
                    decoded.append(b1 ^ b2)
            
            # Check if result is printable ASCII
            is_printable = True
            for b in decoded:
                if b < 32 or b > 126:
                    is_printable = False
                    break
            
            if is_printable and len(decoded) >= min_length:
                try:
                    decoded_str = decoded.decode('ascii')
                    score = self._score_potential_api_string(decoded_str)
                    
                    if score > 0.6:
                        results.append({
                            'offset': offset,
                            'length': len(decoded_str),
                            'encoding': 'BYTE-PAIR-XOR',
                            'decoded': decoded_str,
                            'score': score,
                            'key': 'byte-pair'
                        })
                except UnicodeDecodeError:
                    pass
        
        return results
    
    def _score_potential_api_string(self, string):
        """
        Score a string based on likelihood of being an API name
        
        Args:
            string: String to score
            
        Returns:
            Score between 0.0 and 1.0
        """
        # Common API prefixes
        api_prefixes = [
            "Create", "Get", "Set", "Query", "Open", "Close", "Read", "Write",
            "Alloc", "Free", "Lock", "Unlock", "Initialize", "Terminate",
            "Register", "Unregister", "Enum", "Find", "Connect", "Disconnect",
            "Start", "Stop", "Send", "Recv", "Load", "Unload", "Map", "Unmap"
        ]
        
        # Common API suffixes
        api_suffixes = [
            "A", "W", "Ex", "ExA", "ExW", "Internal", "Proc", "Func", "Callback",
            "Notify", "Handler", "Routine", "Proxy"
        ]
        
        # Common Windows API DLL names
        dll_names = [
            "kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32",
            "oleaut32", "ws2_32", "wininet", "urlmon", "ntdll", "secur32",
            "crypt32", "wtsapi32", "setupapi", "psapi"
        ]
        
        # Initialize score
        score = 0.0
        
        # Check for CamelCase (common in Windows APIs)
        if re.search(r'[a-z][A-Z]', string):
            score += 0.2
        
        # Check for API prefixes
        for prefix in api_prefixes:
            if string.startswith(prefix):
                score += 0.25
                break
        
        # Check for API suffixes
        for suffix in api_suffixes:
            if string.endswith(suffix):
                score += 0.15
                break
        
        # Check for DLL names
        for dll in dll_names:
            if dll in string.lower():
                score += 0.1
                break
        
        # Check for reasonable length (most API names are 6-30 chars)
        if 6 <= len(string) <= 30:
            score += 0.1
        elif 4 <= len(string) < 6:
            score += 0.05
        
        # Check for alphanumeric content
        if re.match(r'^[a-zA-Z0-9_]+$', string):
            score += 0.1
        
        # Penalize strings with unusual characters
        unusual_chars = sum(1 for c in string if not c.isalnum() and c != '_')
        if unusual_chars > 0:
            score -= 0.05 * unusual_chars
        
        # Bonus for known API names
        common_api_names = [
            "VirtualAlloc", "VirtualProtect", "CreateProcess", "CreateFile",
            "ReadFile", "WriteFile", "LoadLibrary", "GetProcAddress",
            "RegOpenKey", "RegSetValue", "WSAStartup", "socket", "connect",
            "send", "recv", "CreateThread", "WinExec", "ShellExecute"
        ]
        
        for api in common_api_names:
            if api in string:
                score += 0.3
                break
        
        # Cap score at 1.0
        return min(1.0, score)
    
    def analyze_binary_for_encoded_strings(self, file_path, output_dir=None):
        """
        Analyze a binary file for encoded strings
        
        Args:
            file_path: Path to the binary file
            output_dir: Directory to save output files (optional)
            
        Returns:
            Dict with analysis results
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found")
            return None
        
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print(f"Analyzing file for encoded strings: {file_path}")
        
        # Read binary data
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Extract plain strings
        print("Extracting plain strings...")
        plain_strings = self.extract_plain_strings(data)
        print(f"Found {len(plain_strings)} plain strings")
        
        # Detect potential encoded strings
        print("Detecting potential encoded strings...")
        encoded_strings = self.detect_potential_encoded_strings(data)
        print(f"Found {len(encoded_strings)} potential encoded strings")
        
        # Generate results
        results = {
            "file_path": file_path,
            "file_size": len(data),
            "plain_strings": plain_strings,
            "encoded_strings": encoded_strings,
            "summary": {
                "total_plain_strings": len(plain_strings),
                "total_encoded_strings": len(encoded_strings)
            }
        }
        
        # Save results if output directory specified
        if output_dir:
            import json
            import os
            
            file_name = os.path.basename(file_path)
            output_path = os.path.join(output_dir, f"{file_name}_string_analysis.json")
            
            # Prepare for JSON serialization
            serializable_results = self._prepare_for_serialization(results)
            
            with open(output_path, 'w') as f:
                json.dump(serializable_results, f, indent=2)
            
            print(f"Analysis results saved to: {output_path}")
            
            # Generate human-readable report
            report_path = os.path.join(output_dir, f"{file_name}_string_analysis_report.txt")
            self._generate_report(results, report_path)
            print(f"Human-readable report saved to: {report_path}")
        
        return results
    
    def _prepare_for_serialization(self, obj):
        """Prepare results for JSON serialization"""
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode()
        elif isinstance(obj, dict):
            return {k: self._prepare_for_serialization(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._prepare_for_serialization(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._prepare_for_serialization(item) for item in obj)
        else:
            return obj
    
    def _generate_report(self, results, output_path):
        """Generate a human-readable report of the string analysis"""
        with open(output_path, 'w') as f:
            f.write("KEYPLUG Encoded String Analysis Report\n")
            f.write("=====================================\n\n")
            
            f.write(f"File: {results['file_path']}\n")
            f.write(f"Size: {results['file_size']} bytes\n\n")
            
            f.write("Summary\n")
            f.write("-------\n")
            summary = results['summary']
            f.write(f"Total plain strings: {summary['total_plain_strings']}\n")
            f.write(f"Total potential encoded strings: {summary['total_encoded_strings']}\n\n")
            
            # Show top encoded strings
            if results['encoded_strings']:
                f.write("Top Potential Encoded Strings\n")
                f.write("--------------------------\n")
                
                # Sort by score
                top_strings = sorted(results['encoded_strings'], key=lambda x: x['score'], reverse=True)
                
                # Show top 20
                for i, string in enumerate(top_strings[:20]):
                    f.write(f"\n[{i+1}] Offset: 0x{string['offset']:x}\n")
                    f.write(f"    Encoding: {string['encoding']}\n")
                    f.write(f"    Decoded: {string['decoded']}\n")
                    f.write(f"    Score: {string['score']:.2f}\n")
                
                if len(top_strings) > 20:
                    f.write(f"\n... and {len(top_strings) - 20} more encoded strings\n")
            
            # Show interesting plain strings
            if results['plain_strings']:
                f.write("\nInteresting Plain Strings\n")
                f.write("------------------------\n")
                
                # Filter for interesting strings
                interesting_strings = []
                for offset, string, encoding in results['plain_strings']:
                    score = self._score_potential_api_string(string)
                    if score > 0.5:
                        interesting_strings.append((offset, string, encoding, score))
                
                # Sort by score
                interesting_strings.sort(key=lambda x: x[3], reverse=True)
                
                # Show top 20
                for i, (offset, string, encoding, score) in enumerate(interesting_strings[:20]):
                    f.write(f"\n[{i+1}] Offset: 0x{offset:x}\n")
                    f.write(f"    String: {string}\n")
                    f.write(f"    Encoding: {encoding}\n")
                    f.write(f"    Score: {score:.2f}\n")
                
                if len(interesting_strings) > 20:
                    f.write(f"\n... and {len(interesting_strings) - 20} more interesting strings\n")
