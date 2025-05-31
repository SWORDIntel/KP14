#!/usr/bin/env python3
"""
KEYPLUG ML Pattern Analyzer
Uses OpenVINO and machine learning techniques to identify patterns in encrypted malware
"""
import os
import binascii
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import re

try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False
    print("WARNING: OpenVINO not available. Will use statistical analysis only.")

# Constants
BLOCK_SIZE = 256
MIN_ENTROPY_THRESHOLD = 0.3
MAX_ENTROPY_THRESHOLD = 0.9
MIN_PATTERN_LENGTH = 4
MAX_PATTERN_LENGTH = 32

# Common executable file signatures
EXECUTABLE_SIGNATURES = {
    b'MZ': 'DOS/PE Executable',
    b'PK': 'ZIP/JAR/APK Archive',
    b'\x7fELF': 'ELF Executable',
    b'\xca\xfe\xba\xbe': 'Mach-O Fat Binary',
    b'\xce\xfa\xed\xfe': 'Mach-O Binary',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit Binary',
    b'\x23\x21': 'Script (Shebang)',
    b'\x89PNG': 'PNG Image',
    b'GIF8': 'GIF Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'%PDF': 'PDF Document',
    b'BM': 'BMP Image',
    b'II*\x00': 'TIFF Image',
    b'MM\x00*': 'TIFF Image',
    b'\x00\x61\x73\x6d': 'WebAssembly Binary',
    b'\x7b\x5c\x72\x74': 'RTF Document',
    b'\x50\x4b\x05\x06': 'ZIP Archive End',
    b'\xd0\xcf\x11\xe0': 'Microsoft Compound Document',
    b'\x52\x61\x72\x21': 'RAR Archive',
    b'\x1f\x8b\x08': 'GZIP Archive',
    b'\x42\x5a\x68': 'BZIP2 Archive',
    b'\x37\x7a\xbc\xaf': '7-Zip Archive',
    b'\x75\x73\x74\x61\x72': 'TAR Archive',
    b'\x04\x22\x4d\x18': 'LZ4 Compressed',
    b'\x28\xb5\x2f\xfd': 'ZSTD Compressed',
    b'\x4f\x67\x67\x53': 'Ogg Vorbis',
    b'\x1a\x45\xdf\xa3': 'Matroska/WebM',
    b'\x30\x26\xb2\x75': 'ASF/WMA/WMV',
    b'\x00\x00\x00\x18\x66\x74\x79\x70': 'MP4',
    b'\x49\x44\x33': 'MP3 with ID3',
    b'\xff\xfb': 'MP3',
    b'\x3c\x68\x74\x6d\x6c': 'HTML Document',
    b'\x3c\x73\x76\x67': 'SVG Document',
    b'\x3c\x3f\x78\x6d\x6c': 'XML Document',
    b'\x21\x3c\x61\x72\x63\x68\x3e': 'Linux deb',
    b'\x5b\x5a\x6f\x6e\x65': 'Windows Registry',
}

# Common strings in malware
SUSPICIOUS_STRINGS = [
    'cmd.exe', 'powershell', 'wscript', 'cscript', 'rundll32', 'regsvr32',
    'explorer.exe', 'winlogon.exe', 'lsass.exe', 'services.exe', 'svchost.exe',
    'HTTP/', 'Mozilla/', 'User-Agent:', 'GET ', 'POST ',
    'CreateProcess', 'VirtualAlloc', 'LoadLibrary', 'GetProcAddress',
    'URLDownloadToFile', 'ShellExecute', 'WinExec', 'CreateService',
    'StartService', 'CreateRemoteThread', 'ReadProcessMemory', 'WriteProcessMemory',
    'WSASocket', 'connect', 'send', 'recv', 'bind', 'accept',
    'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile',
    'RegCreate', 'RegSet', 'RegGet', 'RegDelete',
    'StrCat', 'StrCpy', 'StrLen', 'StrStr', 'StrCmp',
    'SetWindowsHook', 'GetAsyncKeyState', 'GetKeyState',
    'CreateMutex', 'OpenMutex', 'CreateEvent', 'SetEvent',
    'AdjustTokenPrivileges', 'LookupPrivilegeValue',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString',
    'NtGlobalFlag', 'HeapFlags', 'ForceFlags',
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
    '.onion', '.bit', '.bazar', '.io',
    'localhost', '127.0.0.1', '0.0.0.0',
    'admin', 'administrator', 'root', 'system',
    'password', 'passwd', 'credentials', 'creds',
    'key', 'secret', 'token', 'auth',
    'bitcoin', 'wallet', 'ransom', 'encrypt', 'decrypt',
    'botnet', 'backdoor', 'trojan', 'virus', 'worm', 'keylogger', 'rootkit',
]

# Opcode sequences common in malware
COMMON_X86_OPCODES = [
    b'\x33\xc0',              # xor eax, eax
    b'\x8b\xff',              # mov edi, edi
    b'\x55\x8b\xec',          # push ebp; mov ebp, esp
    b'\x33\xc9',              # xor ecx, ecx
    b'\x33\xd2',              # xor edx, edx
    b'\x33\xf6',              # xor esi, esi
    b'\x33\xff',              # xor edi, edi
    b'\x6a\x00',              # push 0
    b'\x68',                  # push imm32
    b'\xe8',                  # call
    b'\xff\x15',              # call dword ptr [addr]
    b'\xff\x25',              # jmp dword ptr [addr]
    b'\x83\xc4',              # add esp, imm8
    b'\x8d\x85',              # lea eax, [ebp+disp32]
    b'\x8d\x95',              # lea edx, [ebp+disp32]
    b'\x8b\x45',              # mov eax, [ebp+disp8]
    b'\x8b\x55',              # mov edx, [ebp+disp8]
    b'\x8b\x4d',              # mov ecx, [ebp+disp8]
    b'\x89\x45',              # mov [ebp+disp8], eax
    b'\x89\x55',              # mov [ebp+disp8], edx
    b'\x89\x4d',              # mov [ebp+disp8], ecx
    b'\xc3',                  # ret
    b'\xc2',                  # ret imm16
    b'\x74',                  # je/jz
    b'\x75',                  # jne/jnz
    b'\xeb',                  # jmp rel8
    b'\xe9',                  # jmp rel32
]

# API patterns that may indicate specific malware functionality
API_PATTERNS = [
    # Network communication
    r'(WSAStartup|socket|connect|bind|send|recv|inet_addr)',
    # Process manipulation
    r'(CreateProcess|OpenProcess|CreateRemoteThread|VirtualAlloc|WriteProcessMemory)',
    # Registry manipulation
    r'(RegOpenKey|RegCreateKey|RegSetValue|RegGetValue|RegDeleteKey)',
    # File operations
    r'(CreateFile|WriteFile|ReadFile|CopyFile|DeleteFile|MoveFile)',
    # System persistence
    r'(CreateService|StartService|OpenSCManager|RegSetValueEx.*\\Run)',
    # Information theft
    r'(GetClipboardData|GetWindowText|keybd_event|GetAsyncKeyState)',
    # Anti-analysis
    r'(IsDebuggerPresent|CheckRemoteDebuggerPresent|GetTickCount|QueryPerformanceCounter)',
    # Encryption
    r'(CryptEncrypt|CryptDecrypt|CryptCreateHash|CryptDeriveKey)',
    # Shell code execution
    r'(CreateThread|VirtualProtect|VirtualAlloc.*PAGE_EXECUTE)',
]

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for byte_value in range(256):
        p_x = data.count(byte_value) / len(data)
        if p_x > 0:
            entropy += -p_x * np.log2(p_x)
    
    return entropy / 8.0  # Normalize to [0,1]

def find_executable_signatures(data):
    """Find executable file signatures in the data"""
    results = []
    for sig, desc in EXECUTABLE_SIGNATURES.items():
        positions = []
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + len(sig)
        
        if positions:
            results.append((sig, desc, positions))
    
    return results

def find_repeating_patterns(data, min_pattern_len=4, max_pattern_len=32, min_count=3):
    """Find repeating byte patterns in the data"""
    patterns = {}
    
    # For each pattern length
    for pattern_len in range(min_pattern_len, min(max_pattern_len + 1, len(data) // 2)):
        # Collect all patterns of this length
        all_patterns = {}
        for i in range(len(data) - pattern_len + 1):
            pattern = data[i:i+pattern_len]
            if pattern in all_patterns:
                all_patterns[pattern].append(i)
            else:
                all_patterns[pattern] = [i]
        
        # Keep patterns that repeat enough times
        for pattern, positions in all_patterns.items():
            if len(positions) >= min_count:
                patterns[pattern] = positions
    
    # Sort by pattern frequency
    return sorted(patterns.items(), key=lambda x: len(x[1]), reverse=True)

def find_strings(data, min_len=4):
    """Find printable ASCII strings in binary data"""
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= min_len:
                strings.append(current_string)
            current_string = ""
    
    # Don't forget the last string
    if len(current_string) >= min_len:
        strings.append(current_string)
    
    return strings

def find_suspicious_strings(strings_list):
    """Identify suspicious strings from a list of strings"""
    suspicious = []
    
    for string in strings_list:
        for sus_str in SUSPICIOUS_STRINGS:
            if sus_str.lower() in string.lower():
                suspicious.append((string, sus_str))
                break
    
    return suspicious

def detect_api_patterns(strings_list):
    """Detect API call patterns in a list of strings"""
    api_matches = defaultdict(list)
    
    for string in strings_list:
        for pattern_name, pattern in enumerate(API_PATTERNS):
            matches = re.findall(pattern, string, re.IGNORECASE)
            if matches:
                for match in matches:
                    api_matches[f"Pattern {pattern_name+1}"].append((string, match))
    
    return api_matches

def sliding_window_entropy(data, window_size=256, step=64):
    """Calculate entropy over a sliding window"""
    entropies = []
    positions = []
    
    for i in range(0, len(data) - window_size + 1, step):
        window = data[i:i+window_size]
        entropies.append(calculate_entropy(window))
        positions.append(i)
    
    return positions, entropies

def find_opcode_sequences(data):
    """Find common opcode sequences in the data"""
    results = []
    
    for opcode in COMMON_X86_OPCODES:
        positions = []
        start = 0
        while True:
            pos = data.find(opcode, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1  # Overlapping search
        
        if positions:
            results.append((opcode, positions))
    
    return sorted(results, key=lambda x: len(x[1]), reverse=True)

def analyze_byte_frequency(data):
    """Analyze byte frequency distribution"""
    counter = Counter(data)
    return counter

def detect_xor_key_candidates(data, max_key_len=4):
    """Detect potential XOR key candidates"""
    candidates = []
    
    # For different key lengths
    for key_len in range(1, max_key_len + 1):
        # Split data into columns based on key length
        columns = [data[i::key_len] for i in range(key_len)]
        
        # Find the most common byte in each column
        key = bytearray()
        for column in columns:
            counter = Counter(column)
            # Assume the most common byte XORed with space (0x20) is part of the key
            # This heuristic works well for text-based content
            most_common = counter.most_common(5)
            # Try multiple possibilities for each byte
            for byte, _ in most_common:
                key_byte_candidates = [byte ^ 0x20, byte ^ 0x00, byte ^ 0x0A, byte ^ 0x0D]
                for k in key_byte_candidates:
                    key.append(k)
                    # Test key on a sample
                    test_result = bytearray()
                    for i, b in enumerate(data[:100]):
                        test_result.append(b ^ key[i % len(key)])
                    
                    # Check if result contains mostly printable ASCII
                    printable_ratio = sum(32 <= b <= 126 for b in test_result) / len(test_result)
                    
                    if printable_ratio > 0.7:
                        candidates.append((bytes(key), printable_ratio))
                    
                    # Remove the last key byte for the next iteration
                    key.pop()
    
    # Sort by printable ratio
    return sorted(candidates, key=lambda x: x[1], reverse=True)

def detect_encryption_boundaries(entropy_values, threshold=0.2):
    """Detect potential encryption boundaries based on entropy changes"""
    boundaries = []
    
    for i in range(1, len(entropy_values)):
        diff = abs(entropy_values[i] - entropy_values[i-1])
        if diff > threshold:
            boundaries.append(i)
    
    return boundaries

def plot_entropy(positions, entropies, output_file=None):
    """Plot entropy over file position"""
    plt.figure(figsize=(12, 6))
    plt.plot(positions, entropies)
    plt.xlabel('File Position (bytes)')
    plt.ylabel('Entropy')
    plt.title('Entropy Analysis')
    plt.grid(True)
    
    if output_file:
        plt.savefig(output_file)
    else:
        plt.show()

def perform_ml_analysis(data):
    """Perform machine learning analysis on the data using OpenVINO"""
    if not OPENVINO_AVAILABLE:
        return {"error": "OpenVINO not available"}
    
    results = {}
    
    try:
        # Initialize OpenVINO Runtime
        core = Core()
        
        # For demonstration, we'll just show how to prepare the data
        # In a real implementation, you would load and run actual models here
        
        # Prepare data for analysis
        # Convert bytes to normalized float array for ML input
        data_array = np.frombuffer(data, dtype=np.uint8).astype(np.float32) / 255.0
        
        # Reshape data for model input (depending on your model requirements)
        # For example, create sliding windows of 256 bytes
        windows = []
        for i in range(0, len(data_array) - BLOCK_SIZE + 1, BLOCK_SIZE // 2):
            windows.append(data_array[i:i+BLOCK_SIZE])
        
        if not windows:
            return {"error": "Not enough data for ML analysis"}
        
        # Convert to numpy array of proper shape
        X = np.array(windows).reshape(-1, BLOCK_SIZE, 1)
        
        # In a real implementation, you would run inference here:
        # model = core.read_model(model_path)
        # compiled_model = core.compile_model(model)
        # results = compiled_model(X)
        
        # For now, we'll just return a placeholder
        results["ml_analysis"] = "ML analysis would be performed here with actual models"
        results["windows_count"] = len(windows)
        
        # Calculate feature statistics that might be useful for ML
        results["statistics"] = {
            "mean": float(np.mean(data_array)),
            "std": float(np.std(data_array)),
            "min": float(np.min(data_array)),
            "max": float(np.max(data_array)),
            "entropy": calculate_entropy(data)
        }
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def analyze_file(file_path, output_dir=None, enable_ml=False):
    """Main analysis function"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return
    
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"Analyzing file: {file_path}")
    file_name = os.path.basename(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    results = {}
    
    # Basic file info
    results["file_info"] = {
        "file_path": file_path,
        "file_size": len(data),
        "entropy": calculate_entropy(data)
    }
    
    # Entropy analysis
    print("Performing entropy analysis...")
    positions, entropies = sliding_window_entropy(data)
    results["entropy_analysis"] = {
        "overall_entropy": calculate_entropy(data),
        "sliding_window": list(zip(positions, entropies))
    }
    
    # Look for encryption boundaries
    boundaries = detect_encryption_boundaries(entropies)
    results["potential_boundaries"] = boundaries
    
    # Plot entropy
    if output_dir:
        entropy_plot = os.path.join(output_dir, f"{file_name}_entropy.png")
        plot_entropy(positions, entropies, entropy_plot)
        results["entropy_plot"] = entropy_plot
    
    # File signatures
    print("Searching for file signatures...")
    signatures = find_executable_signatures(data)
    results["file_signatures"] = [
        {"signature": binascii.hexlify(sig).decode(), "description": desc, "positions": pos}
        for sig, desc, pos in signatures
    ]
    
    # String analysis
    print("Extracting strings...")
    strings_list = find_strings(data)
    results["strings"] = {
        "count": len(strings_list),
        "samples": strings_list[:100] if len(strings_list) > 100 else strings_list
    }
    
    # Suspicious strings
    suspicious = find_suspicious_strings(strings_list)
    results["suspicious_strings"] = [
        {"string": s, "matched": m} for s, m in suspicious
    ]
    
    # API patterns
    api_patterns = detect_api_patterns(strings_list)
    results["api_patterns"] = {
        pattern: [{"string": s, "match": m} for s, m in matches]
        for pattern, matches in api_patterns.items()
    }
    
    # Repeating patterns
    print("Finding repeating patterns...")
    patterns = find_repeating_patterns(data)
    results["repeating_patterns"] = [
        {"pattern": binascii.hexlify(pattern).decode(), "count": len(positions), "positions": positions[:10]}
        for pattern, positions in patterns[:20]  # Limit to top 20 patterns
    ]
    
    # Opcode sequences
    print("Searching for opcode sequences...")
    opcodes = find_opcode_sequences(data)
    results["opcode_sequences"] = [
        {"opcode": binascii.hexlify(op).decode(), "count": len(pos), "positions": pos[:10]}
        for op, pos in opcodes[:20]  # Limit to top 20 sequences
    ]
    
    # Byte frequency analysis
    print("Analyzing byte frequency...")
    byte_freq = analyze_byte_frequency(data)
    # Convert to serializable format
    results["byte_frequency"] = {
        str(byte): count for byte, count in byte_freq.most_common()
    }
    
    # XOR key candidates
    print("Detecting potential XOR keys...")
    xor_candidates = detect_xor_key_candidates(data)
    results["xor_key_candidates"] = [
        {"key": binascii.hexlify(key).decode(), "printable_ratio": ratio}
        for key, ratio in xor_candidates[:10]  # Limit to top 10 candidates
    ]
    
    # ML analysis if enabled
    if enable_ml and OPENVINO_AVAILABLE:
        print("Performing machine learning analysis...")
        ml_results = perform_ml_analysis(data)
        results["ml_analysis"] = ml_results
    
    # Save results
    if output_dir:
        import json
        results_file = os.path.join(output_dir, file_name + "_analysis.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        print("Results saved to: {}".format(results_file))
    
    return results

def main():
    """Main function to run the analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ML-powered pattern analyzer for encrypted payloads")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-o", "--output-dir", help="Output directory for results")
    parser.add_argument("--ml", action="store_true", help="Enable machine learning analysis")
    args = parser.parse_args()
    
    analyze_file(args.file, args.output_dir, args.ml)

if __name__ == "__main__":
    main()
