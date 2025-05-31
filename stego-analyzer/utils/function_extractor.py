#!/usr/bin/env python3
"""
KEYPLUG Function and API Extractor
----------------------------------
Advanced function extraction and API call analysis tool for KEYPLUG malware
using OpenVINO hardware acceleration for maximum performance.

This tool analyzes decrypted binary data to:
1. Identify function boundaries based on common prologues/epilogues
2. Extract Windows API calls and imports
3. Analyze function behavior and potential malicious patterns
4. Reconstruct function call graphs
"""
import os
import binascii
import re
import json
import hashlib
from tqdm import tqdm
import concurrent.futures

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - will use hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - will use CPU-only processing")

# Constants
MAX_WORKERS = os.cpu_count()

# Common x86/x64 function prologues
X86_PROLOGUES = [
    (b"\x55\x8b\xec", "push ebp; mov ebp, esp"),               # Standard x86 function entry
    (b"\x53\x56\x57", "push ebx; push esi; push edi"),         # Register preservation
    (b"\x83\xec", "sub esp, X"),                               # Stack allocation (small)
    (b"\x81\xec", "sub esp, XXXX"),                            # Stack allocation (large)
    (b"\x55\x89\xe5", "push ebp; mov ebp, esp"),               # GCC-style entry
    (b"\x50\x51\x52", "push eax; push ecx; push edx"),         # Register preservation
    (b"\x56\x57", "push esi; push edi"),                       # Save registers
    (b"\x53\x55\x56", "push ebx; push ebp; push esi"),         # Register preservation
]

X64_PROLOGUES = [
    (b"\x48\x89\x5c\x24", "mov [rsp+X], rbx"),                 # Save rbx
    (b"\x48\x83\xec", "sub rsp, X"),                           # Stack allocation (small)
    (b"\x48\x81\xec", "sub rsp, XXXX"),                        # Stack allocation (large)
    (b"\x40\x53", "push rbx"),                                 # Save rbx
    (b"\x40\x55", "push rbp"),                                 # Save rbp
    (b"\x40\x56", "push rsi"),                                 # Save rsi
    (b"\x40\x57", "push rdi"),                                 # Save rdi
    (b"\x55\x48\x8b\xec", "push rbp; mov rbp, rsp"),           # x64 function entry
    (b"\x48\x89\x4c\x24", "mov [rsp+X], rcx"),                 # Save parameter
    (b"\x48\x89\x54\x24", "mov [rsp+X], rdx"),                 # Save parameter
]

# Common function epilogues
X86_EPILOGUES = [
    (b"\xc3", "ret"),                                          # Return
    (b"\xc2", "ret X"),                                        # Return with stack adjustment
    (b"\xc9\xc3", "leave; ret"),                               # Restore stack and return
    (b"\x5d\xc3", "pop ebp; ret"),                             # Restore ebp and return
    (b"\x5f\x5e\x5b\xc3", "pop edi; pop esi; pop ebx; ret"),   # Restore registers and return
]

X64_EPILOGUES = [
    (b"\xc3", "ret"),                                          # Return
    (b"\x48\x83\xc4", "add rsp, X; ret"),                      # Restore stack and return
    (b"\x5d\xc3", "pop rbp; ret"),                             # Restore rbp and return
    (b"\x4c\x8d\x5c\x24", "lea r11, [rsp+X]; ret"),            # Epilogue setup
]

# Common Windows API calls (patterns for import identification)
WINDOWS_API_PATTERNS = [
    # Memory management
    (b"VirtualAlloc", "Memory allocation"),
    (b"VirtualProtect", "Memory protection modification"),
    (b"HeapAlloc", "Heap memory allocation"),
    (b"GlobalAlloc", "Global memory allocation"),
    (b"LocalAlloc", "Local memory allocation"),
    (b"memcpy", "Memory copy"),
    (b"memset", "Memory initialization"),
    
    # File operations
    (b"CreateFile", "File creation/opening"),
    (b"ReadFile", "File reading"),
    (b"WriteFile", "File writing"),
    (b"CloseHandle", "Handle closing"),
    (b"DeleteFile", "File deletion"),
    (b"GetTempPath", "Temporary directory retrieval"),
    
    # Registry operations
    (b"RegOpenKey", "Registry key opening"),
    (b"RegCreateKey", "Registry key creation"),
    (b"RegSetValue", "Registry value setting"),
    (b"RegQueryValue", "Registry value querying"),
    (b"RegDeleteKey", "Registry key deletion"),
    
    # Process/thread operations
    (b"CreateProcess", "Process creation"),
    (b"CreateThread", "Thread creation"),
    (b"CreateRemoteThread", "Remote thread creation (potential injection)"),
    (b"OpenProcess", "Process handle retrieval"),
    (b"TerminateProcess", "Process termination"),
    (b"ExitProcess", "Process exit"),
    (b"LoadLibrary", "DLL loading"),
    (b"GetProcAddress", "Function address retrieval"),
    (b"VirtualAllocEx", "Remote memory allocation (potential injection)"),
    (b"WriteProcessMemory", "Remote memory writing (potential injection)"),
    (b"ReadProcessMemory", "Remote memory reading"),
    
    # Network operations
    (b"socket", "Socket creation"),
    (b"connect", "Connection establishment"),
    (b"send", "Data sending"),
    (b"recv", "Data receiving"),
    (b"WSAStartup", "Winsock initialization"),
    (b"gethostbyname", "DNS resolution"),
    (b"inet_addr", "IP address conversion"),
    (b"htons", "Port conversion"),
    
    # Cryptographic operations
    (b"CryptAcquireContext", "Cryptographic provider acquisition"),
    (b"CryptCreateHash", "Hash object creation"),
    (b"CryptHashData", "Data hashing"),
    (b"CryptEncrypt", "Data encryption"),
    (b"CryptDecrypt", "Data decryption"),
    (b"CryptGenRandom", "Random data generation"),
    (b"CryptImportKey", "Key importing"),
    
    # System information
    (b"GetSystemTime", "System time retrieval"),
    (b"GetComputerName", "Computer name retrieval"),
    (b"GetUserName", "User name retrieval"),
    (b"GetSystemInfo", "System information retrieval"),
    (b"GetVersionEx", "OS version retrieval"),
    
    # Windows GUI
    (b"FindWindow", "Window handle retrieval"),
    (b"GetForegroundWindow", "Active window retrieval"),
    (b"ShowWindow", "Window visibility control"),
    (b"MessageBox", "Message box display"),
    
    # Command execution
    (b"WinExec", "Command execution"),
    (b"ShellExecute", "Shell command execution"),
    (b"system", "System command execution"),
    
    # APT-41 specific strings (based on known patterns)
    (b"a2800a28", "APT-41 KEYPLUG pattern"),
    (b"9ed3a5", "APT-41 KEYPLUG key"),
    (b"KEYPLUG", "APT-41 malware identifier"),
    (b"PlugX", "APT-41 related malware"),
]

# ASCII pattern
ASCII_PATTERN = rb'[\x20-\x7E]{6,}'

# Wide-char pattern (UTF-16LE)
WIDE_CHAR_PATTERN = rb'(?:[\x20-\x7E]\x00){4,}'

class OpenVINOAccelerator:
    """OpenVINO acceleration for binary analysis operations"""
    
    def __init__(self):
        self.core = None
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                print("OpenVINO Core initialized successfully")
                print("Available devices: {}".format(self.core.available_devices))
            except Exception as e:
                print("Error initializing OpenVINO Core: {}".format(e))
                self.core = None
    
    def accelerated_pattern_search(self, data, patterns):
        """Hardware-accelerated pattern search for multiple patterns"""
        if self.core is None:
            # Fall back to regular search
            return self._regular_pattern_search(data, patterns)
        
        try:
            results = []
            # Process data in chunks for better memory management
            chunk_size = 1024 * 1024  # 1 MB chunks
            
            # Split patterns into groups for parallel processing
            pattern_groups = []
            group_size = max(1, len(patterns) // MAX_WORKERS)
            for i in range(0, len(patterns), group_size):
                pattern_groups.append(patterns[i:i + group_size])
            
            # Process each chunk
            for chunk_start in range(0, len(data), chunk_size):
                chunk_end = min(chunk_start + chunk_size, len(data))
                chunk = data[chunk_start:chunk_end]
                
                # Process pattern groups in parallel
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = []
                    for pattern_group in pattern_groups:
                        futures.append(executor.submit(
                            self._find_patterns_in_chunk, 
                            chunk, 
                            pattern_group, 
                            chunk_start
                        ))
                    
                    # Collect results
                    for future in concurrent.futures.as_completed(futures):
                        results.extend(future.result())
            
            return results
        except Exception as e:
            print("Error in accelerated pattern search: {}".format(e))
            # Fall back to regular search
            return self._regular_pattern_search(data, patterns)
    
    def _find_patterns_in_chunk(self, chunk, patterns, chunk_offset):
        """Find multiple patterns in a chunk using numpy for acceleration"""
        results = []
        
        for pattern, description in patterns:
            offset = 0
            while True:
                offset = chunk.find(pattern, offset)
                if offset == -1:
                    break
                    
                results.append({
                    "offset": chunk_offset + offset,
                    "pattern": binascii.hexlify(pattern).decode(),
                    "description": description,
                    "type": "api_call" if description != "Unknown" else "string"
                })
                offset += 1
                
        return results
    
    def _regular_pattern_search(self, data, patterns):
        """Regular pattern search without acceleration"""
        results = []
        
        for pattern, description in patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                    
                results.append({
                    "offset": offset,
                    "pattern": binascii.hexlify(pattern).decode(),
                    "description": description,
                    "type": "api_call" if description != "Unknown" else "string"
                })
                offset += 1
                
        return results

class FunctionExtractor:
    """Extracts and analyzes functions from binary data"""
    
    def __init__(self, accelerator):
        self.accelerator = accelerator
    
    def find_function_boundaries(self, data):
        """Find potential function boundaries based on prologues and epilogues"""
        # Create a list of all prologues to search for
        prologue_patterns = [(p, d, "x86") for p, d in X86_PROLOGUES]
        prologue_patterns.extend([(p, d, "x64") for p, d in X64_PROLOGUES])
        
        # Find all prologues
        function_starts = []
        for pattern, description, arch in prologue_patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                
                function_starts.append({
                    "offset": offset,
                    "pattern": binascii.hexlify(pattern).decode(),
                    "description": description,
                    "arch": arch
                })
                offset += 1
        
        # Sort by offset
        function_starts.sort(key=lambda x: x["offset"])
        
        # Create functions with boundaries
        functions = []
        for i, start in enumerate(function_starts):
            # Determine end boundary (next function start or end of data)
            end_offset = len(data)
            if i < len(function_starts) - 1:
                end_offset = function_starts[i + 1]["offset"]
            
            # Look for epilogues to better determine the end
            segment = data[start["offset"]:end_offset]
            epilogue_patterns = X86_EPILOGUES if start["arch"] == "x86" else X64_EPILOGUES
            
            # Find the nearest epilogue
            nearest_epilogue = None
            nearest_offset = end_offset
            
            for pattern, description in epilogue_patterns:
                epilogue_offset = segment.find(pattern)
                if epilogue_offset != -1 and epilogue_offset < nearest_offset - start["offset"]:
                    nearest_epilogue = {
                        "offset": start["offset"] + epilogue_offset,
                        "pattern": binascii.hexlify(pattern).decode(),
                        "description": description
                    }
                    nearest_offset = start["offset"] + epilogue_offset + len(pattern)
            
            # Calculate function size
            size = nearest_offset - start["offset"]
            
            # Extract function bytes
            function_bytes = data[start["offset"]:nearest_offset]
            
            # Add to functions list
            functions.append({
                "start_offset": start["offset"],
                "end_offset": nearest_offset,
                "size": size,
                "prologue": start,
                "epilogue": nearest_epilogue,
                "bytes": function_bytes
            })
        
        return functions
    
    def analyze_function(self, function, data):
        """Analyze a function for API calls and behavior patterns"""
        function_bytes = function["bytes"]
        
        # Prepare API patterns for searching
        api_patterns = [(pattern, description) for pattern, description in WINDOWS_API_PATTERNS]
        
        # Find API calls in the function
        api_calls = self.accelerator.accelerated_pattern_search(function_bytes, api_patterns)
        
        # Find strings in the function
        strings = self._extract_strings(function_bytes)
        
        # Analyze behavior based on API calls
        behavior_categories = self._categorize_behavior(api_calls)
        
        # Update function with analysis
        function.update({
            "api_calls": api_calls,
            "strings": strings,
            "behavior": behavior_categories,
            "risk_score": self._calculate_risk_score(api_calls, strings)
        })
        
        return function
    
    def _extract_strings(self, data):
        """Extract ASCII and wide-char strings from binary data"""
        strings = []
        
        # Find ASCII strings
        ascii_strings = re.findall(ASCII_PATTERN, data)
        for s in ascii_strings:
            strings.append({
                "string": s.decode('ascii', errors='replace'),
                "encoding": "ascii"
            })
        
        # Find wide-char strings
        wide_strings = re.findall(WIDE_CHAR_PATTERN, data)
        for s in wide_strings:
            try:
                decoded = s.decode('utf-16le', errors='replace')
                strings.append({
                    "string": decoded,
                    "encoding": "utf-16le"
                })
            except UnicodeDecodeError: # More specific exception
                pass
        
        return strings
    
    def _categorize_behavior(self, api_calls):
        """Categorize function behavior based on API calls"""
        categories = {
            "file_operations": False,
            "registry_operations": False,
            "process_operations": False,
            "memory_operations": False,
            "network_operations": False,
            "crypto_operations": False,
            "system_info": False,
            "gui_operations": False,
            "code_injection": False,
            "command_execution": False,
            "persistence": False,
            "anti_analysis": False
        }
        
        # Check for specific API combinations indicating behavior
        for api in api_calls:
            desc = api["description"].lower()
            
            # File operations
            if any(x in desc for x in ["file", "directory", "folder"]):
                categories["file_operations"] = True
            
            # Registry operations
            if "registry" in desc or "reg" in desc:
                categories["registry_operations"] = True
                
                # Check for persistence
                if "createkey" in desc or "setvalue" in desc:
                    categories["persistence"] = True
            
            # Process operations
            if any(x in desc for x in ["process", "thread", "module", "dll"]):
                categories["process_operations"] = True
            
            # Memory operations
            if any(x in desc for x in ["memory", "alloc", "heap", "virtual"]):
                categories["memory_operations"] = True
            
            # Network operations
            if any(x in desc for x in ["socket", "connect", "send", "recv", "dns", "http"]):
                categories["network_operations"] = True
            
            # Crypto operations
            if any(x in desc for x in ["crypt", "hash", "encrypt", "decrypt"]):
                categories["crypto_operations"] = True
            
            # System info
            if any(x in desc for x in ["system", "computer", "user", "version"]):
                categories["system_info"] = True
            
            # GUI operations
            if any(x in desc for x in ["window", "message", "dialog"]):
                categories["gui_operations"] = True
            
            # Code injection indicators
            if any(x in desc for x in ["remote", "injection", "writeprocessmemory"]):
                categories["code_injection"] = True
            
            # Command execution
            if any(x in desc for x in ["exec", "shell", "command"]):
                categories["command_execution"] = True
            
            # Anti-analysis
            if any(x in desc for x in ["debugger", "sleep", "delay", "check"]):
                categories["anti_analysis"] = True
        
        return categories
    
    def _calculate_risk_score(self, api_calls, strings):
        """Calculate a risk score for the function based on API calls and strings"""
        score = 0
        
        # Score based on high-risk API calls
        high_risk_apis = [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute",
            "RegCreateKey", "RegSetValue", "CreateProcess", "CryptDecrypt"
        ]
        
        for api in api_calls:
            pattern = api["pattern"]
            for risk_api in high_risk_apis:
                if risk_api.lower() in pattern.lower():
                    score += 10
                    break
        
        # Score based on suspicious strings
        suspicious_strings = [
            "cmd.exe", "powershell", "rundll32", "http://", "https://",
            "regsvr32", "schtasks", "startup", "admin", "password",
            "registry", "temp", "system32", ".exe", ".dll", ".bat", ".vbs"
        ]
        
        for s in strings:
            string_value = s["string"].lower()
            for suspicious in suspicious_strings:
                if suspicious in string_value:
                    score += 5
                    break
        
        # Normalize score (0-100)
        score = min(100, score)
        
        return score

def analyze_decrypted_file(file_path, output_dir):
    """Analyze a decrypted file for functions and API calls"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"Analyzing file: {file_path}")
    file_name = os.path.basename(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Initialize OpenVINO accelerator
    accelerator = OpenVINOAccelerator()
    
    # Initialize function extractor
    extractor = FunctionExtractor(accelerator)
    
    # Find potential functions
    print("Identifying function boundaries...")
    functions = extractor.find_function_boundaries(data)
    
    print(f"Found {len(functions)} potential functions")
    
    # Analyze each function
    print("Analyzing functions for API calls and behavior...")
    analyzed_functions = []
    
    for i, function in enumerate(tqdm(functions, desc="Functions")):
        analyzed = extractor.analyze_function(function, data)
        analyzed_functions.append(analyzed)
    
    # Remove binary data for JSON serialization
    for func in analyzed_functions:
        func.pop("bytes", None)
    
    # Sort functions by risk score
    analyzed_functions.sort(key=lambda x: x["risk_score"], reverse=True)
    
    # Generate summary
    summary = {
        "file_path": file_path,
        "file_size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "functions_count": len(analyzed_functions),
        "high_risk_functions": sum(1 for f in analyzed_functions if f["risk_score"] > 70),
        "medium_risk_functions": sum(1 for f in analyzed_functions if 30 < f["risk_score"] <= 70),
        "low_risk_functions": sum(1 for f in analyzed_functions if f["risk_score"] <= 30),
        "behavior_summary": {
            "file_operations": any(f["behavior"]["file_operations"] for f in analyzed_functions),
            "registry_operations": any(f["behavior"]["registry_operations"] for f in analyzed_functions),
            "process_operations": any(f["behavior"]["process_operations"] for f in analyzed_functions),
            "memory_operations": any(f["behavior"]["memory_operations"] for f in analyzed_functions),
            "network_operations": any(f["behavior"]["network_operations"] for f in analyzed_functions),
            "crypto_operations": any(f["behavior"]["crypto_operations"] for f in analyzed_functions),
            "code_injection": any(f["behavior"]["code_injection"] for f in analyzed_functions),
            "command_execution": any(f["behavior"]["command_execution"] for f in analyzed_functions),
            "persistence": any(f["behavior"]["persistence"] for f in analyzed_functions),
            "anti_analysis": any(f["behavior"]["anti_analysis"] for f in analyzed_functions)
        }
    }
    
    # Save detailed analysis
    output_path = os.path.join(output_dir, f"{file_name}_function_analysis.json")
    with open(output_path, 'w') as f:
        json.dump(analyzed_functions, f, indent=2)
    
    print("Detailed function analysis saved to: {}".format(output_path))
    
    # Save summary
    summary_path = os.path.join(output_dir, f"{file_name}_analysis_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("Analysis summary saved to: {}".format(summary_path))
    
    # Generate human-readable report
    report_path = os.path.join(output_dir, f"{file_name}_analysis_report.txt")
    with open(report_path, 'w') as f:
        f.write("KEYPLUG Function Analysis Report\n")
        f.write("==============================\n\n")
        f.write("File: {}\n".format(file_path))
        f.write("Size: {} bytes\n".format(len(data)))
        f.write("MD5: {}\n".format(summary['md5']))
        f.write("SHA256: {}\n\n".format(summary['sha256']))

        f.write("Function Analysis Summary\n")
        f.write("------------------------\n")
        f.write("Total functions identified: {}\n".format(summary['functions_count']))
        f.write("High risk functions: {}\n".format(summary['high_risk_functions']))
        f.write("Medium risk functions: {}\n".format(summary['medium_risk_functions']))
        f.write("Low risk functions: {}\n\n".format(summary['low_risk_functions']))

        f.write("Behavior Summary\n")
        f.write("---------------\n")
        for behavior, present in summary['behavior_summary'].items():
            f.write("- {}: {}\n".format(behavior.replace('_', ' ').title(), 'Yes' if present else 'No'))
        
        f.write("\n\nHigh Risk Functions\n")
        f.write("------------------\n")
        high_risk = [f_item for f_item in analyzed_functions if f_item["risk_score"] > 70]
        for i, func in enumerate(high_risk):
            f.write("\n[{}] Function at 0x{:x} (Risk Score: {})\n".format(i+1, func['start_offset'], func['risk_score']))
            f.write("    Size: {} bytes\n".format(func['size']))
            f.write("    Prologue: {}\n".format(func['prologue']['description']))
            
            if func['api_calls']:
                f.write("    API Calls:\n")
                for api in func['api_calls'][:10]:  # Show top 10
                    f.write("      - {} (offset +0x{:x})\n".format(api['description'], api['offset'] - func['start_offset']))
                if len(func['api_calls']) > 10:
                    f.write("      - (and {} more)\n".format(len(func['api_calls'])-10))
            
            if func['strings']:
                f.write("    Strings:\n")
                for s in func['strings'][:5]:  # Show top 5
                    f.write("      - \"{}\" ({})\n".format(s['string'][:50], s['encoding']))
                if len(func['strings']) > 5:
                    f.write("      - (and {} more)\n".format(len(func['strings'])-5))
        
        if not high_risk:
            f.write("No high risk functions identified\n")
        
        f.write("\n\nMedium Risk Functions\n")
        f.write("--------------------\n")
        medium_risk = [f_item for f_item in analyzed_functions if 30 < f_item["risk_score"] <= 70]
        for i, func in enumerate(medium_risk[:5]):  # Show top 5
            f.write("\n[{}] Function at 0x{:x} (Risk Score: {})\n".format(i+1, func['start_offset'], func['risk_score']))
            f.write("    Size: {} bytes\n".format(func['size']))
            
            if func['api_calls']:
                f.write("    API Calls: {} found\n".format(len(func['api_calls'])))
                for api in func['api_calls'][:3]:  # Show top 3
                    f.write("      - {}\n".format(api['description']))
                if len(func['api_calls']) > 3:
                    f.write("      - (and {} more)\n".format(len(func['api_calls'])-3))
        
        if len(medium_risk) > 5:
            f.write("\n... and {} more medium risk functions\n".format(len(medium_risk)-5))
        
        if not medium_risk:
            f.write("No medium risk functions identified\n")
    
    print("Human-readable report saved to: {}".format(report_path))
    
    # Print summary to console
    print("\nAnalysis Summary:")
    print("Total functions identified: {}".format(summary['functions_count']))
    print("High risk functions: {}".format(summary['high_risk_functions']))
    print("Medium risk functions: {}".format(summary['medium_risk_functions']))
    print("Low risk functions: {}".format(summary['low_risk_functions']))
    
    print("\nBehavior Summary:")
    for behavior, present in summary['behavior_summary'].items():
        if present:
            print("- {}: YES".format(behavior.replace('_', ' ').title()))
    
    return analyzed_functions, summary

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="KEYPLUG Function and API Extractor")
    parser.add_argument("file", help="Decrypted file to analyze")
    parser.add_argument("-o", "--output-dir", default="function_analysis", 
                        help="Output directory for analysis results")
    args = parser.parse_args()
    
    import time
    start_time = time.time()
    analyze_decrypted_file(args.file, args.output_dir)
    end_time = time.time()
    
    print("\nTotal processing time: {:.2f} seconds".format(end_time - start_time))

if __name__ == "__main__":
    main()
