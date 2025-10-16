#!/usr/bin/env python3
"""
KEYPLUG PEB Traversal Detector
------------------------------
Specialized module for detecting Process Environment Block (PEB) traversal patterns
in malware using OpenVINO hardware acceleration for maximum performance.

This technique is commonly used by malware to find loaded modules and their export
tables without using easily detectable GetProcAddress/LoadLibrary calls.
"""
import os
import sys
import struct
import binascii
import re
import json
import time
import numpy as np
import concurrent.futures
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from tqdm import tqdm

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - falling back to CPU-only processing")

# Maximize CPU utilization
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

# PEB access patterns
# x86 PEB access patterns (FS:[0x30])
X86_PEB_PATTERNS = [
    (b"\x64\xA1\x30\x00\x00\x00", "mov eax, fs:[30h]"),
    (b"\x64\x8B\x1D\x30\x00\x00\x00", "mov ebx, fs:[30h]"),
    (b"\x64\x8B\x0D\x30\x00\x00\x00", "mov ecx, fs:[30h]"),
    (b"\x64\x8B\x15\x30\x00\x00\x00", "mov edx, fs:[30h]"),
    (b"\x64\x8B\x35\x30\x00\x00\x00", "mov esi, fs:[30h]"),
    (b"\x64\x8B\x3D\x30\x00\x00\x00", "mov edi, fs:[30h]"),
    # Alternative encodings
    (b"\x64\x67\x8B\x1E\x30\x00\x00\x00", "mov ebx, fs:[30h] (alt encoding)"),
    (b"\x64\xFF\x35\x30\x00\x00\x00", "push dword ptr fs:[30h]"),
]

# x64 PEB access patterns (GS:[0x60])
X64_PEB_PATTERNS = [
    (b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00", "mov rax, gs:[60h]"),
    (b"\x65\x48\x8B\x1C\x25\x60\x00\x00\x00", "mov rbx, gs:[60h]"),
    (b"\x65\x48\x8B\x0C\x25\x60\x00\x00\x00", "mov rcx, gs:[60h]"),
    (b"\x65\x48\x8B\x14\x25\x60\x00\x00\x00", "mov rdx, gs:[60h]"),
    (b"\x65\x48\x8B\x34\x25\x60\x00\x00\x00", "mov rsi, gs:[60h]"),
    (b"\x65\x48\x8B\x3C\x25\x60\x00\x00\x00", "mov rdi, gs:[60h]"),
    # Alternative encodings
    (b"\x65\x4C\x8B\x1C\x25\x60\x00\x00\x00", "mov r11, gs:[60h]"),
    (b"\x65\x4C\x8B\x14\x25\x60\x00\x00\x00", "mov r10, gs:[60h]"),
]

# WOW64 transition (x86 on x64)
WOW64_PATTERNS = [
    (b"\x64\x8B\x0D\x30\x00\x00\x00\x8B\x41", "WOW64 PEB access"),
    (b"\x64\xA1\x30\x00\x00\x00\x8B\x40", "WOW64 PEB access alt"),
]

# Common PEB offsets that malware accesses after getting PEB pointer
PEB_OFFSETS = {
    # _PEB structure offsets (x86/x64)
    0x00C: "PEB.Ldr",                         # Pointer to PEB_LDR_DATA
    0x010: "PEB.InLoadOrderModuleList",       # Start of module list
    0x014: "PEB.InMemoryOrderModuleList",     # Alternative module list
    0x01C: "PEB.OSMajorVersion",              # OS version check (common in VM detection)
    0x020: "PEB.OSMinorVersion",              # OS version check
    0x068: "PEB.NtGlobalFlag",                # Debugger detection
    
    # _PEB_LDR_DATA offsets
    0x00C: "Ldr.InLoadOrderModuleList",       # Module linked list
    0x014: "Ldr.InMemoryOrderModuleList",     # Module linked list (alt)
    0x01C: "Ldr.InInitializationOrderModuleList", # Module linked list (alt)
    
    # _LDR_DATA_TABLE_ENTRY offsets
    0x010: "LdrEntry.InMemoryOrderLinks",     # Link to next module
    0x018: "LdrEntry.InInitializationOrderLinks", # Link to next module (alt)
    0x020: "LdrEntry.DllBase",                # Base address of the DLL
    0x024: "LdrEntry.EntryPoint",             # Entry point of the DLL
    0x028: "LdrEntry.SizeOfImage",            # Size of the DLL image
    0x02C: "LdrEntry.FullDllName",            # Full path of the DLL
    0x038: "LdrEntry.BaseDllName",            # Name of the DLL
    
    # PE header offsets (commonly accessed after finding DLL base)
    0x03C: "DosHeader.e_lfanew",              # Offset to PE header
    0x078: "PEHeader.ExportDirectoryRVA",     # RVA of export directory
    0x088: "PEHeader.ImportDirectoryRVA",     # RVA of import directory
}

# Patterns that often follow PEB access (for context analysis)
FOLLOW_UP_PATTERNS = [
    (b"\x8B\x40", "mov eax, [eax+XX]"),       # Access field in PEB
    (b"\x8B\x48", "mov ecx, [eax+XX]"),       # Access field in PEB
    (b"\x8B\x50", "mov edx, [eax+XX]"),       # Access field in PEB
    (b"\x8B\x80", "mov eax, [eax+XXXX]"),     # Access field in PEB (large offset)
    (b"\x8B\x88", "mov ecx, [eax+XXXX]"),     # Access field in PEB (large offset)
    (b"\x8B\x90", "mov edx, [eax+XXXX]"),     # Access field in PEB (large offset)
    (b"\x8B\xB0", "mov esi, [eax+XXXX]"),     # Access field in PEB (large offset)
    (b"\x8B\xB8", "mov edi, [eax+XXXX]"),     # Access field in PEB (large offset)
    (b"\x83\xB8", "cmp dword ptr [eax+XX], immediate"), # Common debugger check
    (b"\x74", "je XX"),                        # Common conditional after flag check
    (b"\x75", "jne XX"),                       # Common conditional after flag check
    (b"\xEB", "jmp XX"),                       # Common jump after check
]

# Common hash computation patterns that follow PEB traversal
HASH_PATTERNS = [
    (b"\x33\xC0", "xor eax, eax - hash init"),
    (b"\x33\xDB", "xor ebx, ebx - hash init"),
    (b"\xB8\x00\x00\x00\x00", "mov eax, 0 - hash init"),
    (b"\x66\x83\xC0", "add ax, XX - hash computation"),
    (b"\x66\x83\xC3", "add bx, XX - hash computation"),
    (b"\xC1\xC0", "rol eax, XX - hash computation"),
    (b"\xC1\xC8", "ror eax, XX - hash computation"),
    (b"\xC1\xE0", "shl eax, XX - hash computation"),
    (b"\xC1\xE8", "shr eax, XX - hash computation"),
    (b"\x69\xC0", "imul eax, eax, XX - hash computation"),
    (b"\x0F\xB7", "movzx - char extraction for hash"),
]

class OpenVINOAccelerator:
    """OpenVINO acceleration for binary analysis operations"""
    
    def __init__(self):
        self.core = None
        self.devices = []
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                self.devices = self.core.available_devices
                print(f"OpenVINO Core initialized successfully")
                print(f"Available devices: {self.devices}")
                
                # Default to CPU
                self.preferred_device = "CPU"
                
                # Try to use more powerful devices if available
                if "GPU" in self.devices:
                    self.preferred_device = "GPU"
                    print("Using GPU acceleration")
                elif "VPU" in self.devices:
                    self.preferred_device = "VPU"
                    print("Using VPU acceleration")
                else:
                    print("Using CPU acceleration")
                    
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.core = None
    
    def accelerated_pattern_search(self, data, patterns):
        """
        Hardware-accelerated pattern search for multiple patterns
        
        Args:
            data: Binary data to search through
            patterns: List of (pattern, description) tuples
            
        Returns:
            List of matches with offsets and descriptions
        """
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
            print(f"Error in accelerated pattern search: {e}")
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
                    "pattern_length": len(pattern)
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
                    "pattern_length": len(pattern)
                })
                offset += 1
                
        return results
    
    def analyze_context(self, data, peb_match, follow_up_patterns, context_size=32):
        """
        Analyze the context around a PEB access to find related instructions
        
        Args:
            data: Binary data
            peb_match: A match from the pattern search
            follow_up_patterns: Patterns to look for after PEB access
            context_size: Number of bytes to check after PEB access
            
        Returns:
            Dict with context analysis results
        """
        # Extract context after PEB access
        offset = peb_match["offset"]
        pattern_len = peb_match["pattern_length"]
        context_end = min(offset + pattern_len + context_size, len(data))
        context_data = data[offset + pattern_len:context_end]
        
        # Look for follow-up patterns
        follow_ups = []
        for pattern, description in follow_up_patterns:
            ctx_offset = 0
            while True:
                ctx_offset = context_data.find(pattern, ctx_offset)
                if ctx_offset == -1:
                    break
                
                # Look for offset byte that follows many of these instructions
                offset_byte = None
                if len(context_data) > ctx_offset + len(pattern):
                    offset_byte = context_data[ctx_offset + len(pattern)]
                
                follow_ups.append({
                    "offset": offset + pattern_len + ctx_offset,
                    "pattern": binascii.hexlify(pattern).decode(),
                    "description": description,
                    "offset_byte": hex(offset_byte) if offset_byte is not None else None
                })
                ctx_offset += 1
        
        # Check if any PEB structure offsets are accessed
        peb_struct_accesses = []
        for ctx_offset in range(len(context_data) - 1):
            # Check for common mov reg, [reg+offset] patterns
            if context_data[ctx_offset] in [0x8B, 0x89, 0x8A, 0x88]:  # MOV instructions
                if ctx_offset + 1 < len(context_data):
                    modrm = context_data[ctx_offset + 1]
                    
                    # Check if this is a register+offset addressing mode
                    if (modrm & 0xC0) == 0x80:  # ModRM with 32-bit displacement
                        if ctx_offset + 6 < len(context_data):
                            offset_bytes = context_data[ctx_offset + 2:ctx_offset + 6]
                            offset_value = struct.unpack("<I", offset_bytes)[0]
                            
                            if offset_value in PEB_OFFSETS:
                                peb_struct_accesses.append({
                                    "offset": offset + pattern_len + ctx_offset,
                                    "instruction": f"mov reg, [reg+0x{offset_value:x}]",
                                    "peb_field": PEB_OFFSETS[offset_value],
                                    "offset_value": offset_value
                                })
                    elif (modrm & 0xC0) == 0x40:  # ModRM with 8-bit displacement
                        if ctx_offset + 3 < len(context_data):
                            offset_value = context_data[ctx_offset + 2]
                            
                            if offset_value in PEB_OFFSETS:
                                peb_struct_accesses.append({
                                    "offset": offset + pattern_len + ctx_offset,
                                    "instruction": f"mov reg, [reg+0x{offset_value:x}]",
                                    "peb_field": PEB_OFFSETS[offset_value],
                                    "offset_value": offset_value
                                })
        
        return {
            "follow_up_instructions": follow_ups,
            "peb_field_accesses": peb_struct_accesses
        }

def analyze_functions_for_peb_traversal(binary_data, functions, accelerator):
    """
    Analyze functions for PEB traversal patterns
    
    Args:
        binary_data: The full binary data
        functions: List of function dictionaries with start_offset and size
        accelerator: OpenVINO accelerator instance
        
    Returns:
        List of PEB traversal instances with context
    """
    peb_traversal_instances = []
    
    # Combine all patterns
    all_patterns = X86_PEB_PATTERNS + X64_PEB_PATTERNS + WOW64_PATTERNS
    
    # Process each function in parallel for maximum performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_func = {}
        for func in functions:
            start = func["start_offset"]
            end = start + func["size"]
            func_data = binary_data[start:end]
            
            future = executor.submit(
                analyze_function_for_peb, 
                func_data, 
                func, 
                start, 
                all_patterns, 
                accelerator
            )
            future_to_func[future] = func
        
        # Collect results
        for future in tqdm(concurrent.futures.as_completed(future_to_func), 
                          total=len(future_to_func),
                          desc="Analyzing functions"):
            func = future_to_func[future]
            try:
                result = future.result()
                if result:
                    peb_traversal_instances.extend(result)
            except Exception as e:
                print(f"Error analyzing function at 0x{func['start_offset']:x}: {e}")
    
    # Sort by offset
    peb_traversal_instances.sort(key=lambda x: x["offset"])
    
    return peb_traversal_instances

def analyze_function_for_peb(func_data, func, func_offset, patterns, accelerator):
    """Analyze a single function for PEB traversal patterns"""
    # Find PEB access patterns
    matches = accelerator.accelerated_pattern_search(func_data, patterns)
    
    if not matches:
        return []
    
    results = []
    for match in matches:
        # Adjust offset to be relative to the full binary
        match["offset"] += func_offset
        
        # Analyze context after PEB access
        context = accelerator.analyze_context(
            func_data, 
            match, 
            FOLLOW_UP_PATTERNS + HASH_PATTERNS
        )
        
        # Create detailed result
        result = {
            "offset": match["offset"],
            "pattern": match["pattern"],
            "description": match["description"],
            "function_offset": func_offset,
            "function_size": func["size"],
            "context": context
        }
        
        results.append(result)
    
    return results

def analyze_binary_for_peb_traversal(file_path, output_dir=None):
    """
    Analyze a binary file for PEB traversal patterns
    
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
    
    print(f"Analyzing file: {file_path}")
    file_name = os.path.basename(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Initialize OpenVINO accelerator for maximum performance
    accelerator = OpenVINOAccelerator()
    
    print("Scanning for PEB traversal patterns...")
    
    # Analyze full binary first (without function boundaries)
    all_patterns = X86_PEB_PATTERNS + X64_PEB_PATTERNS + WOW64_PATTERNS
    
    print("Performing initial PEB pattern scan...")
    raw_matches = accelerator.accelerated_pattern_search(data, all_patterns)
    print(f"Found {len(raw_matches)} potential PEB access patterns")
    
    # Process each match to add context
    print("Analyzing context around PEB accesses...")
    detailed_matches = []
    for match in tqdm(raw_matches, desc="Context analysis"):
        context = accelerator.analyze_context(
            data, 
            match, 
            FOLLOW_UP_PATTERNS + HASH_PATTERNS
        )
        
        match["context"] = context
        detailed_matches.append(match)
    
    # Identify function boundaries using common prologues/epilogues
    # This is a simplified version - in a real tool you'd use the function extractor
    print("Identifying function boundaries...")
    functions = identify_function_boundaries(data)
    print(f"Found {len(functions)} potential functions")
    
    # Analyze functions specifically for PEB traversal
    print("Analyzing functions for PEB traversal patterns...")
    function_analysis = analyze_functions_for_peb_traversal(data, functions, accelerator)
    
    # Prepare final results
    results = {
        "file_path": file_path,
        "file_size": len(data),
        "raw_peb_matches": raw_matches,
        "detailed_matches": detailed_matches,
        "function_analysis": function_analysis,
        "summary": {
            "total_peb_patterns": len(raw_matches),
            "total_functions": len(functions),
            "functions_with_peb": len(set(m["function_offset"] for m in function_analysis)) if function_analysis else 0,
            "peb_with_context": sum(1 for m in detailed_matches if m["context"]["follow_up_instructions"] or m["context"]["peb_field_accesses"]),
            "likely_api_resolution": sum(1 for m in detailed_matches if len(m["context"]["peb_field_accesses"]) > 2)
        }
    }
    
    # Save results if output directory is specified
    if output_dir:
        output_path = os.path.join(output_dir, f"{file_name}_peb_analysis.json")
        with open(output_path, 'w') as f:
            # Convert binary data to hex strings for JSON serialization
            serializable_results = prepare_for_serialization(results)
            json.dump(serializable_results, f, indent=2)
        
        print(f"Analysis results saved to: {output_path}")
        
        # Generate human-readable report
        report_path = os.path.join(output_dir, f"{file_name}_peb_analysis_report.txt")
        generate_report(results, report_path)
        print(f"Human-readable report saved to: {report_path}")
    
    return results

def identify_function_boundaries(data):
    """
    Simple function boundary identification based on common prologues
    
    Note: This is a simplified version. In real usage, you would use the
    more comprehensive function extractor you've already developed.
    """
    # Common function prologues
    prologues = [
        b"\x55\x8b\xec",           # push ebp; mov ebp, esp
        b"\x53\x56\x57",           # push ebx; push esi; push edi
        b"\x56\x57",               # push esi; push edi
        b"\x83\xec",               # sub esp, X
        b"\x81\xec",               # sub esp, XXXX
        b"\x55\x89\xe5",           # push ebp; mov ebp, esp
        b"\x48\x89\x5c\x24",       # mov [rsp+X], rbx
        b"\x48\x83\xec",           # sub rsp, X
        b"\x48\x81\xec",           # sub rsp, XXXX
        b"\x40\x53",               # push rbx
        b"\x40\x55",               # push rbp
        b"\x40\x56",               # push rsi
        b"\x40\x57",               # push rdi
    ]
    
    # Find all prologues
    function_starts = []
    for prologue in prologues:
        offset = 0
        while True:
            offset = data.find(prologue, offset)
            if offset == -1:
                break
            function_starts.append(offset)
            offset += 1
    
    # Sort and deduplicate
    function_starts = sorted(set(function_starts))
    
    # Create functions with estimated boundaries
    functions = []
    for i, start in enumerate(function_starts):
        # Determine end boundary (next function start or end of data)
        end = len(data)
        if i < len(function_starts) - 1:
            end = function_starts[i + 1]
        
        # Limit function size to reasonable maximum
        if end - start > 4096:
            end = start + 4096
        
        functions.append({
            "start_offset": start,
            "size": end - start
        })
    
    return functions

def prepare_for_serialization(obj):
    """Prepare results for JSON serialization by converting binary data to hex"""
    if isinstance(obj, bytes):
        return binascii.hexlify(obj).decode()
    elif isinstance(obj, dict):
        return {k: prepare_for_serialization(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [prepare_for_serialization(item) for item in obj]
    else:
        return obj

def generate_report(results, output_path):
    """Generate a human-readable report of the PEB traversal analysis"""
    with open(output_path, 'w') as f:
        f.write("KEYPLUG PEB Traversal Analysis Report\n")
        f.write("===================================\n\n")
        
        f.write(f"File: {results['file_path']}\n")
        f.write(f"Size: {results['file_size']} bytes\n\n")
        
        f.write("Summary\n")
        f.write("-------\n")
        summary = results['summary']
        f.write(f"Total PEB access patterns found: {summary['total_peb_patterns']}\n")
        f.write(f"Total functions identified: {summary['total_functions']}\n")
        f.write(f"Functions with PEB traversal: {summary['functions_with_peb']}\n")
        f.write(f"PEB accesses with context: {summary['peb_with_context']}\n")
        f.write(f"Likely API resolution techniques: {summary['likely_api_resolution']}\n\n")
        
        f.write("PEB Traversal Details\n")
        f.write("--------------------\n")
        if results['function_analysis']:
            for i, func_analysis in enumerate(results['function_analysis'][:10]):  # Limit to top 10
                f.write(f"\n[{i+1}] Function at 0x{func_analysis['function_offset']:x}\n")
                f.write(f"    PEB access at 0x{func_analysis['offset']:x}: {func_analysis['description']}\n")
                
                if func_analysis['context']['peb_field_accesses']:
                    f.write("    PEB fields accessed:\n")
                    for field in func_analysis['context']['peb_field_accesses']:
                        f.write(f"      - {field['peb_field']} (offset 0x{field['offset_value']:x})\n")
                
                if func_analysis['context']['follow_up_instructions']:
                    f.write("    Follow-up instructions:\n")
                    for instr in func_analysis['context']['follow_up_instructions'][:5]:  # Limit to top 5
                        f.write(f"      - 0x{instr['offset']:x}: {instr['description']}\n")
                    
                    if len(func_analysis['context']['follow_up_instructions']) > 5:
                        f.write(f"      - (and {len(func_analysis['context']['follow_up_instructions'])-5} more)\n")
            
            if len(results['function_analysis']) > 10:
                f.write(f"\n... and {len(results['function_analysis'])-10} more PEB traversal instances\n")
        else:
            f.write("No detailed PEB traversal analysis found in functions.\n")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="KEYPLUG PEB Traversal Detector")
    parser.add_argument("file", help="Binary file to analyze")
    parser.add_argument("-o", "--output-dir", default="peb_analysis", 
                        help="Output directory for analysis results")
    args = parser.parse_args()
    
    start_time = time.time()
    analyze_binary_for_peb_traversal(args.file, args.output_dir)
    end_time = time.time()
    
    print(f"\nTotal processing time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
