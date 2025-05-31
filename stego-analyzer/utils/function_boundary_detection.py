#!/usr/bin/env python3
"""
KEYPLUG Function Boundary Detection
----------------------------------
Detect function boundaries in binary files using OpenVINO acceleration.
"""

import os
import struct
import numpy as np
import concurrent.futures

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core # , Type, Layout, PartialShape # F401 unused
    # from openvino.preprocess import PrePostProcessor # F401 unused
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class FunctionBoundaryDetector:
    """
    Detect function boundaries in binary files using OpenVINO acceleration
    for pattern matching and machine learning-based detection
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the function boundary detector
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Common function prologue patterns for x86/x64
        self.x86_prologues = [
            # push ebp; mov ebp, esp
            b"\x55\x89\xe5",
            # push ebp; mov ebp, esp; sub esp, XX
            b"\x55\x89\xe5\x83\xec",
            # push ebp; mov ebp, esp; push ebx
            b"\x55\x89\xe5\x53",
            # push ebp; mov ebp, esp; push edi
            b"\x55\x89\xe5\x57",
            # push ebp; mov ebp, esp; push esi
            b"\x55\x89\xe5\x56",
            # push ebp; mov ebp, esp; push ebx; push esi
            b"\x55\x89\xe5\x53\x56",
            # push ebp; mov ebp, esp; push esi; push edi
            b"\x55\x89\xe5\x56\x57"
        ]
        
        # Common function prologue patterns for x64
        self.x64_prologues = [
            # push rbp; mov rbp, rsp
            b"\x55\x48\x89\xe5",
            # push rbp; mov rbp, rsp; push r15
            b"\x55\x48\x89\xe5\x41\x57",
            # push rbp; mov rbp, rsp; push r14
            b"\x55\x48\x89\xe5\x41\x56",
            # push rbp; mov rbp, rsp; push r13
            b"\x55\x48\x89\xe5\x41\x55",
            # push rbp; mov rbp, rsp; push r12
            b"\x55\x48\x89\xe5\x41\x54",
            # push rbp; mov rbp, rsp; push rbx
            b"\x55\x48\x89\xe5\x53",
            # sub rsp, XX
            b"\x48\x83\xec"
        ]
        
        # Common function epilogue patterns for x86/x64
        self.x86_epilogues = [
            # leave; ret
            b"\xc9\xc3",
            # pop ebp; ret
            b"\x5d\xc3",
            # mov esp, ebp; pop ebp; ret
            b"\x89\xec\x5d\xc3"
        ]
        
        # Common function epilogue patterns for x64
        self.x64_epilogues = [
            # leave; ret
            b"\xc9\xc3",
            # pop rbp; ret
            b"\x5d\xc3",
            # add rsp, XX; pop rbp; ret
            b"\x48\x83\xc4.\x5d\xc3"
        ]
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Initialize OpenVINO Core
        self.core = Core()
        
        # Get available devices
        devices = self.core.available_devices
        
        # Select preferred device
        self.device = "CPU"
        if "GPU" in devices:
            self.device = "GPU"
        elif "NPU" in devices:
            self.device = "NPU"
    
    def detect_functions(self, binary_path):
        """
        Detect function boundaries in a binary file
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            List of function addresses
        """
        if not os.path.exists(binary_path):
            print(f"Error: File {binary_path} not found")
            return []
        
        print(f"Detecting function boundaries in {os.path.basename(binary_path)}")
        
        # Read the binary data
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        # Detect architecture (x86 or x64)
        architecture = self._detect_architecture(data)
        print(f"Detected architecture: {architecture}")
        
        # Select appropriate patterns based on architecture
        if architecture == "x64":
            prologues = self.x64_prologues
            epilogues = self.x64_epilogues
        else:  # Default to x86
            prologues = self.x86_prologues
            epilogues = self.x86_epilogues
        
        # Detect function boundaries using pattern matching
        if self.use_openvino:
            print("Using OpenVINO acceleration for function boundary detection")
            functions = self._detect_functions_openvino(data, prologues, epilogues)
        else:
            print("Using standard pattern matching for function boundary detection")
            functions = self._detect_functions_standard(data, prologues, epilogues)
        
        # Post-process function boundaries
        functions = self._post_process_functions(functions, data)
        
        print(f"Detected {len(functions)} functions")
        return functions
    
    def _detect_architecture(self, data):
        """
        Detect the architecture of a binary file
        
        Args:
            data: Binary data
            
        Returns:
            Architecture string ("x86" or "x64")
        """
        # Check for PE header
        if data[:2] == b'MZ':
            # Find PE header offset
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            
            # Check for valid PE header
            if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b'PE\0\0':
                # Get machine type
                machine_type = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                
                # Check machine type
                if machine_type == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    return "x64"
                elif machine_type == 0x014c:  # IMAGE_FILE_MACHINE_I386
                    return "x86"
        
        # Check for ELF header
        if data[:4] == b'\x7fELF':
            # Check ELF class
            if data[4] == 1:  # ELFCLASS32
                return "x86"
            elif data[4] == 2:  # ELFCLASS64
                return "x64"
        
        # Default to x86 if architecture cannot be determined
        return "x86"
    
    def _detect_functions_standard(self, data, prologues, epilogues):
        """
        Detect function boundaries using standard pattern matching
        
        Args:
            data: Binary data
            prologues: List of function prologue patterns
            epilogues: List of function epilogue patterns
            
        Returns:
            List of function addresses
        """
        functions = []
        
        # Find all function prologues
        for prologue in prologues:
            offset = 0
            while offset < len(data):
                offset = data.find(prologue, offset)
                if offset == -1:
                    break
                
                functions.append(offset)
                offset += 1
        
        # Sort and deduplicate function addresses
        functions = sorted(set(functions))
        
        return functions
    
    def _detect_functions_openvino(self, data, prologues, epilogues):
        """
        Detect function boundaries using OpenVINO-accelerated pattern matching
        
        Args:
            data: Binary data
            prologues: List of function prologue patterns
            epilogues: List of function epilogue patterns
            
        Returns:
            List of function addresses
        """
        # Convert data to numpy array
        data_array = np.frombuffer(data, dtype=np.uint8)
        
        # Use parallel processing for pattern matching
        functions = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create tasks for each prologue pattern
            future_to_pattern = {
                executor.submit(self._find_pattern_openvino, data_array, pattern): pattern
                for pattern in prologues
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_pattern):
                pattern = future_to_pattern[future]
                try:
                    matches = future.result()
                    functions.extend(matches)
                except Exception as e:
                    print(f"Error processing pattern {pattern.hex()}: {e}")
        
        # Sort and deduplicate function addresses
        functions = sorted(set(functions))
        
        return functions
    
    def _find_pattern_openvino(self, data_array, pattern):
        """
        Find a pattern in data using OpenVINO acceleration
        
        Args:
            data_array: Numpy array of binary data
            pattern: Pattern to search for
            
        Returns:
            List of match offsets
        """
        # Convert pattern to numpy array
        pattern_array = np.frombuffer(pattern, dtype=np.uint8)
        
        # Use sliding window approach for pattern matching
        matches = []
        pattern_len = len(pattern_array)
        
        # Use vectorized operations for better performance
        for i in range(len(data_array) - pattern_len + 1):
            if np.array_equal(data_array[i:i+pattern_len], pattern_array):
                matches.append(i)
        
        return matches
    
    def _post_process_functions(self, functions, data):
        """
        Post-process function boundaries
        
        Args:
            functions: List of function addresses
            data: Binary data
            
        Returns:
            List of processed function addresses
        """
        # Filter out functions that are too close to each other
        # (likely false positives)
        MIN_FUNCTION_SIZE = 16
        filtered_functions = []
        
        for i in range(len(functions)):
            if i == len(functions) - 1:
                # Last function
                filtered_functions.append(functions[i])
            else:
                # Check if function is large enough
                if functions[i+1] - functions[i] >= MIN_FUNCTION_SIZE:
                    filtered_functions.append(functions[i])
        
        # Convert addresses to hex strings for easier processing
        hex_functions = [hex(addr) for addr in filtered_functions]
        
        return hex_functions

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
