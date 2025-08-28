#!/usr/bin/env python3
"""
KEYPLUG Type Inference Engine
----------------------------
Infer types in decompiled code using OpenVINO acceleration.
"""

import os
import re
import tempfile
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, Optional # F401 unused 'Dict', 'Any', 'Optional'

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False
    
# Try to import TypePropagator for advanced type propagation
try:
    from type_propagation import TypePropagator
    TYPE_PROPAGATOR_AVAILABLE = True
except ImportError:
    TYPE_PROPAGATOR_AVAILABLE = False
    print("WARNING: TypePropagator not available. Advanced type propagation disabled.")

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class TypeInferenceEngine:
    """
    Infer types in decompiled code using OpenVINO acceleration
    for pattern matching and machine learning-based inference
    """
    
    def __init__(self, use_openvino=True, logger=None):
        """
        Initialize the type inference engine
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
            logger: Logger instance for logging
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        self.logger = logger
        
        # Initialize TypePropagator if available
        self.type_propagator = None
        if TYPE_PROPAGATOR_AVAILABLE:
            self.type_propagator = TypePropagator(logger=logger)
        
        # Common Windows API function signatures
        self.win_api_signatures = {
            "CreateFileA": {
                "return_type": "HANDLE",
                "params": [
                    {"name": "lpFileName", "type": "LPCSTR"},
                    {"name": "dwDesiredAccess", "type": "DWORD"},
                    {"name": "dwShareMode", "type": "DWORD"},
                    {"name": "lpSecurityAttributes", "type": "LPSECURITY_ATTRIBUTES"},
                    {"name": "dwCreationDisposition", "type": "DWORD"},
                    {"name": "dwFlagsAndAttributes", "type": "DWORD"},
                    {"name": "hTemplateFile", "type": "HANDLE"}
                ]
            },
            "ReadFile": {
                "return_type": "BOOL",
                "params": [
                    {"name": "hFile", "type": "HANDLE"},
                    {"name": "lpBuffer", "type": "LPVOID"},
                    {"name": "nNumberOfBytesToRead", "type": "DWORD"},
                    {"name": "lpNumberOfBytesRead", "type": "LPDWORD"},
                    {"name": "lpOverlapped", "type": "LPOVERLAPPED"}
                ]
            },
            "WriteFile": {
                "return_type": "BOOL",
                "params": [
                    {"name": "hFile", "type": "HANDLE"},
                    {"name": "lpBuffer", "type": "LPCVOID"},
                    {"name": "nNumberOfBytesToWrite", "type": "DWORD"},
                    {"name": "lpNumberOfBytesWritten", "type": "LPDWORD"},
                    {"name": "lpOverlapped", "type": "LPOVERLAPPED"}
                ]
            },
            "VirtualAlloc": {
                "return_type": "LPVOID",
                "params": [
                    {"name": "lpAddress", "type": "LPVOID"},
                    {"name": "dwSize", "type": "SIZE_T"},
                    {"name": "flAllocationType", "type": "DWORD"},
                    {"name": "flProtect", "type": "DWORD"}
                ]
            },
            "VirtualFree": {
                "return_type": "BOOL",
                "params": [
                    {"name": "lpAddress", "type": "LPVOID"},
                    {"name": "dwSize", "type": "SIZE_T"},
                    {"name": "dwFreeType", "type": "DWORD"}
                ]
            }
        }
        
        # Common type patterns
        self.type_patterns = {
            # Variable declarations
            r"(int|char|short|long|float|double|void|unsigned|DWORD|WORD|BYTE)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;": "variable_declaration",
            # Function declarations
            r"(int|char|short|long|float|double|void|unsigned|DWORD|WORD|BYTE)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(": "function_declaration",
            # Pointer declarations
            r"(int|char|short|long|float|double|void|unsigned|DWORD|WORD|BYTE)\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;": "pointer_declaration",
            # Array declarations
            r"(int|char|short|long|float|double|void|unsigned|DWORD|WORD|BYTE)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[": "array_declaration"
        }
        
        # Type inference rules
        self.type_inference_rules = {
            # String operations suggest char* type
            r"str(cpy|cat|str|chr|rchr|tok|len)": "char*",
            # Memory operations suggest void* type
            r"mem(cpy|set|move|cmp)": "void*",
            # File operations suggest FILE* type
            r"f(open|close|read|write|seek|tell|eof)": "FILE*",
            # Integer operations suggest int type
            r"(atoi|itoa|strtol)": "int",
            # Float operations suggest float/double type
            r"(atof|strtod)": "double"
        }
        
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
    
    def infer_types(self, decompiled_code, binary_path=None, signature_data_path=None):
        """
        Infer types in decompiled code using both pattern matching and advanced type propagation
        
        Args:
            decompiled_code: Decompiled code as string or path to decompiled code file
            binary_path: Path to the binary file (optional)
            signature_data_path: Path to function signature data in JSON format (optional)
            
        Returns:
            Decompiled code with inferred types
        """
        if not decompiled_code:
            print("Error: No decompiled code provided")
            return None
        
        print("Inferring types in decompiled code...")
        
        # Check if decompiled_code is a string or a file path
        is_file_path = not decompiled_code.strip().startswith('{')
        decompiled_code_path = None
        temp_dir = None
        
        # If it's a string but not a file path, create a temporary file
        if not is_file_path and not os.path.exists(decompiled_code):
            temp_dir = tempfile.TemporaryDirectory()
            decompiled_code_path = Path(temp_dir.name) / "decompiled_code.c"
            with open(decompiled_code_path, 'w') as f:
                f.write(decompiled_code)
        else:
            decompiled_code_path = decompiled_code if is_file_path else decompiled_code
        
        # Extract existing type information using pattern matching
        existing_types = self._extract_existing_types(decompiled_code)
        
        # Use advanced type propagation if available
        propagated_types = {}
        if self.type_propagator and decompiled_code_path:
            print("Using advanced type propagation...")
            propagation_results = self.type_propagator.propagate_types(
                decompiled_code_path=str(decompiled_code_path),
                signature_data_path=signature_data_path,
                existing_types=existing_types
            )
            propagated_types = propagation_results.get("inferred_types", {})        
            print(f"Type propagation identified {len(propagated_types)} types")
        
        # Infer types using pattern matching as a fallback
        inferred_types = self._infer_types_from_patterns(decompiled_code, existing_types)
        
        # Infer types from API calls
        api_types = self._infer_types_from_api_calls(decompiled_code)
        
        # Merge all type information with propagated types taking precedence
        all_types = {**existing_types, **inferred_types, **api_types, **propagated_types}
        
        # If we read from a file, make sure we have the content as a string for applying types
        if is_file_path and os.path.exists(decompiled_code_path):
            with open(decompiled_code_path, 'r') as f:
                decompiled_code = f.read()
        
        # Apply inferred types to the code
        typed_code = self._apply_types(decompiled_code, all_types)
        
        # Clean up temporary files if created
        if temp_dir:
            temp_dir.cleanup()
        
        print(f"Inferred types for {len(all_types)} variables/functions")
        return typed_code
    
    def _extract_existing_types(self, code):
        """
        Extract existing type information from decompiled code
        
        Args:
            code: Decompiled code as string
            
        Returns:
            Dictionary mapping variable/function names to types
        """
        types = {}
        
        # Process code in parallel for better performance
        lines = code.split('\n')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_line = {
                executor.submit(self._extract_type_from_line, line): line
                for line in lines
            }
            
            for future in concurrent.futures.as_completed(future_to_line):
                # line_data = future_to_line[future] # Original line, kept for context if needed for debugging
                try:
                    name, type_info = future.result()
                    if name and type_info:
                        types[name] = type_info
                except Exception as e:
                    # print(f"Error extracting type from line '{line_data}': {e}") # Example with more context
                    print(f"Error extracting type from line: {e}")
        
        return types
    
    def _extract_type_from_line(self, line):
        """
        Extract type information from a single line of code
        
        Args:
            line: Line of code
            
        Returns:
            Tuple of (name, type)
        """
        # Check each type pattern
        for pattern, pattern_type in self.type_patterns.items():
            match = re.search(pattern, line)
            if match:
                type_name = match.group(1)
                var_name = match.group(2)
                
                # Handle pointers
                if '*' in line and '*' not in type_name:
                    type_name += '*'
                
                return var_name, type_name
        
        return None, None
    
    def _infer_types_from_patterns(self, code, existing_types):
        """
        Infer types using pattern matching
        
        Args:
            code: Decompiled code as string
            existing_types: Dictionary of existing types
            
        Returns:
            Dictionary of inferred types
        """
        inferred_types = {}
        
        # Process each type inference rule
        for pattern, type_name in self.type_inference_rules.items():
            # Find all occurrences of the pattern
            matches = re.finditer(pattern, code)
            
            for match in matches:
                # Find variable name associated with this pattern
                # This is a simplified approach - in a real implementation,
                # we would use more sophisticated analysis
                line_start = code.rfind('\n', 0, match.start()) + 1
                line_end = code.find('\n', match.end())
                line = code[line_start:line_end]
                
                # Look for variable assignments
                var_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=', line)
                if var_match:
                    var_name = var_match.group(1)
                    
                    # Only add if not already typed
                    if var_name not in existing_types:
                        inferred_types[var_name] = type_name
        
        return inferred_types
    
    def _infer_types_from_api_calls(self, code):
        """
        Infer types from API calls
        
        Args:
            code: Decompiled code as string
            
        Returns:
            Dictionary of inferred types
        """
        api_types = {}
        
        # Look for API calls
        for api_name, signature in self.win_api_signatures.items():
            # Find all calls to this API
            api_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*' + api_name + r'\s*\('
            matches = re.finditer(api_pattern, code)
            
            for match in matches:
                var_name = match.group(1)
                api_types[var_name] = signature["return_type"]
                
                # Also try to infer parameter types
                # This is a simplified approach - in a real implementation,
                # we would use more sophisticated analysis
                line_start = code.rfind('\n', 0, match.start()) + 1
                line_end = code.find('\n', match.end())
                line = code[line_start:line_end]
                
                # Extract parameters
                params_start = line.find('(', line.find(api_name)) + 1
                params_end = line.find(')', params_start)
                if params_start > 0 and params_end > params_start:
                    params = line[params_start:params_end].split(',')
                    
                    # Match parameters with signature
                    for i, param in enumerate(params):
                        if i < len(signature["params"]):
                            param = param.strip()
                            
                            # Look for variable names
                            var_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)', param)
                            if var_match:
                                param_name = var_match.group(1)
                                param_type = signature["params"][i]["type"]
                                api_types[param_name] = param_type
        
        return api_types
    
    def _apply_types(self, code, types):
        """
        Apply inferred types to the code
        
        Args:
            code: Decompiled code as string
            types: Dictionary mapping variable/function names to types
            
        Returns:
            Code with inferred types
        """
        # Split code into lines for easier processing
        lines = code.split('\n')
        typed_lines = []
        
        # Process each line
        for line in lines:
            # Skip lines that already have type declarations
            if any(re.search(pattern, line) for pattern in self.type_patterns.keys()):
                typed_lines.append(line)
                continue
            
            # Look for variable declarations without types
            var_match = re.search(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=', line)
            if var_match:
                var_name = var_match.group(1)
                
                # Check if we have a type for this variable
                type_key = var_name
                scoped_name = None
                
                # Look for function-scoped variables (format: function::variable)
                for key in types.keys():
                    if '::' in key and key.split('::')[-1] == var_name:
                        # Check if we're in this function's scope by looking for function name
                        func_name = key.split('::')[0]
                        # Simple heuristic: if the function name appears in previous 50 lines, consider it in scope
                        # In a real implementation, this would use proper scope analysis
                        if func_name in '\n'.join(typed_lines[-50:]):
                            scoped_name = key
                            break
                
                if scoped_name and scoped_name in types:
                    type_key = scoped_name
                
                if type_key in types:
                    # Replace the line with a typed declaration
                    indent = line[:line.find(var_name)]
                    new_line = f"{indent}{types[type_key]} {var_name}{line[line.find('='):]}"
                    typed_lines.append(new_line)
                else:
                    typed_lines.append(line)
            else:
                typed_lines.append(line)
        
        # Join lines back into a single string
        return '\n'.join(typed_lines)

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
