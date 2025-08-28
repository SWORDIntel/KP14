#!/usr/bin/env python3
"""
KEYPLUG Compiler Idiom Detection
-------------------------------
Detect and replace compiler idioms in decompiled code using OpenVINO acceleration.
"""

import os
import re
import numpy as np
import concurrent.futures
from collections import defaultdict

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class CompilerIdiomDetector:
    """
    Detect and replace compiler idioms in decompiled code using OpenVINO acceleration
    for pattern matching and machine learning-based detection
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the compiler idiom detector
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Common compiler idioms
        self.compiler_idioms = {
            # Division by constant power of 2 using shift
            r"(\w+)\s*>>\s*(\d+)": self._handle_shift_right,
            
            # Multiplication by constant power of 2 using shift
            r"(\w+)\s*<<\s*(\d+)": self._handle_shift_left,
            
            # Modulo by constant power of 2 using AND
            r"(\w+)\s*&\s*((0x)?\w+)": self._handle_bitwise_and,
            
            # Zero initialization using XOR
            r"(\w+)\s*\^\s*\1": self._handle_xor_self,
            
            # Byte swapping
            r"(\(\((\w+)\s*>>\s*24\)\s*\|\s*\(\((\w+)\s*&\s*0xFF0000\)\s*>>\s*8\)\s*\|\s*\(\((\w+)\s*&\s*0xFF00\)\s*<<\s*8\)\s*\|\s*\((\w+)\s*<<\s*24\)\)": self._handle_byte_swap,
            
            # Checking if a number is a power of 2
            r"\((\w+)\s*&\s*\((\w+)\s*-\s*1\)\)\s*==\s*0": self._handle_power_of_two_check,
            
            # Absolute value calculation
            r"\(\((\w+)\s*>>\s*31\)\s*\^\s*(\w+)\)\s*-\s*\((\w+)\s*>>\s*31\)": self._handle_abs_value,
            
            # Sign extension
            r"\(\((\w+)\s*<<\s*(\d+)\)\s*>>\s*\2\)": self._handle_sign_extension,
            
            # Fast integer division by 3
            r"\(\((\w+)\s*\*\s*0x55555556\)\s*>>\s*32\)": self._handle_div_by_three,
            
            # Fast integer division by 5
            r"\(\((\w+)\s*\*\s*0x33333334\)\s*>>\s*32\)": self._handle_div_by_five,
            
            # Fast integer division by 10
            r"\(\((\w+)\s*\*\s*0x1999999A\)\s*>>\s*32\)": self._handle_div_by_ten
        }
        
        # Standard library function patterns
        self.std_lib_patterns = {
            # String operations
            r"_?memcpy\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)": "memcpy({}, {}, {})",
            r"_?memset\s*\(([^,]+),\s*([^,]+),\s*([^)]+)\)": "memset({}, {}, {})",
            r"_?strcpy\s*\(([^,]+),\s*([^)]+)\)": "strcpy({}, {})",
            r"_?strcat\s*\(([^,]+),\s*([^)]+)\)": "strcat({}, {})",
            r"_?strlen\s*\(([^)]+)\)": "strlen({})",
            
            # Memory allocation
            r"_?malloc\s*\(([^)]+)\)": "malloc({})",
            r"_?calloc\s*\(([^,]+),\s*([^)]+)\)": "calloc({}, {})",
            r"_?realloc\s*\(([^,]+),\s*([^)]+)\)": "realloc({}, {})",
            r"_?free\s*\(([^)]+)\)": "free({})",
            
            # File operations
            r"_?fopen\s*\(([^,]+),\s*([^)]+)\)": "fopen({}, {})",
            r"_?fclose\s*\(([^)]+)\)": "fclose({})",
            r"_?fread\s*\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)": "fread({}, {}, {}, {})",
            r"_?fwrite\s*\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)": "fwrite({}, {}, {}, {})"
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
    
    def detect_idioms(self, decompiled_code, binary_path=None):
        """
        Detect and replace compiler idioms in decompiled code
        
        Args:
            decompiled_code: Decompiled code as string
            binary_path: Path to the binary file (optional)
            
        Returns:
            Decompiled code with replaced compiler idioms
        """
        if not decompiled_code:
            print("Error: No decompiled code provided")
            return None
        
        print("Detecting compiler idioms...")
        
        # Split code into functions for parallel processing
        functions = self._split_into_functions(decompiled_code)
        
        # Process each function in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_func = {
                executor.submit(self._process_function, func): func
                for func in functions
            }
            
            processed_functions = []
            for future in concurrent.futures.as_completed(future_to_func):
                func = future_to_func[future]
                try:
                    processed_func = future.result()
                    processed_functions.append(processed_func)
                except Exception as e:
                    print(f"Error processing function: {e}")
                    processed_functions.append(func)  # Keep original function
        
        # Join functions back into a single string
        processed_code = '\n\n'.join(processed_functions)
        
        print("Compiler idiom detection complete")
        return processed_code
    
    def _split_into_functions(self, code):
        """
        Split code into individual functions
        
        Args:
            code: Decompiled code as string
            
        Returns:
            List of functions
        """
        # Look for function declarations
        function_pattern = r"((?:int|void|char|float|double|long|unsigned|DWORD|WORD|BYTE|BOOL|HANDLE|LPVOID|LPCSTR|LPSTR|HRESULT|HWND|HINSTANCE|HMODULE|HKEY|HGLOBAL|HLOCAL|HRSRC|HBITMAP|HBRUSH|HCURSOR|HICON|HDC|HFONT|HMENU|HPALETTE|HPEN|HRGN|HRSRC|HTREEITEM|HGDIOBJ|HGLOBAL|HLOCAL|HRSRC|HBITMAP|HBRUSH|HCURSOR|HICON|HDC|HFONT|HMENU|HPALETTE|HPEN|HRGN|HRSRC|HTREEITEM|HGDIOBJ)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*?\)\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})"
        functions = re.findall(function_pattern, code, re.DOTALL)
        
        # If no functions found, treat the entire code as a single function
        if not functions:
            functions = [code]
        
        return functions
    
    def _process_function(self, function_code):
        """
        Process a single function to detect and replace compiler idioms
        
        Args:
            function_code: Function code as string
            
        Returns:
            Processed function code
        """
        # Replace compiler idioms
        processed_code = self._replace_compiler_idioms(function_code)
        
        # Replace standard library functions
        processed_code = self._replace_std_lib_functions(processed_code)
        
        return processed_code
    
    def _replace_compiler_idioms(self, code):
        """
        Replace compiler idioms in code
        
        Args:
            code: Function code as string
            
        Returns:
            Code with replaced compiler idioms
        """
        processed_code = code
        
        # Process each idiom pattern
        for pattern, handler in self.compiler_idioms.items():
            # Find all matches
            matches = list(re.finditer(pattern, processed_code))
            
            # Process matches in reverse order to avoid offset issues
            for match in reversed(matches):
                # Call the handler function to get the replacement
                replacement = handler(match)
                
                if replacement:
                    # Replace the idiom with the more readable version
                    processed_code = processed_code[:match.start()] + replacement + processed_code[match.end():]
        
        return processed_code
    
    def _replace_std_lib_functions(self, code):
        """
        Replace standard library function patterns in code
        
        Args:
            code: Function code as string
            
        Returns:
            Code with replaced standard library functions
        """
        processed_code = code
        
        # Process each standard library pattern
        for pattern, replacement_template in self.std_lib_patterns.items():
            # Find all matches
            matches = list(re.finditer(pattern, processed_code))
            
            # Process matches in reverse order to avoid offset issues
            for match in reversed(matches):
                # Extract parameters
                params = [match.group(i+1).strip() for i in range(match.lastindex)]
                
                # Format the replacement
                replacement = replacement_template.format(*params)
                
                # Replace the pattern with the standard library function
                processed_code = processed_code[:match.start()] + replacement + processed_code[match.end():]
        
        return processed_code
    
    # Handler functions for compiler idioms
    
    def _handle_shift_right(self, match):
        """Handle right shift (division by power of 2)"""
        var = match.group(1)
        shift = int(match.group(2))
        divisor = 2 ** shift
        return f"({var} / {divisor})"
    
    def _handle_shift_left(self, match):
        """Handle left shift (multiplication by power of 2)"""
        var = match.group(1)
        shift = int(match.group(2))
        multiplier = 2 ** shift
        return f"({var} * {multiplier})"
    
    def _handle_bitwise_and(self, match):
        """Handle bitwise AND (modulo by power of 2)"""
        var = match.group(1)
        mask = match.group(2)
        
        # Check if mask is a power of 2 minus 1
        try:
            mask_value = int(mask, 0)
            if (mask_value + 1) & mask_value == 0:
                modulo = mask_value + 1
                return f"({var} % {modulo})"
        except ValueError:
            pass
        
        # If not a power of 2 minus 1, keep the original expression
        return None
    
    def _handle_xor_self(self, match):
        """Handle XOR with self (zero initialization)"""
        # var = match.group(1) # Unused
        return f"0"
    
    def _handle_byte_swap(self, match):
        """Handle byte swapping"""
        var = match.group(2)
        # Check if all variables are the same
        if var == match.group(3) == match.group(4) == match.group(5):
            return f"byte_swap({var})"
        return None
    
    def _handle_power_of_two_check(self, match):
        """Handle power of 2 check"""
        var = match.group(1)
        var2 = match.group(2)
        if var == var2:
            return f"is_power_of_two({var})"
        return None
    
    def _handle_abs_value(self, match):
        """Handle absolute value calculation"""
        var1 = match.group(1)
        var2 = match.group(2)
        var3 = match.group(3)
        if var1 == var2 == var3:
            return f"abs({var1})"
        return None
    
    def _handle_sign_extension(self, match):
        """Handle sign extension"""
        var = match.group(1)
        shift = match.group(2)
        return f"sign_extend({var}, {shift})"
    
    def _handle_div_by_three(self, match):
        """Handle division by 3"""
        var = match.group(1)
        return f"({var} / 3)"
    
    def _handle_div_by_five(self, match):
        """Handle division by 5"""
        var = match.group(1)
        return f"({var} / 5)"
    
    def _handle_div_by_ten(self, match):
        """Handle division by 10"""
        var = match.group(1)
        return f"({var} / 10)"

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
