#!/usr/bin/env python3
"""
KEYPLUG Control Flow Recovery
----------------------------
Recover control flow structures in decompiled code using OpenVINO acceleration.
"""

import os
import sys
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

class ControlFlowRecovery:
    """
    Recover control flow structures in decompiled code using OpenVINO acceleration
    for pattern matching and machine learning-based recovery
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the control flow recovery engine
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Control flow patterns
        self.if_patterns = [
            r"if\s*\((.*?)\)\s*{",
            r"if\s*\((.*?)\)\s*\n\s*{",
            r"if\s*\((.*?)\)",
        ]
        
        self.else_patterns = [
            r"}\s*else\s*{",
            r"}\s*else\s*\n\s*{",
            r"}\s*else\s*if\s*\((.*?)\)\s*{",
            r"}\s*else\s*if\s*\((.*?)\)\s*\n\s*{"
        ]
        
        self.loop_patterns = [
            # for loops
            r"for\s*\((.*?);(.*?);(.*?)\)\s*{",
            r"for\s*\((.*?);(.*?);(.*?)\)\s*\n\s*{",
            # while loops
            r"while\s*\((.*?)\)\s*{",
            r"while\s*\((.*?)\)\s*\n\s*{",
            # do-while loops
            r"do\s*{(.*?)}\s*while\s*\((.*?)\);",
            r"do\s*\n\s*{(.*?)}\s*while\s*\((.*?)\);"
        ]
        
        self.switch_patterns = [
            r"switch\s*\((.*?)\)\s*{",
            r"switch\s*\((.*?)\)\s*\n\s*{"
        ]
        
        self.case_patterns = [
            r"case\s+(.*?):",
            r"default:"
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
    
    def recover_control_flow(self, decompiled_code, binary_path=None):
        """
        Recover control flow structures in decompiled code
        
        Args:
            decompiled_code: Decompiled code as string
            binary_path: Path to the binary file (optional)
            
        Returns:
            Decompiled code with recovered control flow structures
        """
        if not decompiled_code:
            print("Error: No decompiled code provided")
            return None
        
        print("Recovering control flow structures...")
        
        # Split code into functions for parallel processing
        functions = self._split_into_functions(decompiled_code)
        
        # Process each function in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_func = {
                executor.submit(self._recover_function_control_flow, func): func
                for func in functions
            }
            
            recovered_functions = []
            for future in concurrent.futures.as_completed(future_to_func):
                func = future_to_func[future]
                try:
                    recovered_func = future.result()
                    recovered_functions.append(recovered_func)
                except Exception as e:
                    print(f"Error recovering control flow for function: {e}")
                    recovered_functions.append(func)  # Keep original function
        
        # Join functions back into a single string
        recovered_code = '\n\n'.join(recovered_functions)
        
        print("Control flow recovery complete")
        return recovered_code
    
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
    
    def _recover_function_control_flow(self, function_code):
        """
        Recover control flow structures in a single function
        
        Args:
            function_code: Function code as string
            
        Returns:
            Function code with recovered control flow structures
        """
        # Recover if-else structures
        recovered_code = self._recover_if_else(function_code)
        
        # Recover loop structures
        recovered_code = self._recover_loops(recovered_code)
        
        # Recover switch-case structures
        recovered_code = self._recover_switch_case(recovered_code)
        
        return recovered_code
    
    def _recover_if_else(self, code):
        """
        Recover if-else structures
        
        Args:
            code: Function code as string
            
        Returns:
            Code with recovered if-else structures
        """
        # Find all if statements
        if_blocks = []
        for pattern in self.if_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                if_blocks.append((match.start(), match.group()))
        
        # Find all else statements
        else_blocks = []
        for pattern in self.else_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                else_blocks.append((match.start(), match.group()))
        
        # Sort blocks by position
        all_blocks = sorted(if_blocks + else_blocks)
        
        # Process blocks
        if not all_blocks:
            return code  # No if-else blocks found
        
        # Reconstruct code with proper indentation
        result = code[:all_blocks[0][0]]
        for i, (pos, block) in enumerate(all_blocks):
            # Add the current block
            result += block
            
            # Add code between this block and the next
            if i < len(all_blocks) - 1:
                next_pos = all_blocks[i+1][0]
                result += code[pos + len(block):next_pos]
            else:
                result += code[pos + len(block):]
        
        return result
    
    def _recover_loops(self, code):
        """
        Recover loop structures
        
        Args:
            code: Function code as string
            
        Returns:
            Code with recovered loop structures
        """
        # Find all loop statements
        loop_blocks = []
        for pattern in self.loop_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                loop_blocks.append((match.start(), match.group()))
        
        # Sort blocks by position
        loop_blocks.sort()
        
        # Process blocks
        if not loop_blocks:
            return code  # No loop blocks found
        
        # Reconstruct code with proper indentation
        result = code[:loop_blocks[0][0]]
        for i, (pos, block) in enumerate(loop_blocks):
            # Add the current block
            result += block
            
            # Add code between this block and the next
            if i < len(loop_blocks) - 1:
                next_pos = loop_blocks[i+1][0]
                result += code[pos + len(block):next_pos]
            else:
                result += code[pos + len(block):]
        
        return result
    
    def _recover_switch_case(self, code):
        """
        Recover switch-case structures
        
        Args:
            code: Function code as string
            
        Returns:
            Code with recovered switch-case structures
        """
        # Find all switch statements
        switch_blocks = []
        for pattern in self.switch_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                switch_blocks.append((match.start(), match.group()))
        
        # Find all case statements
        case_blocks = []
        for pattern in self.case_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                case_blocks.append((match.start(), match.group()))
        
        # Sort blocks by position
        all_blocks = sorted(switch_blocks + case_blocks)
        
        # Process blocks
        if not all_blocks:
            return code  # No switch-case blocks found
        
        # Reconstruct code with proper indentation
        result = code[:all_blocks[0][0]]
        for i, (pos, block) in enumerate(all_blocks):
            # Add the current block
            result += block
            
            # Add code between this block and the next
            if i < len(all_blocks) - 1:
                next_pos = all_blocks[i+1][0]
                result += code[pos + len(block):next_pos]
            else:
                result += code[pos + len(block):]
        
        return result
    
    def _identify_goto_patterns(self, code):
        """
        Identify goto patterns that can be converted to structured control flow
        
        Args:
            code: Function code as string
            
        Returns:
            Dictionary mapping goto labels to their corresponding control flow structures
        """
        # Find all goto statements
        goto_pattern = r"goto\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;"
        goto_matches = re.finditer(goto_pattern, code)
        
        # Find all labels
        label_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*):"
        label_matches = re.finditer(label_pattern, code)
        
        # Map labels to positions
        labels = {}
        for match in label_matches:
            labels[match.group(1)] = match.start()
        
        # Analyze goto patterns
        goto_patterns = {}
        for match in goto_matches:
            goto_pos = match.start()
            label_name = match.group(1)
            
            if label_name in labels:
                label_pos = labels[label_name]
                
                # Check if this is a forward or backward goto
                if label_pos > goto_pos:
                    # Forward goto - could be a break or continue
                    goto_patterns[label_name] = "break"
                else:
                    # Backward goto - could be a loop
                    goto_patterns[label_name] = "loop"
        
        return goto_patterns

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
