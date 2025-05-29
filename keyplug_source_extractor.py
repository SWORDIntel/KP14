#!/usr/bin/env python3
"""
KEYPLUG Source Code Extractor
-----------------------------
Extract and analyze source code from KEYPLUG malware binaries using
OpenVINO acceleration for maximum performance.

This module provides integration with decompilers, advanced pattern matching,
function boundary detection, type inference, and control flow recovery.
"""

import os
import sys
import argparse
import json
import subprocess
import tempfile
import concurrent.futures
import numpy as np
from collections import defaultdict
from datetime import datetime
import time
import shutil
import re

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core, Type, Layout, PartialShape
    from openvino.preprocess import PrePostProcessor
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for source extraction")
    
    # Initialize OpenVINO Core
    core = Core()
    print(f"Available devices: {core.available_devices}")
    
    # Select preferred device
    PREFERRED_DEVICE = "CPU"
    if "GPU" in core.available_devices:
        PREFERRED_DEVICE = "GPU"
        print(f"Using GPU acceleration ({PREFERRED_DEVICE})")
    elif "NPU" in core.available_devices:
        PREFERRED_DEVICE = "NPU"
        print(f"Using NPU acceleration ({PREFERRED_DEVICE})")
    else:
        print(f"Using CPU acceleration ({PREFERRED_DEVICE})")
        
    # Set OpenVINO environment variables for maximum performance
    os.environ["OPENVINO_DEVICE"] = PREFERRED_DEVICE
    os.environ["OPENVINO_THREAD_NUM"] = str(os.cpu_count())
    os.environ["OPENVINO_NUM_STREAMS"] = str(os.cpu_count())
    print(f"OpenVINO configured for maximum performance with {os.cpu_count()} threads")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("WARNING: OpenVINO not available - performance will be degraded")

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

# Module imports
from decompiler_integration import DecompilerIntegration
from function_boundary_detection import FunctionBoundaryDetector
from type_inference import TypeInferenceEngine
from control_flow_recovery import ControlFlowRecovery
from compiler_idiom_detection import CompilerIdiomDetector

class SourceCodeExtractor:
    """
    Extract source code from binary files using OpenVINO acceleration
    for maximum performance
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the source code extractor
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
        
        # Initialize components
        self.decompiler = DecompilerIntegration(use_openvino=self.use_openvino)
        self.boundary_detector = FunctionBoundaryDetector(use_openvino=self.use_openvino)
        self.type_inference = TypeInferenceEngine(use_openvino=self.use_openvino)
        self.control_flow = ControlFlowRecovery(use_openvino=self.use_openvino)
        self.idiom_detector = CompilerIdiomDetector(use_openvino=self.use_openvino)
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Initialize OpenVINO Core
        self.core = Core()
        self.device = PREFERRED_DEVICE
        
        # Set up OpenVINO for pattern matching
        # This is a placeholder for actual OpenVINO model setup
    
    def extract_source_code(self, binary_path, output_dir, decompiler_type="ghidra", 
                            detect_boundaries=True, infer_types=True, 
                            recover_control_flow=True, detect_idioms=True,
                            signature_data_path=None):
        """
        Extract source code from a binary file
        
        Args:
            binary_path: Path to the binary file
            output_dir: Directory to save extracted source code
            decompiler_type: Type of decompiler to use (ghidra, retdec, ida)
            detect_boundaries: Whether to detect function boundaries
            infer_types: Whether to infer types
            recover_control_flow: Whether to recover control flow
            detect_idioms: Whether to detect compiler idioms
            signature_data_path: Path to JSON file containing function signatures (optional)
            
        Returns:
            Path to the extracted source code
        """
        if not os.path.exists(binary_path):
            print(f"Error: File {binary_path} not found")
            return None
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        binary_name = os.path.basename(binary_path)
        print(f"Extracting source code from {binary_name}")
        
        # Create output directory for this binary
        binary_output_dir = os.path.join(output_dir, binary_name + "_source")
        if not os.path.exists(binary_output_dir):
            os.makedirs(binary_output_dir)
        
        # Step 1: Detect function boundaries if requested
        functions = []
        if detect_boundaries:
            print("Detecting function boundaries...")
            functions = self.boundary_detector.detect_functions(binary_path)
            print(f"Detected {len(functions)} functions")
            
            # Save function boundaries
            boundaries_path = os.path.join(binary_output_dir, "function_boundaries.json")
            with open(boundaries_path, 'w') as f:
                json.dump(functions, f, indent=2)
        
        # Step 2: Decompile the binary
        print(f"Decompiling binary using {decompiler_type}...")
        decompiled_code = self.decompiler.decompile(binary_path, binary_output_dir, 
                                                   decompiler_type, functions)
        
        # Step 3: Infer types if requested
        if infer_types and decompiled_code:
            print("Inferring types...")
            typed_code = self.type_inference.infer_types(
                decompiled_code, 
                binary_path,
                signature_data_path=signature_data_path
            )
            
            # Save typed code
            typed_path = os.path.join(binary_output_dir, "typed_code.c")
            with open(typed_path, 'w') as f:
                f.write(typed_code)
        
        # Step 4: Recover control flow if requested
        if recover_control_flow and decompiled_code:
            print("Recovering control flow...")
            structured_code = self.control_flow.recover_control_flow(
                decompiled_code if not infer_types else typed_code, 
                binary_path
            )
            
            # Save structured code
            structured_path = os.path.join(binary_output_dir, "structured_code.c")
            with open(structured_path, 'w') as f:
                f.write(structured_code)
        
        # Step 5: Detect compiler idioms if requested
        if detect_idioms and decompiled_code:
            print("Detecting compiler idioms...")
            final_code = self.idiom_detector.detect_idioms(
                decompiled_code if not (infer_types or recover_control_flow) 
                else (typed_code if not recover_control_flow else structured_code),
                binary_path
            )
            
            # Save final code
            final_path = os.path.join(binary_output_dir, "final_code.c")
            with open(final_path, 'w') as f:
                f.write(final_code)
        
        print(f"Source code extraction complete. Results saved to {binary_output_dir}")
        return binary_output_dir

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="KEYPLUG Source Code Extractor")
    parser.add_argument('-f', '--file', help='Binary file to analyze')
    parser.add_argument('-d', '--dir', help='Directory containing binary files to analyze')
    parser.add_argument('-p', '--pattern', help='File pattern to match in directory', default='*.bin')
    parser.add_argument('-o', '--output', help='Output directory', default='keyplug_source_code')
    parser.add_argument('--decompiler', help='Decompiler to use (ghidra, retdec, ida)', default='ghidra')
    parser.add_argument('--signatures', help='Path to function signatures JSON file for improved type inference')
    parser.add_argument('--no-boundaries', action='store_true', help='Disable function boundary detection')
    parser.add_argument('--no-types', action='store_true', help='Disable type inference')
    parser.add_argument('--no-control-flow', action='store_true', help='Disable control flow recovery')
    parser.add_argument('--no-idioms', action='store_true', help='Disable compiler idiom detection')
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.dir:
        parser.error("Either --file or --dir must be specified")
    
    # Create output directory
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Initialize extractor
    extractor = SourceCodeExtractor(use_openvino=not args.no_openvino)
    
    start_time = time.time()
    
    # Process a single file
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
        
        print(f"[+] Analyzing file: {args.file}")
        output_dir = extractor.extract_source_code(
            args.file,
            args.output,
            decompiler_type=args.decompiler,
            detect_boundaries=not args.no_boundaries,
            infer_types=not args.no_types,
            recover_control_flow=not args.no_control_flow,
            detect_idioms=not args.no_idioms
        )
        
        if not output_dir:
            print(f"Error extracting source code from {args.file}")
            return 1
        
        print(f"[+] Source code extracted to: {output_dir}")
    
    # Process a directory of files
    elif args.dir:
        if not os.path.exists(args.dir):
            print(f"Error: Directory {args.dir} not found")
            return 1
        
        # Find all files matching the pattern
        import glob
        files = glob.glob(os.path.join(args.dir, args.pattern))
        
        if not files:
            print(f"No files matching {args.pattern} found in {args.dir}")
            return 1
        
        print(f"[+] Found {len(files)} files to analyze")
        
        # Process each file
        successful = 0
        failed = 0
        output_dirs = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(
                    extractor.extract_source_code,
                    file_path,
                    args.output,
                    args.decompiler,
                    not args.no_boundaries,
                    not args.no_types,
                    not args.no_control_flow,
                    not args.no_idioms
                ): file_path for file_path in files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    output_dir = future.result()
                    if output_dir:
                        successful += 1
                        output_dirs.append(output_dir)
                    else:
                        failed += 1
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    failed += 1
        
        # Generate summary
        summary = {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "openvino_acceleration": OPENVINO_AVAILABLE and not args.no_openvino,
            "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE and not args.no_openvino else "None",
            "decompiler": args.decompiler,
            "total_files": len(files),
            "successful": successful,
            "failed": failed,
            "output_directories": output_dirs
        }
        
        # Save summary
        summary_path = os.path.join(args.output, "extraction_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Successfully extracted source code from {successful} of {len(files)} files")
        print(f"[+] Summary saved to: {summary_path}")
    
    end_time = time.time()
    print(f"[+] Total execution time: {end_time - start_time:.2f} seconds")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
