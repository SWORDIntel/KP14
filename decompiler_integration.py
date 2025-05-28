#!/usr/bin/env python3
"""
KEYPLUG Decompiler Integration
------------------------------
Integration with various decompilers for KEYPLUG malware analysis.
Supports Ghidra, RetDec, and IDA Pro with OpenVINO acceleration.
"""

import os
import sys
import subprocess
import tempfile
import json
import concurrent.futures
import shutil
import time
from pathlib import Path

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
except ImportError:
    OPENVINO_AVAILABLE = False

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class DecompilerIntegration:
    """
    Integration with various decompilers with OpenVINO acceleration
    for parallel processing and optimization
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the decompiler integration
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Check for decompiler installations
        self.ghidra_available = self._check_ghidra()
        self.retdec_available = self._check_retdec()
        self.ida_available = self._check_ida()
        
        # Print available decompilers
        print("Available decompilers:")
        print(f"  - Ghidra: {'Available' if self.ghidra_available else 'Not available'}")
        print(f"  - RetDec: {'Available' if self.retdec_available else 'Not available'}")
        print(f"  - IDA Pro: {'Available' if self.ida_available else 'Not available'}")
    
    def _check_ghidra(self):
        """Check if Ghidra is available"""
        # Look for GHIDRA_HOME environment variable
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home and os.path.exists(ghidra_home):
            return True
            
        # Check common installation paths
        common_paths = [
            "/opt/ghidra",
            "/usr/local/ghidra",
            "/usr/share/ghidra",
            os.path.expanduser("~/ghidra")
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                os.environ["GHIDRA_HOME"] = path
                return True
        
        return False
    
    def _check_retdec(self):
        """Check if RetDec is available"""
        try:
            result = subprocess.run(
                ["retdec-decompiler", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _check_ida(self):
        """Check if IDA Pro is available"""
        # Look for IDA_HOME environment variable
        ida_home = os.environ.get("IDA_HOME")
        if ida_home and os.path.exists(ida_home):
            return True
            
        # Check common installation paths
        common_paths = [
            "/opt/ida",
            "/usr/local/ida",
            os.path.expanduser("~/ida")
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                os.environ["IDA_HOME"] = path
                return True
        
        return False
    
    def decompile(self, binary_path, output_dir, decompiler_type="ghidra", functions=None):
        """
        Decompile a binary file
        
        Args:
            binary_path: Path to the binary file
            output_dir: Directory to save decompiled code
            decompiler_type: Type of decompiler to use (ghidra, retdec, ida)
            functions: List of function addresses to decompile (optional)
            
        Returns:
            Decompiled code as string
        """
        if not os.path.exists(binary_path):
            print(f"Error: File {binary_path} not found")
            return None
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Choose decompiler based on type and availability
        if decompiler_type == "ghidra" and self.ghidra_available:
            return self._decompile_with_ghidra(binary_path, output_dir, functions)
        elif decompiler_type == "retdec" and self.retdec_available:
            return self._decompile_with_retdec(binary_path, output_dir, functions)
        elif decompiler_type == "ida" and self.ida_available:
            return self._decompile_with_ida(binary_path, output_dir, functions)
        else:
            # Fall back to available decompiler
            if self.ghidra_available:
                print(f"Decompiler {decompiler_type} not available, falling back to Ghidra")
                return self._decompile_with_ghidra(binary_path, output_dir, functions)
            elif self.retdec_available:
                print(f"Decompiler {decompiler_type} not available, falling back to RetDec")
                return self._decompile_with_retdec(binary_path, output_dir, functions)
            elif self.ida_available:
                print(f"Decompiler {decompiler_type} not available, falling back to IDA Pro")
                return self._decompile_with_ida(binary_path, output_dir, functions)
            else:
                print("No decompilers available")
                return None
    
    def _decompile_with_ghidra(self, binary_path, output_dir, functions=None):
        """
        Decompile a binary file using Ghidra
        
        Args:
            binary_path: Path to the binary file
            output_dir: Directory to save decompiled code
            functions: List of function addresses to decompile (optional)
            
        Returns:
            Decompiled code as string
        """
        print("Decompiling with Ghidra...")
        
        # Create temporary directory for Ghidra project
        with tempfile.TemporaryDirectory() as temp_dir:
            project_name = "ghidra_project"
            project_dir = os.path.join(temp_dir, project_name)
            
            # Create Ghidra script for decompilation
            script_path = os.path.join(temp_dir, "DecompileScript.java")
            with open(script_path, 'w') as f:
                f.write(self._get_ghidra_script(output_dir, functions))
            
            # Run Ghidra headless analyzer
            ghidra_home = os.environ.get("GHIDRA_HOME")
            ghidra_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
            
            cmd = [
                ghidra_headless,
                temp_dir,
                project_name,
                "-import", binary_path,
                "-postScript", script_path,
                "-scriptPath", temp_dir,
                "-deleteProject"
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode != 0:
                    print(f"Error running Ghidra: {result.stderr}")
                    return None
                
                # Check if decompiled code was generated
                decompiled_path = os.path.join(output_dir, "decompiled.c")
                if os.path.exists(decompiled_path):
                    with open(decompiled_path, 'r') as f:
                        return f.read()
                else:
                    print("Decompilation failed, no output generated")
                    return None
            except Exception as e:
                print(f"Error running Ghidra: {e}")
                return None
    
    def _get_ghidra_script(self, output_dir, functions=None):
        """
        Generate Ghidra script for decompilation
        
        Args:
            output_dir: Directory to save decompiled code
            functions: List of function addresses to decompile (optional)
            
        Returns:
            Ghidra script as string
        """
        # Create a Java script for Ghidra to decompile functions
        script = """
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;

public class DecompileScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        FunctionManager functionManager = program.getFunctionManager();
        DecompInterface decompInterface = new DecompInterface();
        
        // Initialize decompiler
        decompInterface.openProgram(program);
        
        // Create output file
        File outputDir = new File("%s");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        
        File outputFile = new File(outputDir, "decompiled.c");
        FileWriter writer = new FileWriter(outputFile);
        
        // Write header
        writer.write("// Decompiled with Ghidra\\n");
        writer.write("// Binary: " + program.getName() + "\\n");
        writer.write("// Timestamp: " + new java.util.Date() + "\\n\\n");
        
        // Get functions to decompile
        List<Function> functionsToDecompile = new ArrayList<>();
        """ % output_dir
        
        # Add specific functions if provided
        if functions and len(functions) > 0:
            script += """
        // Decompile specific functions
        """
            for function in functions:
                script += """
        Address addr = program.getAddressFactory().getAddress("%s");
        Function func = functionManager.getFunctionAt(addr);
        if (func != null) {
            functionsToDecompile.add(func);
        }
        """ % function
        else:
            script += """
        // Decompile all functions
        for (Function function : functionManager.getFunctions(true)) {
            functionsToDecompile.add(function);
        }
        """
        
        # Add decompilation logic
        script += """
        // Decompile functions
        int totalFunctions = functionsToDecompile.size();
        int processedFunctions = 0;
        
        for (Function function : functionsToDecompile) {
            processedFunctions++;
            println("Decompiling function " + processedFunctions + "/" + totalFunctions + ": " + function.getName());
            
            // Decompile function
            DecompileResults results = decompInterface.decompileFunction(function, 120, TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                // Write function header
                writer.write("// Function: " + function.getName() + "\\n");
                writer.write("// Address: " + function.getEntryPoint() + "\\n\\n");
                
                // Write decompiled code
                writer.write(results.getDecompiledFunction().getC());
                writer.write("\\n\\n");
            } else {
                writer.write("// Failed to decompile function: " + function.getName() + "\\n\\n");
            }
        }
        
        writer.close();
        println("Decompilation complete. Output saved to: " + outputFile.getAbsolutePath());
    }
}
"""
        return script
    
    def _decompile_with_retdec(self, binary_path, output_dir, functions=None):
        """
        Decompile a binary file using RetDec
        
        Args:
            binary_path: Path to the binary file
            output_dir: Directory to save decompiled code
            functions: List of function addresses to decompile (optional)
            
        Returns:
            Decompiled code as string
        """
        print("Decompiling with RetDec...")
        
        # Create output path
        decompiled_path = os.path.join(output_dir, "decompiled.c")
        
        # Build RetDec command
        cmd = [
            "retdec-decompiler",
            binary_path,
            "-o", decompiled_path
        ]
        
        # Add function addresses if provided
        if functions and len(functions) > 0:
            functions_str = ",".join(functions)
            cmd.extend(["--select-functions", functions_str])
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                print(f"Error running RetDec: {result.stderr}")
                return None
            
            # Check if decompiled code was generated
            if os.path.exists(decompiled_path):
                with open(decompiled_path, 'r') as f:
                    return f.read()
            else:
                print("Decompilation failed, no output generated")
                return None
        except Exception as e:
            print(f"Error running RetDec: {e}")
            return None
    
    def _decompile_with_ida(self, binary_path, output_dir, functions=None):
        """
        Decompile a binary file using IDA Pro
        
        Args:
            binary_path: Path to the binary file
            output_dir: Directory to save decompiled code
            functions: List of function addresses to decompile (optional)
            
        Returns:
            Decompiled code as string
        """
        print("Decompiling with IDA Pro...")
        
        # Create temporary directory for IDA script
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create IDA script for decompilation
            script_path = os.path.join(temp_dir, "decompile.py")
            with open(script_path, 'w') as f:
                f.write(self._get_ida_script(output_dir, functions))
            
            # Run IDA Pro headless
            ida_home = os.environ.get("IDA_HOME")
            ida_executable = os.path.join(ida_home, "idat64" if os.name != "nt" else "idat64.exe")
            
            cmd = [
                ida_executable,
                "-B",  # Batch mode
                "-S" + script_path,  # Run script
                binary_path
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode != 0:
                    print(f"Error running IDA Pro: {result.stderr}")
                    return None
                
                # Check if decompiled code was generated
                decompiled_path = os.path.join(output_dir, "decompiled.c")
                if os.path.exists(decompiled_path):
                    with open(decompiled_path, 'r') as f:
                        return f.read()
                else:
                    print("Decompilation failed, no output generated")
                    return None
            except Exception as e:
                print(f"Error running IDA Pro: {e}")
                return None
    
    def _get_ida_script(self, output_dir, functions=None):
        """
        Generate IDA Pro script for decompilation
        
        Args:
            output_dir: Directory to save decompiled code
            functions: List of function addresses to decompile (optional)
            
        Returns:
            IDA Pro script as string
        """
        script = """
import os
import idaapi
import idautils
import idc

def main():
    # Wait for auto-analysis to complete
    idaapi.auto_wait()
    
    # Create output directory if it doesn't exist
    output_dir = r"%s"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create output file
    output_path = os.path.join(output_dir, "decompiled.c")
    output_file = open(output_path, "w")
    
    # Write header
    output_file.write("// Decompiled with IDA Pro\\n")
    output_file.write("// Binary: " + idaapi.get_input_file_path() + "\\n")
    output_file.write("// Timestamp: " + str(idaapi.get_ida_time_str()) + "\\n\\n")
    
    # Get decompiler plugin
    decompiler = idaapi.find_plugin("hexrays")
    if not decompiler:
        print("Hexrays decompiler not available")
        output_file.write("// Error: Hexrays decompiler not available\\n")
        output_file.close()
        idc.qexit(1)
        return
    
    # Initialize decompiler
    if not idaapi.init_hexrays_plugin():
        print("Failed to initialize Hexrays decompiler")
        output_file.write("// Error: Failed to initialize Hexrays decompiler\\n")
        output_file.close()
        idc.qexit(1)
        return
    
    # Get functions to decompile
    functions_to_decompile = []
""" % output_dir
        
        # Add specific functions if provided
        if functions and len(functions) > 0:
            script += """
    # Decompile specific functions
"""
            for function in functions:
                script += """
    func_addr = %s
    if idaapi.get_func(func_addr):
        functions_to_decompile.append(func_addr)
""" % function
        else:
            script += """
    # Decompile all functions
    for func_addr in idautils.Functions():
        functions_to_decompile.append(func_addr)
"""
        
        # Add decompilation logic
        script += """
    # Decompile functions
    total_functions = len(functions_to_decompile)
    processed_functions = 0
    
    for func_addr in functions_to_decompile:
        processed_functions += 1
        func_name = idc.get_func_name(func_addr)
        print(f"Decompiling function {processed_functions}/{total_functions}: {func_name}")
        
        # Decompile function
        cfunc = idaapi.decompile(func_addr)
        if cfunc:
            # Write function header
            output_file.write(f"// Function: {func_name}\\n")
            output_file.write(f"// Address: 0x{func_addr:X}\\n\\n")
            
            # Write decompiled code
            output_file.write(str(cfunc))
            output_file.write("\\n\\n")
        else:
            output_file.write(f"// Failed to decompile function: {func_name}\\n\\n")
    
    output_file.close()
    print(f"Decompilation complete. Output saved to: {output_path}")
    
    # Exit IDA
    idc.qexit(0)

if __name__ == "__main__":
    main()
"""
        return script

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
