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
import collections # Added for Counter

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
    
    def decompile(self, binary_path, output_dir, decompiler_types=["ghidra"], functions=None):
        """
        Decompile a binary file using one or more specified decompilers.
        
        Args:
            binary_path: Path to the binary file.
            output_dir: Directory to save decompiled code and signatures.
            decompiler_types: List of decompiler names to use (e.g., ["ghidra", "retdec"]).
            functions: List of function addresses to decompile (optional).
            
        Returns:
            A dictionary where keys are decompiler names. Each value is another
            dictionary: {"c_code": path_or_none, "signatures": path_or_none}.
        """
        if not os.path.exists(binary_path):
            print(f"Error: File {binary_path} not found")
            return {} 
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        results = {}
        
        for decompiler_type in decompiler_types:
            output_c_filename = f"decompiled_{decompiler_type}.c"
            # Default result structure for each decompiler
            decompiler_result = {"c_code": None, "signatures": None}
            
            if decompiler_type == "ghidra":
                if self.ghidra_available:
                    print(f"Attempting decompilation with Ghidra...")
                    # _decompile_with_ghidra now returns a dict {"c_code": path, "signatures": path}
                    decompiler_result = self._decompile_with_ghidra(binary_path, output_dir, output_c_filename, functions)
                else:
                    print(f"Ghidra not available, skipping.")
            elif decompiler_type == "retdec":
                if self.retdec_available:
                    print(f"Attempting decompilation with RetDec...")
                    c_path = self._decompile_with_retdec(binary_path, output_dir, output_c_filename, functions)
                    decompiler_result = {"c_code": c_path, "signatures": None} # RetDec currently doesn't extract signatures
                else:
                    print(f"RetDec not available, skipping.")
            elif decompiler_type == "ida":
                if self.ida_available:
                    print(f"Attempting decompilation with IDA Pro...")
                    # IDA will be updated later to return a dict similar to Ghidra
                    # For now, its direct output (c_path) is stored, and signatures is None
                    c_path_ida = self._decompile_with_ida(binary_path, output_dir, output_c_filename, functions)
                    decompiler_result = {"c_code": c_path_ida, "signatures": None}
                else:
                    print(f"IDA Pro not available, skipping.")
            else:
                print(f"Unknown decompiler type: {decompiler_type}, skipping.")
            
            results[decompiler_type] = decompiler_result
            
        return results

    def _lines_are_similar(self, line1: str, line2: str) -> bool:
        """
        Helper function to compare two lines after normalizing them.
        For now, it's a simple strip and exact match.
        """
        return line1.strip() == line2.strip()

    def produce_consensus_output(self, decompiler_outputs: dict, output_dir: str, consensus_filename: str = "consensus_decompiled.c"): # -> Optional[str] type hint removed for now
        """
        Produces a consensus output from multiple decompiler outputs.

        Args:
            decompiler_outputs: Dictionary from decompile method 
                                (e.g., {"ghidra": {"c_code": "/path/ghidra.c", "signatures": "/path/ghidra.json"}}).
            output_dir: Directory to save the consensus file.
            consensus_filename: Name for the consensus file.

        Returns:
            Path to the consensus file, or None if it couldn't be created.
        """
        valid_outputs_content = []
        valid_output_paths = []

        for decompiler_name, output_data in decompiler_outputs.items():
            if output_data and output_data.get("c_code") and os.path.exists(output_data["c_code"]):
                output_file_path = output_data["c_code"]
                try:
                    with open(output_file_path, 'r', encoding='utf-8') as f:
                        valid_outputs_content.append(f.readlines())
                        valid_output_paths.append(output_file_path)
                    print(f"Successfully read C code from: {output_file_path}")
                except Exception as e:
                    print(f"Error reading decompiler C output {output_file_path}: {e}")
            else:
                print(f"C code output for {decompiler_name} is invalid or does not exist: {output_data.get('c_code') if output_data else 'N/A'}")

        num_valid_outputs = len(valid_outputs_content)
        consensus_output_path = os.path.join(output_dir, consensus_filename)

        if num_valid_outputs == 0:
            print("No valid decompiler outputs available to produce consensus.")
            return None
        
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except OSError as e:
                print(f"Error creating output directory {output_dir}: {e}")
                return None

        if num_valid_outputs == 1:
            print("Only one valid decompiler output. Copying it as consensus.")
            try:
                shutil.copy(valid_output_paths[0], consensus_output_path)
                return consensus_output_path
            except Exception as e:
                print(f"Error copying single output to consensus: {e}")
                return None

        # Basic line-by-line voting for consensus (for >= 2 outputs)
        print(f"Producing consensus from {num_valid_outputs} decompiler outputs.")
        
        # Count line occurrences across all files
        line_counts = collections.Counter()
        for lines in valid_outputs_content:
            for line in lines:
                line_counts[line.strip()] += 1
        
        consensus_lines = []
        # Use the first valid output as a reference for line order
        # This is a simplification. A more robust approach would involve actual function alignment.
        if valid_outputs_content:
            reference_lines = valid_outputs_content[0] 
            for line in reference_lines:
                stripped_line = line.strip()
                # Include line if it appears in more than half of the outputs
                if line_counts[stripped_line] * 2 > num_valid_outputs:
                    # Add the original line (with leading/trailing whitespace) from the reference
                    consensus_lines.append(line) 
                elif stripped_line.startswith("//") or stripped_line == "" or stripped_line == "}":
                    # Heuristic: Always include comments, blank lines, and closing braces
                    # if they are in the reference, to maintain some structure.
                    # This can be refined.
                    consensus_lines.append(line)


        if not consensus_lines:
            print("Consensus generation resulted in empty output. This might be due to highly dissimilar outputs.")
            # Fallback: if consensus is empty, maybe copy the first decompiler's output?
            # For now, we'll write an empty file.
            # A better strategy could be to pick the largest file, or the one from a preferred decompiler.

        try:
            with open(consensus_output_path, 'w', encoding='utf-8') as f:
                f.writelines(consensus_lines)
            print(f"Consensus output written to: {consensus_output_path}")
            return consensus_output_path
        except Exception as e:
            print(f"Error writing consensus file: {e}")
            return None
            
    def _decompile_with_ghidra(self, binary_path, output_dir, output_c_filename, functions=None):
        """
        Decompile a binary file using Ghidra, producing C code and JSON signatures.
        
        Args:
            binary_path: Path to the binary file.
            output_dir: Directory to save decompiled code and signatures.
            output_c_filename: Name of the file to save decompiled C code to.
            functions: List of function addresses to decompile (optional).
            
        Returns:
            A dictionary {"c_code": path_to_c_file_or_none, "signatures": path_to_json_file_or_none}
        """
        # Note: "Decompiling with Ghidra..." is now printed by the caller
        
        output_signatures_filename = output_c_filename.replace(".c", "_signatures.json")
        # Ensure .c is present before replacing, or append if not.
        if ".c" not in output_c_filename:
            output_signatures_filename = output_c_filename + "_signatures.json"
        else:
            output_signatures_filename = output_c_filename.replace(".c", "_signatures.json")


        result_paths = {"c_code": None, "signatures": None}

        # Create temporary directory for Ghidra project
        with tempfile.TemporaryDirectory() as temp_dir:
            project_name = "ghidra_project"
            
            # Create Ghidra script for decompilation
            script_path = os.path.join(temp_dir, "DecompileScript.java")
            with open(script_path, 'w') as f:
                # Pass output_dir, C filename, and the derived JSON filename to the script generator
                f.write(self._get_ghidra_script(output_dir, output_c_filename, output_signatures_filename, functions))
            
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
                    return result_paths 
                
                # Check if C decompiled code was generated
                decompiled_c_path = os.path.join(output_dir, output_c_filename)
                if os.path.exists(decompiled_c_path):
                    result_paths["c_code"] = decompiled_c_path
                else:
                    print(f"Ghidra C decompilation failed, no C output generated at {decompiled_c_path}")

                # Check if JSON signatures file was generated
                decompiled_json_path = os.path.join(output_dir, output_signatures_filename)
                if os.path.exists(decompiled_json_path):
                    result_paths["signatures"] = decompiled_json_path
                else:
                    # This is not necessarily an error if C code was produced,
                    # but we should note that signatures are missing.
                    print(f"Ghidra signature extraction: JSON output not found at {decompiled_json_path}")
                
                return result_paths
            except Exception as e:
                print(f"Error running Ghidra: {e}")
                return result_paths
    
    def _get_ghidra_script(self, output_dir, output_c_filename, output_signatures_filename, functions=None):
        """
        Generate Ghidra script for C decompilation and JSON signature extraction.
        
        Args:
            output_dir: Directory to save outputs.
            output_c_filename: Filename for the C decompiled code.
            output_signatures_filename: Filename for the JSON signatures.
            functions: List of function addresses to decompile (optional).
            
        Returns:
            Ghidra script as string.
        """
        # Create a Java script for Ghidra to decompile functions and extract signatures
        script = """
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map; // For signature data
import java.util.LinkedHashMap; // For preserving order in JSON objects

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Parameter; // For function parameters
import ghidra.program.model.symbol.SourceType; // For parameter names if available
import ghidra.program.model.address.Address;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;

public class DecompileScript extends GhidraScript {

    // Helper to escape strings for JSON
    private String escapeJson(String str) {
        if (str == null) return "null"; // Use JSON null for null strings
        // Basic escaping for quotes, backslashes, and control characters
        return "\\\"" + str.replace("\\\\", "\\\\\\\\").replace("\\\"", "\\\\\\\"").replace("\\b", "\\\\b")
                          .replace("\\f", "\\\\f").replace("\\n", "\\\\n").replace("\\r", "\\\\r")
                          .replace("\\t", "\\\\t") + "\\\"";
    }

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        FunctionManager functionManager = program.getFunctionManager();
        DecompInterface decompInterface = new DecompInterface();
        
        // Initialize decompiler
        decompInterface.openProgram(program);
        
        // Create output directory if it doesn't exist
        File outputDirFile = new File("%s"); 
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs();
        }
        
        // C code output file
        File cOutputFile = new File(outputDirFile, "%s");
        FileWriter cWriter = new FileWriter(cOutputFile);
        
        // JSON signatures output file
        File jsonOutputFile = new File(outputDirFile, "%s");
        FileWriter jsonWriter = new FileWriter(jsonOutputFile);
        
        // Write C header
        cWriter.write("// Decompiled with Ghidra\\n");
        cWriter.write("// Binary: " + program.getName() + "\\n");
        cWriter.write("// Timestamp: " + new java.util.Date() + "\\n\\n");
        
        List<Map<String, Object>> allFunctionsData = new ArrayList<>();

        // Get functions to decompile
        List<Function> functionsToDecompile = new ArrayList<>();
        """ % (output_dir, output_c_filename, output_signatures_filename)
        
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
        // Decompile functions and collect data
        int totalFunctions = functionsToDecompile.size();
        int processedFunctions = 0;
        
        for (Function function : functionsToDecompile) {
            processedFunctions++;
            // Use monitor from GhidraScript base class
            monitor.setMessage("Processing function " + processedFunctions + "/" + totalFunctions + ": " + function.getName());
            if (monitor.isCancelled()) break;

            Map<String, Object> funcData = new LinkedHashMap<>();
            funcData.put("name", function.getName());
            funcData.put("address", function.getEntryPoint().toString());
            funcData.put("return_type", function.getReturnType().getName());

            List<Map<String, String>> paramsList = new ArrayList<>();
            Parameter[] params = function.getParameters();
            for (Parameter param : params) {
                Map<String, String> paramData = new LinkedHashMap<>();
                // Use param.getName() which might be a default like "param_1" or a user-defined name
                String paramName = param.getName();
                // Ghidra's default names can be like "param_1", check source type if more specific needed
                // if (param.getSource() == SourceType.DEFAULT) { paramName = "arg_" + param.getOrdinal(); }
                paramData.put("name", paramName);
                paramData.put("type", param.getDataType().getName());
                paramsList.add(paramData);
            }
            funcData.put("parameters", paramsList);
            
            // Decompile function for C output
            DecompileResults results = decompInterface.decompileFunction(function, 120, monitor);
            if (results.decompileCompleted()) {
                String decompiledC = results.getDecompiledFunction().getC();
                cWriter.write("// Function: " + function.getName() + "\\n");
                cWriter.write("// Address: " + function.getEntryPoint() + "\\n\\n");
                cWriter.write(decompiledC);
                cWriter.write("\\n\\n");
                // funcData.put("decompiled_code_snippet", decompiledC); // Optional: include snippet in JSON
            } else {
                cWriter.write("// Failed to decompile function: " + function.getName() + "\\n\\n");
                // funcData.put("decompiled_code_snippet", "// Failed to decompile");
            }
            allFunctionsData.add(funcData);
        }
        
        cWriter.close();
        println("C Decompilation complete. Output saved to: " + cOutputFile.getAbsolutePath());

        // Write JSON output
        // This is a manual JSON serialization. For complex cases, a library would be better,
        // but this avoids external dependencies in the Ghidra script.
        jsonWriter.write("[\\n");
        for (int i = 0; i < allFunctionsData.size(); i++) {
            Map<String, Object> funcData = allFunctionsData.get(i);
            jsonWriter.write("  {\\n");
            jsonWriter.write("    " + escapeJson("name") + ": " + escapeJson((String) funcData.get("name")) + ",\\n");
            jsonWriter.write("    " + escapeJson("address") + ": " + escapeJson((String) funcData.get("address")) + ",\\n");
            jsonWriter.write("    " + escapeJson("return_type") + ": " + escapeJson((String) funcData.get("return_type")) + ",\\n");
            
            jsonWriter.write("    " + escapeJson("parameters") + ": [\\n");
            @SuppressWarnings("unchecked") // Suppress warning for the cast
            List<Map<String, String>> paramsList = (List<Map<String, String>>) funcData.get("parameters");
            for (int j = 0; j < paramsList.size(); j++) {
                Map<String, String> paramData = paramsList.get(j);
                jsonWriter.write("      {\\n");
                jsonWriter.write("        " + escapeJson("name") + ": " + escapeJson(paramData.get("name")) + ",\\n");
                jsonWriter.write("        " + escapeJson("type") + ": " + escapeJson(paramData.get("type")) + "\\n");
                jsonWriter.write("      }" + (j < paramsList.size() - 1 ? "," : "") + "\\n");
            }
            jsonWriter.write("    ]\\n");
            // Optional: add "decompiled_code_snippet" here if included above
            // String snippet = (String) funcData.get("decompiled_code_snippet");
            // if (snippet != null) {
            //    jsonWriter.write("    ," + escapeJson("decompiled_code_snippet") + ": " + escapeJson(snippet) + "\\n");
            // } else {
            //    jsonWriter.write("\\n");
            // }
            jsonWriter.write("  }" + (i < allFunctionsData.size() - 1 ? "," : "") + "\\n");
        }
        jsonWriter.write("]\\n");
        jsonWriter.close();
        println("JSON Signatures complete. Output saved to: " + jsonOutputFile.getAbsolutePath());
    }
}
"""
        return script
    
    def _decompile_with_retdec(self, binary_path, output_dir, output_filename, functions=None):
        """
        Decompile a binary file using RetDec.
        
        Args:
            binary_path: Path to the binary file.
            output_dir: Directory to save decompiled code.
            output_filename: Name of the file to save decompiled code to.
            functions: List of function addresses to decompile (optional).
            
        Returns:
            Path to the decompiled file if successful, None otherwise.
        """
        # Note: "Decompiling with RetDec..." is now printed by the caller
        
        # Create output path
        decompiled_path = os.path.join(output_dir, output_filename)
        
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
                # Return the path to the file, not its content
                return decompiled_path
            else:
                print(f"Decompilation failed, no output generated at {decompiled_path}")
                return None
        except Exception as e:
            print(f"Error running RetDec: {e}")
            return None
    
    def _decompile_with_ida(self, binary_path, output_dir, output_c_filename, functions=None):
        """
        Decompile a binary file using IDA Pro, producing C code and JSON signatures.
        
        Args:
            binary_path: Path to the binary file.
            output_dir: Directory to save decompiled code and signatures.
            output_c_filename: Name of the file to save decompiled C code to.
            functions: List of function addresses to decompile (optional).
            
        Returns:
            A dictionary {"c_code": path_to_c_file_or_none, "signatures": path_to_json_file_or_none}
        """
        # Note: "Decompiling with IDA Pro..." is now printed by the caller

        output_signatures_filename = output_c_filename.replace(".c", "_signatures.json")
        if ".c" not in output_c_filename: 
            output_signatures_filename = output_c_filename + "_signatures.json"
        else:
            output_signatures_filename = output_c_filename.replace(".c", "_signatures.json")

        result_paths = {"c_code": None, "signatures": None}
        
        current_env = os.environ.copy()
        if functions and len(functions) > 0:
            current_env["IDA_FUNCTIONS_TO_DECOMPILE"] = ",".join(functions)

        # Create temporary directory for IDA script
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = os.path.join(temp_dir, "decompile_ida_script.py") # Ensure unique script name
            with open(script_path, 'w') as f:
                f.write(self._get_ida_script(output_dir, output_c_filename, output_signatures_filename, functions)) # functions list passed for script generation if needed by _get_ida_script
            
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
                
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=current_env # Pass the modified environment
                )
                
                if result.returncode != 0: # IDA can return non-zero for various reasons even if some output is generated
                    print(f"IDA Pro execution finished with return code {result.returncode}. Stderr: {result.stderr}")
                
                # Check if C decompiled code was generated
                decompiled_c_path = os.path.join(output_dir, output_c_filename)
                if os.path.exists(decompiled_c_path):
                    result_paths["c_code"] = decompiled_c_path
                else:
                    print(f"IDA C decompilation failed, no C output generated at {decompiled_c_path}")

                # Check if JSON signatures file was generated
                decompiled_json_path = os.path.join(output_dir, output_signatures_filename)
                if os.path.exists(decompiled_json_path):
                    result_paths["signatures"] = decompiled_json_path
                else:
                    print(f"IDA signature extraction: JSON output not found at {decompiled_json_path}")
                
                return result_paths
            except Exception as e:
                print(f"Error running IDA Pro: {e}")
                return result_paths # Return whatever paths were found (likely None, None)
    
    def _get_ida_script(self, output_dir, output_c_filename, output_signatures_filename, functions_list_for_script_generation=None): # functions argument renamed for clarity
        """
        Generate IDA Pro script for C decompilation and JSON signature extraction.
        
        Args:
            output_dir: Directory to save outputs.
            output_c_filename: Filename for the C decompiled code.
            output_signatures_filename: Filename for the JSON signatures.
            functions_list_for_script_generation: List of function addresses/names (currently used to set env var, but available here if needed).
            
        Returns:
            IDA Pro script as string.
        """
        # Note: functions_list_for_script_generation is not directly used in this script string's Python logic
        # because function selection is handled by reading the IDA_FUNCTIONS_TO_DECOMPILE environment variable
        # from within the IDA script. This keeps the script string cleaner.
        script = """
import os
import json # For JSON output
import idaapi
import idautils
import idc
import ida_hexrays # For decompiler and type info
import ida_kernwin # For showing messages (optional, for debugging within IDA GUI)

# Helper function to parse IDA type string (simplified)
def parse_ida_type_str(type_str, func_name):
    parsed_params = []
    return_type = "unknown"
    try:
        # Example type_str: "int __cdecl(int arg1, char *arg2)"
        # Or from HexRays: "int (__fastcall *)(int a, _BYTE *b)"
        
        # Clean known calling conventions and modifiers
        conventions = ["__cdecl", "__stdcall", "__thiscall", "__fastcall", "__userpurge", "__usercall", "EFIAPI"]
        for conv in conventions:
            type_str = type_str.replace(conv, "").strip()
        
        # Remove potential pointer syntax around function name for HexRays types like "int (__fastcall *sub_XXXX)(...)"
        if '*' in type_str and '(' in type_str.split('*')[-1]:
             type_str = type_str.replace('*', '', 1) # Remove first '*', assuming it's for function pointer

        # Split return type from parameters
        if '(' not in type_str: # Not a function type string we can parse easily
            return_type = type_str.strip() if type_str else "unknown"
            return return_type, parsed_params

        parts = type_str.split('(', 1)
        return_type_candidate = parts[0].strip()
        
        if len(parts) > 1:
            params_str = parts[1].rsplit(')', 1)[0] # Get content between outer parentheses
        else: # No parameters part
            params_str = ""

        # Check if return_type_candidate is actually part of a function name (e.g. if no space)
        # This logic is tricky because function names can be complex.
        # We rely on idc.get_func_name for the actual name, and this is for type parsing.
        # For now, assume parts[0] is the return type or contains it.
        # A more robust parser would be needed for complex C syntax.
        # Example: "void * ( *)(...)" is a function pointer return type.
        
        # Simplistic assignment for return type
        return_type = return_type_candidate

        if params_str and params_str.lower() != 'void':
            params_list = params_str.split(',')
            for i, p_item in enumerate(params_list):
                p_item = p_item.strip()
                p_name = "param_%d" % (i + 1) # Default name
                p_type = p_item
                
                # Try to split type and name (e.g., "int x", "char *s")
                # This is very basic. IDA's tinfo_t would be better if fully usable.
                last_space = p_item.rfind(' ')
                if last_space != -1:
                    potential_name = p_item[last_space+1:]
                    # Avoid taking part of type (like "unsigned int") as name
                    if potential_name and not potential_name.startswith('*') and potential_name not in ["int", "char", "short", "long", "float", "double", "void"]:
                        p_type = p_item[:last_space].strip()
                        p_name = potential_name
                        if p_name.startswith('*'): # If name is like *myvar
                            p_type += '*'
                            p_name = p_name[1:]
                    else: # Likely just a type, or a type ending with a keyword
                        p_type = p_item
                
                # Further clean param type if name was part of it
                if p_name in p_type: # e.g. p_type = "int param_1", p_name = "param_1"
                    p_type = p_type.replace(p_name, "").strip()

                parsed_params.append({"name": p_name, "type": p_type})
    except Exception as e:
        # ida_kernwin.msg("Exception in parse_ida_type_str for '%s' (func: %s): %s\\n" % (type_str, func_name, str(e)))
        if not return_type or return_type == "unknown": # If return type wasn't parsed before error
             return_type = type_str.split('(')[0].strip() if '(' in type_str else type_str # best guess
        # Keep parsed_params as is, or empty if error was early

    return return_type, parsed_params


def get_func_details(ea):
    func_data = {}
    func_data['address'] = "0x%x" % ea
    name = idc.get_func_name(ea)
    if not name: name = "sub_%X" % ea
    func_data['name'] = name

    # Attempt to get type information using Hex-Rays decompiler if available
    # This often gives more C-like type strings.
    type_str = None
    params_from_hexrays = []
    return_type_from_hexrays = "unknown"

    try:
        if ida_hexrays.init_hexrays_plugin(): # Ensure it's initialized for this thread
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                # For return type and parameters from Hex-Rays 'cfunc.type'
                # cfunc.type is a tinfo_t object representing the function's type
                # Example: cfunc.type might be 'int (__fastcall *)(int, char *)'
                hexrays_type_str = str(cfunc.type) 
                # ida_kernwin.msg("HexRays type for %s: %s\\n" % (name, hexrays_type_str))
                
                # Let's try to parse this Hex-Rays type string
                return_type_from_hexrays, params_from_hexrays = parse_ida_type_str(hexrays_type_str, name)

    except Exception as e_hex:
        # ida_kernwin.msg("HexRays exception for type info on %s: %s\\n" % (name, str(e_hex)))
        pass # Fall through to idc.get_type if Hex-Rays fails

    # Fallback or primary method: idc.get_type(ea)
    # This gets the database type, which might be less "C-like" than Hex-Rays output
    if not params_from_hexrays: # If Hex-Rays didn't provide params, try idc_get_type
        idc_type_str = idaapi.idc_get_type(ea)
        # ida_kernwin.msg("idc_get_type for %s: %s\\n" % (name, idc_type_str))
        if idc_type_str:
            return_type_idc, params_idc = parse_ida_type_str(idc_type_str, name)
            if not params_from_hexrays and params_idc: # Prioritize HexRays if it gave something
                 params_from_hexrays = params_idc
            if return_type_from_hexrays == "unknown" and return_type_idc != "unknown":
                 return_type_from_hexrays = return_type_idc
        else: # If both fail, set to unknown
            if return_type_from_hexrays == "unknown": return_type_from_hexrays = "not_determined"
            # params_from_hexrays remains empty or as is
            
    func_data['return_type'] = return_type_from_hexrays
    func_data['parameters'] = params_from_hexrays
        
    return func_data

def main():
    idaapi.auto_wait() 
    
    output_dir_str = r"%s"
    c_output_filename_str = r"%s"
    json_output_filename_str = r"%s"

    if not os.path.exists(output_dir_str):
        os.makedirs(output_dir_str)
    
    c_output_path = os.path.join(output_dir_str, c_output_filename_str)
    json_output_path = os.path.join(output_dir_str, json_output_filename_str)
    
    all_funcs_data = []
    
    hexrays_initialized = False
    try:
        if ida_hexrays.init_hexrays_plugin():
            hexrays_initialized = True
    except Exception as e_init:
        ida_kernwin.warning("Hex-Rays plugin could not be initialized: %s" % str(e_init))

    if not hexrays_initialized:
        ida_kernwin.warning("Hex-Rays plugin is not available or failed to initialize. C code output will be empty.")
        with open(c_output_path, "w") as c_file:
            c_file.write("// Error: Hex-Rays not available or failed to initialize.\\n")
        # Write empty JSON list if Hex-Rays is not available
        with open(json_output_path, "w") as json_file:
            json.dump([], json_file)
        idc.qexit(1) # Exit IDA if Hex-Rays isn't working
        return

    # Determine functions to process
    functions_to_process = []
    # Get functions from environment variable if provided
    ida_funcs_env_str = os.getenv("IDA_FUNCTIONS_TO_DECOMPILE")
    if ida_funcs_env_str:
        # ida_kernwin.msg("IDA_FUNCTIONS_TO_DECOMPILE: %s\\n" % ida_funcs_env_str)
        for func_item in ida_funcs_env_str.split(','):
            func_item = func_item.strip()
            ea = idaapi.BADADDR
            try: # Try as address first
                ea = int(func_item, 0) # Auto-detect base (e.g. 0x prefix for hex)
            except ValueError: # If not an address, try as name
                ea = idc.get_name_ea_simple(func_item)
            
            if ea != idaapi.BADADDR and idaapi.get_func(ea):
                functions_to_process.append(ea)
            else:
                ida_kernwin.warning("Could not find function via item: %s" % func_item)
    else: # Decompile all functions
        # ida_kernwin.msg("No specific functions from env var, processing all functions.\\n")
        for ea in idautils.Functions():
            functions_to_process.append(ea)

    # Decompile and extract info
    with open(c_output_path, "w") as c_file:
        c_file.write("// Decompiled with IDA Pro (Hex-Rays)\\n")
        c_file.write("// Binary: " + idaapi.get_input_file_path() + "\\n")
        c_file.write("// Timestamp: " + idaapi.get_root_filename() + " IDA Version: " + idaapi.get_ida_version() + "\\n\\n")

        for func_ea in functions_to_process:
            func_name_str = idc.get_func_name(func_ea)
            if not func_name_str: func_name_str = "sub_%X" % func_ea
            # ida_kernwin.msg("Processing %s at 0x%x\\n" % (func_name_str, func_ea))

            # Get signature details
            func_details = get_func_details(func_ea)
            
            # Decompile for C code output
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    c_file.write("// Function: %s\\n" % func_name_str)
                    c_file.write("// Address: 0x%x\\n\\n" % func_ea)
                    c_file.write(str(cfunc))
                    c_file.write("\\n\\n")
                    # func_details["decompiled_code_snippet"] = str(cfunc) # Optional
                else:
                    c_file.write("// Failed to decompile function: %s (0x%x)\\n\\n" % (func_name_str, func_ea))
            except ida_hexrays.DecompilationFailure as e:
                c_file.write("// Decompilation failed for %s (0x%x): %s\\n\\n" % (func_name_str, func_ea, str(e)))
            except Exception as e_decompile: # Catch any other decompile error
                c_file.write("// General Decompilation error for %s (0x%x): %s\\n\\n" % (func_name_str, func_ea, str(e_decompile)))

            all_funcs_data.append(func_details)

    # Write JSON output for signatures
    try:
        with open(json_output_path, "w") as json_file:
            json.dump(all_funcs_data, json_file, indent=2)
        # ida_kernwin.msg("JSON signatures written to: %s\\n" % json_output_path)
    except IOError as e_io:
        ida_kernwin.warning("IOError writing JSON file %s: %s" % (json_output_path, str(e_io)))
    except Exception as e_json_write: # Catch other potential errors during JSON writing
        ida_kernwin.warning("Failed to write JSON output to %s: %s" % (json_output_path, str(e_json_write)))

    # ida_kernwin.msg("IDA Python script finished processing.\\n")
    idc.qexit(0) # Gracefully exit IDA

if __name__ == '__main__':
    # This part is mainly for testing within IDA's script execution context
    # For headless operation, IDA calls main() directly.
    main()
""" % (output_dir, output_c_filename, output_signatures_filename)
        
        # The environment variable IDA_FUNCTIONS_TO_DECOMPILE is set in the calling Python function _decompile_with_ida
        # No need to inject functions directly into the script string here.
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
        return script

    def refine_cfg(self, binary_path: str, decompiler_outputs: Optional[dict] = None, output_dir: Optional[str] = None) -> Optional[str]:
        """
        Placeholder for Control-Flow Graph (CFG) refinement.
        Currently, it checks for existing CFG files (e.g., .dot) from decompiler outputs
        and copies the first one found to the output_dir.

        Args:
            binary_path: Path to the original binary file.
            decompiler_outputs: The dictionary of decompiler outputs.
            output_dir: Directory where any refined CFG or related files could be saved.

        Returns:
            Path to a refined/copied CFG file or None.
        """
        self.logger.info(f"Placeholder for CFG refinement for binary: {binary_path}")

        if not decompiler_outputs:
            self.logger.info("No decompiler outputs provided to search for CFGs.")
            return None

        found_cfg_path = None
        found_cfg_origin_decompiler = None

        for decompiler_name, outputs in decompiler_outputs.items():
            if outputs:
                # Scenario 1: CFG path is explicitly provided in outputs (e.g., outputs["cfg_file"])
                # This would be a more robust way if decompilers are updated to provide this
                explicit_cfg_path = outputs.get("cfg_file") # Assuming a key "cfg_file" might exist
                if explicit_cfg_path and os.path.exists(explicit_cfg_path) and explicit_cfg_path.endswith(".dot"): # Or other CFG formats
                    self.logger.info(f"Found explicitly provided CFG from {decompiler_name}: {explicit_cfg_path}")
                    found_cfg_path = explicit_cfg_path
                    found_cfg_origin_decompiler = decompiler_name
                    break 
                
                # Scenario 2: Infer CFG path based on c_code path (as in the example)
                c_code_path = outputs.get("c_code")
                if c_code_path and os.path.exists(c_code_path):
                    # Try common CFG file extensions next to the C code file
                    base_name_no_ext = os.path.splitext(c_code_path)[0]
                    potential_cfg_files = [
                        base_name_no_ext + ".dot", # DOT file
                        base_name_no_ext + ".gdl", # GDL file (used by IDA sometimes)
                        # Add other potential extensions here, e.g., .vcg
                    ]
                    for potential_cfg_file in potential_cfg_files:
                        if os.path.exists(potential_cfg_file):
                            self.logger.info(f"Found potential CFG (inferred by extension) from {decompiler_name}: {potential_cfg_file}")
                            found_cfg_path = potential_cfg_file
                            found_cfg_origin_decompiler = decompiler_name
                            break # Take the first one found for this decompiler's C code
                if found_cfg_path: # If found from this decompiler, stop searching others
                    break
        
        if not found_cfg_path:
            self.logger.info("No pre-existing CFG file (e.g., .dot, .gdl) found in decompiler outputs.")
            return None

        self.logger.info(f"Identified CFG file '{found_cfg_path}' from decompiler '{found_cfg_origin_decompiler}'.")

        if output_dir:
            if not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                    self.logger.info(f"Created output directory for CFG: {output_dir}")
                except Exception as e:
                    self.logger.error(f"Error creating output directory {output_dir}: {e}")
                    return found_cfg_path # Return original path if dir creation fails
            
            # Use a name that indicates it's an "original" or "copied" CFG
            # Including binary name and original decompiler can be useful
            base_binary_name = os.path.basename(binary_path)
            cfg_filename = f"{base_binary_name}_{found_cfg_origin_decompiler}_original_cfg{os.path.splitext(found_cfg_path)[1]}"
            target_cfg_path = os.path.join(output_dir, cfg_filename)
            
            try:
                shutil.copy(found_cfg_path, target_cfg_path)
                self.logger.info(f"Copied CFG from {found_cfg_path} to {target_cfg_path}")
                return target_cfg_path
            except Exception as e:
                self.logger.error(f"Error copying CFG from {found_cfg_path} to {target_cfg_path}: {e}")
                # If copy fails, consider returning the original path as a fallback,
                # or None if the expectation is that it *must* be copied.
                # For a placeholder, returning original path is reasonable.
                return found_cfg_path 
        else:
            # If no output_dir is specified for copying, return the original path.
            self.logger.info("No output_dir provided, returning path to the original CFG found.")
            return found_cfg_path

    # --- Start of Signature Normalization ---

    TYPE_NORMALIZATION_MAP = {
        # Exact matches for common C integer types & variations
        "INT": "int", "INT32": "int", "int32_t": "int", "signed int": "int", "_DWORD": "unsigned long", # _DWORD often seen for unsigned long
        "UINT": "unsigned int", "UINT32": "unsigned int", "uint32_t": "unsigned int",
        "UINT8": "unsigned char", "uint8_t": "unsigned char", "BYTE": "unsigned char", "byte": "unsigned char",
        "UINT16": "unsigned short", "uint16_t": "unsigned short", "WORD": "unsigned short", "word": "unsigned short",
        "UINT64": "unsigned long long", "uint64_t": "unsigned long long", "ULONG64": "unsigned long long", "QWORD": "unsigned long long",
        "INT8": "signed char", "int8_t": "signed char", # Explicitly signed char for int8_t
        "INT16": "short", "int16_t": "short",
        "INT64": "long long", "int64_t": "long long", "LONG64": "long long",

        # Boolean
        "BOOL": "bool", "_BOOL": "bool", "BOOLEAN": "bool",

        # Characters
        "CHAR": "char",
        "WCHAR": "wchar_t", "wchar": "wchar_t", 

        # Void
        "VOID": "void", # Allow "VOID" to normalize to "void"

        # Pointers - these are common typedefs for pointers.
        # The _normalize_single_type method will handle stripping/adding '*' for the base type.
        "PVOID": "void*", "LPVOID": "void*", "HANDLE": "void*",
        "HWND": "void*", "HMODULE": "void*", "HINSTANCE": "void*", "HDC": "void*", "HKEY": "void*", "HCURSOR": "void*",
        "DWORD_PTR": "uintptr_t", "ULONG_PTR": "uintptr_t", "LONG_PTR": "intptr_t",
        "SIZE_T": "size_t", "SSIZE_T": "ssize_t",

        # String pointers (common Windows API patterns)
        "LPCSTR": "const char*", "PCSTR": "const char*",
        "LPSTR": "char*", "PSTR": "char*",
        "LPCWSTR": "const wchar_t*", "PCWSTR": "const wchar_t*",
        "LPWSTR": "wchar_t*", "PWSTR": "wchar_t*",
        "LPTSTR": "char*", # Assuming TCHAR maps to char for non-Unicode builds often seen in malware
        "LPCTSTR": "const char*", # Assuming TCHAR maps to char

        # Other common typedefs
        "DWORD": "unsigned long", # Typically 32-bit on Windows
        "ULONG": "unsigned long",
        "LONG": "long",
        "USHORT": "unsigned short",
        "SHORT": "short",
        "FLOAT": "float", 
        "DOUBLE": "double",
        
        # C++ specific often seen in RTTI context, map to basic C if possible or a placeholder
        "std::string": "char*", # Simplified, or could be "std_string_placeholder"
        "std::wstring": "wchar_t*", # Simplified
    }

    PRE_NORMALIZED_TYPES = {
        # Standard C types
        "int", "unsigned int", "char", "signed char", "unsigned char", 
        "short", "unsigned short", "long", "unsigned long", 
        "long long", "unsigned long long",
        "float", "double", "long double", "void", "bool",
        "intptr_t", "uintptr_t", "size_t", "ssize_t", "ptrdiff_t",
        "wchar_t",
        # Fixed-size standard types (already in their best form)
        "int8_t", "uint8_t", "int16_t", "uint16_t", 
        "int32_t", "uint32_t", "int64_t", "uint64_t",
        # Keywords that start complex types, to be preserved if no other rule matches.
        "struct", "union", "enum",
    }

    def _normalize_single_type(self, type_str: str) -> str:
        """Normalizes a single type string, handling pointers and const/volatile qualifiers."""
        if not hasattr(self, 'logger'): # Ensure logger is available, e.g. if called directly on an uninitialized instance
            # This basicConfig is a fallback and might not be desired if the class is used in a larger system
            # where logging is configured centrally.
            logging.basicConfig(level=logging.INFO) 
            self.logger = logging.getLogger(self.__class__.__name__) 


        if not type_str:
            self.logger.debug("_normalize_single_type: Received empty or None type_str, returning 'unknown_type'.")
            return "unknown_type" 

        original_type_str_for_fallback = type_str 

        # 1. Handle 'const' and 'volatile' qualifiers
        qualifiers = []
        stripped_type = type_str.strip()

        changed_in_iteration = True
        while changed_in_iteration:
            changed_in_iteration = False
            # Use lower() for checking prefixes to be case-insensitive for qualifiers
            if stripped_type.lower().startswith("const "):
                # Find the actual 'const' to preserve its casing if mixed (though unlikely)
                qualifiers.append(stripped_type[:5]) # "const"
                stripped_type = stripped_type[6:].strip()
                changed_in_iteration = True
            if stripped_type.lower().startswith("volatile "):
                qualifiers.append(stripped_type[:8]) # "volatile"
                stripped_type = stripped_type[9:].strip()
                changed_in_iteration = True
        
        # 2. Separate pointer asterisks from the base type
        pointers = []
        stripped_type = stripped_type.strip() # Ensure no leading/trailing spaces before pointer check
        while stripped_type.endswith("*"):
            pointers.append("*")
            stripped_type = stripped_type[:-1].strip()
        
        base_type_str = stripped_type.strip()
        if not base_type_str: 
            # Handles cases like input "*" or "const *" becoming empty base_type_str
            # If only qualifiers and pointers, assume void* or const void* etc.
            # If no pointers either (e.g. input was "const"), it's an incomplete type.
            base_type_str = "void" if pointers else "unknown_qualifier_only"


        # 3. Normalize the base type string
        normalized_base_type = base_type_str
        if base_type_str in self.PRE_NORMALIZED_TYPES:
            pass 
        elif base_type_str.lower() in self.PRE_NORMALIZED_TYPES:
            normalized_base_type = base_type_str.lower()
        else:
            # Fallback chain: direct, UPPER, lower
            normalized_base_type = self.TYPE_NORMALIZATION_MAP.get(base_type_str,
                                     self.TYPE_NORMALIZATION_MAP.get(base_type_str.upper(),
                                     self.TYPE_NORMALIZATION_MAP.get(base_type_str.lower(), base_type_str)))
        
        # 4. Handle complex types like "struct MyStruct", "enum MyEnum"
        first_word_original = base_type_str.split(' ', 1)[0].lower()
        if first_word_original in ["struct", "union", "enum"]:
            # If the original base_type_str started with struct/union/enum,
            # and normalization changed it based on a partial match (e.g. "MyStruct" in map),
            # it's often better to preserve the original "struct MyStruct" form.
            if normalized_base_type != base_type_str: 
                 # This check ensures we don't revert if "struct MyStruct" itself was mapped.
                 if base_type_str not in self.TYPE_NORMALIZATION_MAP and \
                    base_type_str.upper() not in self.TYPE_NORMALIZATION_MAP and \
                    base_type_str.lower() not in self.TYPE_NORMALIZATION_MAP:
                      normalized_base_type = base_type_str 

        # 5. Reconstruct the type string with qualifiers and pointers
        final_parts = []
        # Add unique qualifiers (e.g. "const volatile", not "const const")
        # sorted() ensures consistent order e.g. "const volatile" not "volatile const"
        unique_qualifiers = sorted(list(set(q.lower() for q in qualifiers))) 
        
        for q_lower in unique_qualifiers:
            if q_lower == "const" and normalized_base_type.lower().startswith("const "):
                continue 
            final_parts.append(q_lower) 
        
        if normalized_base_type != "unknown_qualifier_only": # Avoid "unknown_qualifier_only" in the middle of a type
             final_parts.append(normalized_base_type)
        elif not unique_qualifiers and not pointers : # If input was "const" and became "unknown_qualifier_only" with no pointers
             return original_type_str_for_fallback # Revert to just "const"


        # Join pointers without spaces, e.g. "char**" not "char * *"
        final_parts.append("".join(pointers)) 
        
        final_type = " ".join(p for p in final_parts if p).strip() # Filter out empty parts before join

        if not final_type or final_type == "const" or final_type == "volatile": # If only qualifiers remain
            self.logger.debug(f"_normalize_single_type: Normalization of '{original_type_str_for_fallback}' resulted in problematic type ('{final_type}').")
            # This case might happen if input was e.g. "const *" and base_type_str became "void"
            # but then qualifiers made it just "const". Better to return original or a known placeholder.
            if pointers: # Example: input "const *" -> normalized_base_type "void"
                reconstructed_with_void = ["void"] # Start with void
                if unique_qualifiers: reconstructed_with_void = unique_qualifiers + reconstructed_with_void
                reconstructed_with_void.append("".join(pointers))
                return " ".join(reconstructed_with_void).strip()

            return original_type_str_for_fallback 

        return final_type


    def normalize_signatures(self, signature_data_list: list) -> list:
        """
        Normalizes types within a list of function signature objects.
        """
        if not hasattr(self, 'logger'): 
             logging.basicConfig(level=logging.INFO)
             self.logger = logging.getLogger(self.__class__.__name__)


        if not signature_data_list: 
            self.logger.info("normalize_signatures: Received empty or None list, returning empty list.")
            return []

        normalized_signatures = []
        for original_sig_obj in signature_data_list:
            if not isinstance(original_sig_obj, dict):
                self.logger.warning(f"normalize_signatures: Skipping non-dict item in list: {type(original_sig_obj)}")
                normalized_signatures.append(original_sig_obj) # Or skip, or deepcopy if unsure
                continue
            
            # Deep copy to avoid modifying original objects
            try:
                sig = json.loads(json.dumps(original_sig_obj)) # Simple deepcopy for JSON-like structures
            except Exception as e:
                self.logger.error(f"normalize_signatures: Could not deepcopy signature object using JSON (name: {original_sig_obj.get('name', 'N/A')}). Error: {e}. Using manual dict copy as fallback.")
                # Manual deepcopy for the expected structure (dict of strings, list of dicts of strings)
                sig = {k: v for k, v in original_sig_obj.items() if k != 'parameters'}
                sig['parameters'] = [{p_k: p_v for p_k, p_v in p.items()} for p in original_sig_obj.get('parameters', [])]


            if "return_type" in sig:
                if isinstance(sig["return_type"], str):
                    sig["return_type"] = self._normalize_single_type(sig["return_type"])
                else:
                    self.logger.warning(f"normalize_signatures: Return type for '{sig.get('name', 'N/A')}' is not a string: {sig['return_type']}. Leaving as is.")
            
            if "parameters" in sig and isinstance(sig["parameters"], list):
                for param in sig["parameters"]:
                    if isinstance(param, dict) and "type" in param:
                        if isinstance(param["type"], str):
                            param["type"] = self._normalize_single_type(param["type"])
                        else:
                            self.logger.warning(f"normalize_signatures: Parameter type for '{sig.get('name', 'N/A')}' param '{param.get('name', 'N/A')}' is not a string: {param['type']}. Leaving as is.")
            
            normalized_signatures.append(sig)
            
        self.logger.info(f"normalize_signatures: Processed {len(signature_data_list)} signatures.")
        return normalized_signatures

    # --- End of Signature Normalization ---

if __name__ == "__main__": # This block should be outside _get_ida_script
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
