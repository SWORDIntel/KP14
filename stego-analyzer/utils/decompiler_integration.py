#!/usr/bin/env python3
"""
KEYPLUG Decompiler Integration
------------------------------
Integration with various decompilers for KEYPLUG malware analysis.
Supports Ghidra, RetDec, and IDA Pro with OpenVINO acceleration.
"""

import os
import subprocess
import tempfile
import json
import shutil
from pathlib import Path
import collections # Added for Counter
import logging

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
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Check for decompiler installations
        self.ghidra_available = self._check_ghidra()
        self.retdec_available = self._check_retdec()
        self.ida_available = self._check_ida()
        
        # Print available decompilers
        print("Available decompilers:")
        print(f"  - Ghidra: {'Available' if self.ghidra_available else 'Not available'}")
        print(f"  - RetDec: {'Available' if self.retdec_available else 'Not available'}")
        print(f"  - IDA Pro: {'Available' if self.ida_available else 'Not available'}")

        # Define script file paths relative to this file's directory
        # This assumes decompiler_integration.py and the script files are in the same directory
        self.base_script_dir = Path(__file__).parent.resolve()
        self.ghidra_script_template_path = self.base_script_dir / "ghidra_decompile_script.java"
        self.ida_script_template_path = self.base_script_dir / "ida_decompile_script.py"

    
    def _check_ghidra(self):
        """Check if Ghidra is available"""
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home and os.path.exists(ghidra_home):
            return True
        common_paths = ["/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra", os.path.expanduser("~/ghidra")]
        for path in common_paths:
            if os.path.exists(path): os.environ["GHIDRA_HOME"] = path; return True
        return False
    
    def _check_retdec(self):
        """Check if RetDec is available"""
        try:
            result = subprocess.run(["retdec-decompiler", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.returncode == 0
        except FileNotFoundError: return False
    
    def _check_ida(self):
        """Check if IDA Pro is available"""
        ida_home = os.environ.get("IDA_HOME")
        if ida_home and os.path.exists(ida_home): return True
        common_paths = ["/opt/ida", "/usr/local/ida", os.path.expanduser("~/ida")]
        for path in common_paths:
            if os.path.exists(path): os.environ["IDA_HOME"] = path; return True
        return False
    
    def decompile(self, binary_path, output_dir, decompiler_types=["ghidra"], functions=None):
        if not os.path.exists(binary_path): self.logger.error(f"File {binary_path} not found"); return {} 
        if not os.path.exists(output_dir): os.makedirs(output_dir)
            
        results = {}
        for decompiler_type in decompiler_types:
            output_c_filename = f"decompiled_{decompiler_type}.c"
            decompiler_result = {"c_code": None, "signatures": None, "cfg_file_path": None}
            
            if decompiler_type == "ghidra":
                if self.ghidra_available:
                    self.logger.info(f"Attempting decompilation with Ghidra...")
                    decompiler_result = self._decompile_with_ghidra(binary_path, output_dir, output_c_filename, functions)
                else: self.logger.warning(f"Ghidra not available, skipping.")
            elif decompiler_type == "retdec":
                if self.retdec_available:
                    self.logger.info(f"Attempting decompilation with RetDec...")
                    c_path = self._decompile_with_retdec(binary_path, output_dir, output_c_filename, functions)
                    decompiler_result = {"c_code": c_path, "signatures": None} 
                else: self.logger.warning(f"RetDec not available, skipping.")
            elif decompiler_type == "ida":
                if self.ida_available:
                    self.logger.info(f"Attempting decompilation with IDA Pro...")
                    decompiler_result = self._decompile_with_ida(binary_path, output_dir, output_c_filename, functions)
                else: self.logger.warning(f"IDA Pro not available, skipping.")
            else:
                self.logger.warning(f"Unknown decompiler type: {decompiler_type}, skipping.")
            
            results[decompiler_type] = decompiler_result
            
        return results

    def _lines_are_similar(self, line1: str, line2: str) -> bool:
        return line1.strip() == line2.strip()

    def produce_consensus_output(self, decompiler_outputs: dict, output_dir: str, consensus_filename: str = "consensus_decompiled.c", preferred_decompiler_order: list | None = None):
        if preferred_decompiler_order is None: preferred_decompiler_order = []
        valid_outputs = {}
        for name, data in decompiler_outputs.items():
            if data and data.get("c_code") and os.path.exists(data["c_code"]):
                try:
                    with open(data["c_code"], 'r', encoding='utf-8') as f: lines = f.readlines()
                    valid_outputs[name] = {"path": data["c_code"], "lines": lines, "size": os.path.getsize(data["c_code"])}
                except Exception as e: self.logger.error(f"Error reading {data['c_code']} for {name}: {e}")
        
        num_valid = len(valid_outputs)
        consensus_path = os.path.join(output_dir, consensus_filename)
        if num_valid == 0: self.logger.warning("No valid decompiler outputs for consensus."); return None
        if not os.path.exists(output_dir): os.makedirs(output_dir, exist_ok=True)

        if num_valid == 1:
            name, data = list(valid_outputs.items())[0]
            self.logger.info(f"Only one valid output ({name}). Copying as consensus.")
            try: shutil.copy(data["path"], consensus_path); return consensus_path
            except Exception as e: self.logger.error(f"Error copying single output: {e}"); return None

        ref_lines, ref_name = None, None
        for name in preferred_decompiler_order:
            if name in valid_outputs: ref_lines, ref_name = valid_outputs[name]["lines"], name; break
        if not ref_lines: ref_name, data = list(valid_outputs.items())[0]; ref_lines = data["lines"]
        self.logger.info(f"Using '{ref_name}' as reference for consensus line ordering.")

        line_counts = collections.Counter(l.strip() for data in valid_outputs.values() for l in data["lines"])
        if not line_counts:
            self.logger.warning("Empty line counts - no content found in decompiler outputs")
            consensus_lines = []
        else:
            consensus_lines = [l for l in ref_lines if (line_counts[l.strip()] * 2 > num_valid) or l.strip().startswith("//") or l.strip() == "" or l.strip() == "}"]
        
        if not consensus_lines: # Fallback strategy
            self.logger.warning("Consensus resulted in empty output. Applying fallback (largest or preferred).")
            best_fallback = None
            for name in preferred_decompiler_order:
                if name in valid_outputs: best_fallback = valid_outputs[name]["path"]; break
            if not best_fallback: best_fallback = max(valid_outputs.values(), key=lambda x: x["size"])["path"]
            
            if best_fallback:
                try: shutil.copy(best_fallback, consensus_path); return consensus_path
                except Exception as e: self.logger.error(f"Error copying fallback: {e}"); return None
            return None # Should not happen if valid_outputs is not empty
            
        try:
            with open(consensus_path, 'w', encoding='utf-8') as f: f.writelines(consensus_lines)
            self.logger.info(f"Consensus written to: {consensus_path}")
            return consensus_path
        except Exception as e: self.logger.error(f"Error writing consensus: {e}"); return None
            
    def _decompile_with_ghidra(self, binary_path, output_dir, output_c_filename, functions=None):
        if not self.ghidra_script_template_path.exists():
            self.logger.error(f"Ghidra script template not found at {self.ghidra_script_template_path}")
            return {"c_code": None, "signatures": None, "cfg_file_path": None}
        
        try:
            with open(self.ghidra_script_template_path, 'r', encoding='utf-8') as f_template:
                script_content_template = f_template.read()
        except Exception as e:
            self.logger.error(f"Failed to read Ghidra script template: {e}")
            return {"c_code": None, "signatures": None, "cfg_file_path": None}

        output_signatures_filename = output_c_filename.replace(".c", "_signatures.json") if ".c" in output_c_filename else output_c_filename + "_signatures.json"
        output_cfg_filename = output_c_filename.replace(".c", "_cfg.dot") if ".c" in output_c_filename else output_c_filename + "_cfg.dot"
        result_paths = {"c_code": None, "signatures": None, "cfg_file_path": None}

        with tempfile.TemporaryDirectory() as temp_dir:
            project_name = "ghidra_project"
            script_path = os.path.join(temp_dir, "DecompileScript.java") # Script name in temp dir
            
            function_selection_logic = ""
            if functions and len(functions) > 0:
                function_selection_logic = "\n".join([
                    f'        Address addr_{i} = program.getAddressFactory().getAddress("{func_addr}");\n'
                    f'        Function func_{i} = functionManager.getFunctionAt(addr_{i});\n'
                    f'        if (func_{i} != null) {{ functionsToDecompile.add(func_{i}); }}\n'
                    f'        else {{ println("Warning: Could not find function at address: {func_addr}"); }}'
                    for i, func_addr in enumerate(functions)
                ])
            else:
                function_selection_logic = """
        for (Function function : functionManager.getFunctions(true)) {
            functionsToDecompile.add(function);
        }
        """
            
            try:
                formatted_script = script_content_template % (
                    output_dir.replace("\\", "\\\\"), # Escape backslashes for Java string
                    output_c_filename.replace("\\", "\\\\"),
                    output_signatures_filename.replace("\\", "\\\\"),
                    output_cfg_filename.replace("\\", "\\\\"),
                    function_selection_logic
                )
                with open(script_path, 'w') as f: f.write(formatted_script)
            except Exception as e_fmt:
                self.logger.error(f"Error formatting Ghidra script: {e_fmt}")
                return result_paths

            ghidra_home = os.environ.get("GHIDRA_HOME")
            ghidra_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
            ghidra_base_cmd = [ghidra_headless, temp_dir, project_name, "-import", binary_path, "-postScript", os.path.basename(script_path), "-scriptPath", temp_dir, "-deleteProject"]
            
            # Check if firejail is available
            use_firejail = False
            try:
                firejail_check = subprocess.run(["firejail", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if firejail_check.returncode == 0:
                    use_firejail = True
                    self.logger.info("Using firejail for sandboxing Ghidra execution")
                else:
                    self.logger.warning("Firejail check failed. Running Ghidra without sandboxing.")
            except FileNotFoundError:
                self.logger.warning("Firejail not found. Running Ghidra without sandboxing.")
                
            if use_firejail:
                firejail_prefix = ["firejail", "--quiet", f"--whitelist={os.path.abspath(binary_path)}", f"--whitelist={os.path.abspath(output_dir)}", "--private=" + temp_dir]
                cmd = firejail_prefix + ghidra_base_cmd
            else:
                cmd = ghidra_base_cmd
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0: self.logger.error(f"Error running Ghidra: {result.stderr}"); return result_paths 
                
                decompiled_c_path = os.path.join(output_dir, output_c_filename)
                if os.path.exists(decompiled_c_path): result_paths["c_code"] = decompiled_c_path
                else: self.logger.warning(f"Ghidra C output not found at {decompiled_c_path}")

                decompiled_json_path = os.path.join(output_dir, output_signatures_filename)
                if os.path.exists(decompiled_json_path): result_paths["signatures"] = decompiled_json_path
                else: self.logger.warning(f"Ghidra JSON signatures not found at {decompiled_json_path}")

                decompiled_cfg_path = os.path.join(output_dir, output_cfg_filename)
                if os.path.exists(decompiled_cfg_path): result_paths["cfg_file_path"] = decompiled_cfg_path
                else: self.logger.warning(f"Ghidra CFG DOT file not found at {decompiled_cfg_path}")
                
                return result_paths
            except Exception as e: self.logger.error(f"Error running Ghidra: {e}"); return result_paths
    
    def _get_ghidra_script(self, output_dir, output_c_filename, output_signatures_filename, output_cfg_filename, functions=None):
        # This method now reads the template and formats it.
        if not self.ghidra_script_template_path.exists():
            self.logger.error(f"Ghidra script template not found at {self.ghidra_script_template_path}")
            return "// ERROR: Ghidra script template file not found"
        try:
            with open(self.ghidra_script_template_path, 'r', encoding='utf-8') as f:
                script_template = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read Ghidra script template: {e}")
            return f"// ERROR: Failed to read Ghidra script template: {e}"

        function_selection_logic = ""
        if functions and len(functions) > 0:
            for i, func_addr_str in enumerate(functions):
                # Ensure addresses are correctly formatted for Java/Ghidra
                func_addr_str_java = func_addr_str if func_addr_str.startswith("0x") else "0x" + func_addr_str
                function_selection_logic += (
                    f'        Address addr_{i} = program.getAddressFactory().getAddress("{func_addr_str_java}");\n'
                    f'        Function func_{i} = functionManager.getFunctionAt(addr_{i});\n'
                    f'        if (func_{i} != null) {{ functionsToDecompile.add(func_{i}); }}\n'
                    f'        else {{ println("Warning: Could not find function at address: {func_addr_str_java}"); }}\n'
                )
        else:
            function_selection_logic = """
        for (Function function : functionManager.getFunctions(true)) {
            functionsToDecompile.add(function);
        }
        """
        
        # Escape backslashes in paths for Java string literals
        escaped_output_dir = output_dir.replace("\\", "\\\\")
        escaped_c_filename = output_c_filename.replace("\\", "\\\\")
        escaped_sig_filename = output_signatures_filename.replace("\\", "\\\\")
        escaped_cfg_filename = output_cfg_filename.replace("\\", "\\\\")

        return script_template % (
            escaped_output_dir,
            escaped_c_filename,
            escaped_sig_filename,
            escaped_cfg_filename,
            function_selection_logic
        )

    def _decompile_with_retdec(self, binary_path, output_dir, output_filename, functions=None):
        decompiled_path = os.path.join(output_dir, output_filename)
        cmd = ["retdec-decompiler", binary_path, "-o", decompiled_path]
        if functions and len(functions) > 0: cmd.extend(["--select-functions", ",".join(functions)])
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0: self.logger.error(f"Error running RetDec: {result.stderr}"); return None
            if os.path.exists(decompiled_path): return decompiled_path
            else: self.logger.warning(f"RetDec output not found at {decompiled_path}"); return None
        except Exception as e: self.logger.error(f"Error running RetDec: {e}"); return None
    
    def _decompile_with_ida(self, binary_path, output_dir, output_c_filename, functions=None):
        if not self.ida_script_template_path.exists():
            self.logger.error(f"IDA script template not found at {self.ida_script_template_path}")
            return {"c_code": None, "signatures": None}

        try:
            with open(self.ida_script_template_path, 'r', encoding='utf-8') as f_template:
                script_content_template = f_template.read()
        except Exception as e:
            self.logger.error(f"Failed to read IDA script template: {e}")
            return {"c_code": None, "signatures": None}

        output_signatures_filename = output_c_filename.replace(".c", "_signatures.json") if ".c" in output_c_filename else output_c_filename + "_signatures.json"
        result_paths = {"c_code": None, "signatures": None}
        current_env = os.environ.copy()
        if functions and len(functions) > 0: current_env["IDA_FUNCTIONS_TO_DECOMPILE"] = ",".join(functions)

        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = os.path.join(temp_dir, "decompile_ida_script.py")
            
            # The IDA script template already handles function selection via ENV var,
            # so the `function_block_ida` part is not needed here for simple substitution.
            # The last %s in the original IDA script string was likely a bug or unused.
            try:
                formatted_script = script_content_template % (
                    output_dir.replace("\\", "\\\\"), 
                    output_c_filename.replace("\\", "\\\\"),
                    output_signatures_filename.replace("\\", "\\\\")
                )
                with open(script_path, 'w') as f: f.write(formatted_script)
            except Exception as e_fmt:
                self.logger.error(f"Error formatting IDA script: {e_fmt}")
                return result_paths

            ida_home = os.environ.get("IDA_HOME")
            ida_executable = os.path.join(ida_home, "idat64" if os.name != "nt" else "idat64.exe")
            cmd = [ida_executable, "-B", "-S" + script_path, binary_path]
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=current_env)
                if result.returncode != 0: self.logger.warning(f"IDA Pro execution finished with code {result.returncode}. Stderr: {result.stderr}")
                
                decompiled_c_path = os.path.join(output_dir, output_c_filename)
                if os.path.exists(decompiled_c_path): result_paths["c_code"] = decompiled_c_path
                else: self.logger.warning(f"IDA C output not found at {decompiled_c_path}")

                decompiled_json_path = os.path.join(output_dir, output_signatures_filename)
                if os.path.exists(decompiled_json_path): result_paths["signatures"] = decompiled_json_path
                else: self.logger.warning(f"IDA JSON signatures not found at {decompiled_json_path}")
                
                return result_paths
            except Exception as e: self.logger.error(f"Error running IDA Pro: {e}"); return result_paths
    
    def _get_ida_script(self, output_dir, output_c_filename, output_signatures_filename, functions_list_for_script_generation=None):
        if not self.ida_script_template_path.exists():
            self.logger.error(f"IDA script template not found at {self.ida_script_template_path}")
            return "# ERROR: IDA script template file not found"
        try:
            with open(self.ida_script_template_path, 'r', encoding='utf-8') as f:
                script_template = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read IDA script template: {e}")
            return f"# ERROR: Failed to read IDA script template: {e}"
        
        # The IDA script template is designed to use an environment variable for functions.
        # The final %s in the original script was likely unused or a bug, so it's removed here.
        return script_template % (
            output_dir.replace("\\", "\\\\"),
            output_c_filename.replace("\\", "\\\\"),
            output_signatures_filename.replace("\\", "\\\\")
        )

    def refine_cfg(self, binary_path: str, decompiler_outputs: dict | None = None, output_dir: str | None = None, preferred_decompiler_order: list | None = None) -> str | None:
        self.logger.info(f"Starting CFG selection process for binary: {binary_path}")
        if preferred_decompiler_order is None: preferred_decompiler_order = []
        if not decompiler_outputs: self.logger.info("No decompiler outputs for CFG selection."); return None

        found_cfg_path, found_cfg_origin_decompiler, source_method = None, None, ""
        for decompiler_name in preferred_decompiler_order + list(d for d in decompiler_outputs if d not in preferred_decompiler_order):
            outputs = decompiler_outputs.get(decompiler_name)
            if outputs and isinstance(outputs, dict):
                cfg_path = outputs.get("cfg_file_path")
                if cfg_path and os.path.exists(cfg_path) and (cfg_path.endswith(".dot") or cfg_path.endswith(".gdl")):
                    found_cfg_path, found_cfg_origin_decompiler, source_method = cfg_path, decompiler_name, f"explicit path ({decompiler_name})"
                    break
                elif outputs.get("c_code") and os.path.exists(outputs["c_code"]): # Fallback to inference
                    base_name = os.path.splitext(outputs["c_code"])[0]
                    for ext in [".dot", ".gdl"]:
                        if os.path.exists(base_name + ext):
                            found_cfg_path, found_cfg_origin_decompiler, source_method = base_name + ext, decompiler_name, f"inference ({decompiler_name})"
                            break
            if found_cfg_path: break
        
        if not found_cfg_path: self.logger.warning(f"No CFG file found for {binary_path}."); return None
        self.logger.info(f"Selected CFG '{found_cfg_path}' from '{found_cfg_origin_decompiler}' (method: {source_method}). Refinement is future work.")

        if output_dir:
            if not os.path.exists(output_dir): os.makedirs(output_dir, exist_ok=True)
            cfg_filename = f"{os.path.basename(binary_path)}_{found_cfg_origin_decompiler}_selected_cfg{os.path.splitext(found_cfg_path)[1]}"
            target_cfg_path = os.path.join(output_dir, cfg_filename)
            try: shutil.copy(found_cfg_path, target_cfg_path); return target_cfg_path
            except Exception as e: self.logger.error(f"Error copying CFG to {target_cfg_path}: {e}"); return None
        return found_cfg_path

    TYPE_NORMALIZATION_MAP = {
        "INT": "int", "INT32": "int", "int32_t": "int", "signed int": "int", "_DWORD": "unsigned long", 
        "UINT": "unsigned int", "UINT32": "unsigned int", "uint32_t": "unsigned int",
        "UINT8": "unsigned char", "uint8_t": "unsigned char", "BYTE": "unsigned char", "byte": "unsigned char",
        "UINT16": "unsigned short", "uint16_t": "unsigned short", "WORD": "unsigned short", "word": "unsigned short",
        "UINT64": "unsigned long long", "uint64_t": "unsigned long long", "ULONG64": "unsigned long long", "QWORD": "unsigned long long",
        "INT8": "signed char", "int8_t": "signed char", 
        "INT16": "short", "int16_t": "short",
        "INT64": "long long", "int64_t": "long long", "LONG64": "long long",
        "BOOL": "bool", "_BOOL": "bool", "BOOLEAN": "bool",
        "CHAR": "char",
        "WCHAR": "wchar_t", "wchar": "wchar_t", 
        "VOID": "void", 
        "PVOID": "void*", "LPVOID": "void*", "HANDLE": "void*",
        "HWND": "void*", "HMODULE": "void*", "HINSTANCE": "void*", "HDC": "void*", "HKEY": "void*", "HCURSOR": "void*",
        "DWORD_PTR": "uintptr_t", "ULONG_PTR": "uintptr_t", "LONG_PTR": "intptr_t",
        "SIZE_T": "size_t", "SSIZE_T": "ssize_t",
        "LPCSTR": "const char*", "PCSTR": "const char*",
        "LPSTR": "char*", "PSTR": "char*",
        "LPCWSTR": "const wchar_t*", "PCWSTR": "const wchar_t*",
        "LPWSTR": "wchar_t*", "PWSTR": "wchar_t*",
        "LPTSTR": "char*", 
        "LPCTSTR": "const char*", 
        "DWORD": "unsigned long", 
        "ULONG": "unsigned long",
        "LONG": "long",
        "USHORT": "unsigned short",
        "SHORT": "short",
        "FLOAT": "float", 
        "DOUBLE": "double",
        "std::string": "char*", 
        "std::wstring": "wchar_t*", 
    }
    PRE_NORMALIZED_TYPES = {
        "int", "unsigned int", "char", "signed char", "unsigned char", 
        "short", "unsigned short", "long", "unsigned long", 
        "long long", "unsigned long long",
        "float", "double", "long double", "void", "bool",
        "intptr_t", "uintptr_t", "size_t", "ssize_t", "ptrdiff_t",
        "wchar_t",
        "int8_t", "uint8_t", "int16_t", "uint16_t", 
        "int32_t", "uint32_t", "int64_t", "uint64_t",
        "struct", "union", "enum",
    }

    def _normalize_single_type(self, type_str: str) -> str:
        if not type_str: return "unknown_type" 
        original_type_str_for_fallback = type_str 
        qualifiers, pointers, stripped_type = [], [], type_str.strip()
        changed = True
        while changed:
            changed = False
            for q in ["const ", "volatile "]:
                if stripped_type.lower().startswith(q):
                    qualifiers.append(stripped_type[:len(q)-1]); stripped_type = stripped_type[len(q):].strip(); changed = True
        while stripped_type.endswith("*"): pointers.append("*"); stripped_type = stripped_type[:-1].strip()
        
        base_type_str = stripped_type.strip()
        if not base_type_str: base_type_str = "void" if pointers else "unknown_qualifier_only"

        normalized_base_type = base_type_str
        if base_type_str not in self.PRE_NORMALIZED_TYPES and base_type_str.lower() not in self.PRE_NORMALIZED_TYPES:
            normalized_base_type = self.TYPE_NORMALIZATION_MAP.get(base_type_str, self.TYPE_NORMALIZATION_MAP.get(base_type_str.upper(), self.TYPE_NORMALIZATION_MAP.get(base_type_str.lower(), base_type_str)))
        elif base_type_str.lower() in self.PRE_NORMALIZED_TYPES: # Ensure canonical casing for pre-normalized
            normalized_base_type = base_type_str.lower()

        first_word_original = base_type_str.split(' ', 1)[0].lower()
        if first_word_original in ["struct", "union", "enum"] and normalized_base_type != base_type_str:
            if base_type_str not in self.TYPE_NORMALIZATION_MAP and base_type_str.upper() not in self.TYPE_NORMALIZATION_MAP and base_type_str.lower() not in self.TYPE_NORMALIZATION_MAP:
                normalized_base_type = base_type_str 

        final_parts = []
        unique_qualifiers = sorted(list(set(q.lower() for q in qualifiers)))
        for q_lower in unique_qualifiers:
            if q_lower == "const" and normalized_base_type.lower().startswith("const "): continue 
            final_parts.append(q_lower) 
        if normalized_base_type != "unknown_qualifier_only": final_parts.append(normalized_base_type)
        elif not unique_qualifiers and not pointers : return original_type_str_for_fallback 
        final_parts.append("".join(pointers)) 
        final_type = " ".join(p for p in final_parts if p).strip()

        if not final_type or final_type in ["const", "volatile"]:
            if pointers:
                reconstructed = ["void"]
                if unique_qualifiers: reconstructed = unique_qualifiers + reconstructed
                reconstructed.append("".join(pointers))
                return " ".join(reconstructed).strip()
            return original_type_str_for_fallback 
        return final_type

    def normalize_signatures(self, signature_data_list: list) -> list:
        if not signature_data_list: return []
        normalized_signatures = []
        for original_sig_obj in signature_data_list:
            if not isinstance(original_sig_obj, dict):
                normalized_signatures.append(original_sig_obj); continue
            try: sig = json.loads(json.dumps(original_sig_obj))
            except Exception:
                sig = {k: v for k, v in original_sig_obj.items() if k != 'parameters'}
                sig['parameters'] = [{p_k: p_v for p_k, p_v in p.items()} for p in original_sig_obj.get('parameters', [])]
            if "return_type" in sig and isinstance(sig["return_type"], str): sig["return_type"] = self._normalize_single_type(sig["return_type"])
            if "parameters" in sig and isinstance(sig["parameters"], list):
                for param in sig["parameters"]:
                    if isinstance(param, dict) and "type" in param and isinstance(param["type"], str):
                        param["type"] = self._normalize_single_type(param["type"])
            normalized_signatures.append(sig)
        return normalized_signatures

if __name__ == '__main__': 
    print("This module is not meant to be run directly.")
    print("Please use keyplug_source_extractor.py instead.")
    # Example main for direct testing (simplified)
    # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # main_logger = logging.getLogger("DecompilerIntegrationExample")
    # decompiler_integration = DecompilerIntegration(logger=main_logger)

    # # Dummy binary file path for testing
    # dummy_binary_name = "dummy_binary_for_test.exe"
    # test_output_dir = "test_decompiler_output"
    # with open(dummy_binary_name, "wb") as f: f.write(b"MZ\x00\x00PE\x00\x00Test") # Minimal valid PE-like structure

    # # Ensure the script path is correctly set if not using default logic in the class
    # current_dir = Path(__file__).parent.resolve()
    # # decompiler_integration.ghidra_script_template_path = current_dir / "ghidra_decompile_script.java"
    # # decompiler_integration.ida_script_template_path = current_dir / "ida_decompile_script.py"


    # main_logger.info("--- Test Decompilation with Ghidra (if available) ---")
    # if decompiler_integration.ghidra_available:
    #     main_logger.info(f"Ghidra is available. GHIDRA_HOME: {os.environ.get('GHIDRA_HOME')}")
    #     # Ensure the script path is correctly set if not using default logic in the class
    #     decompiler_integration.ghidra_script_template_path = current_dir / "ghidra_decompile_script.java" # Adjust as necessary
    #     if not decompiler_integration.ghidra_script_template_path.exists():
    #          main_logger.warning(f"Ghidra script template not found at {decompiler_integration.ghidra_script_template_path}, Ghidra test might fail or use internal template.")

    #     ghidra_results = decompiler_integration.decompile(dummy_binary_name, test_output_dir, decompiler_types=["ghidra"])
    #     main_logger.info(f"Ghidra results: {json.dumps(ghidra_results, indent=2)}")
    #     # Add asserts here based on expected outcomes if dummy_binary_name was a real binary
    #     # For example: assert "c_code" in ghidra_results.get("ghidra", {}) and ghidra_results["ghidra"]["c_code"] is not None
    # else:
    #     main_logger.warning("Ghidra not available or GHIDRA_HOME not set. Skipping Ghidra decompilation test.")

    # main_logger.info("\n--- Test Decompilation with RetDec (if available) ---")
    # if decompiler_integration.retdec_available:
    #     main_logger.info("RetDec is available.")
    #     retdec_results = decompiler_integration.decompile(dummy_binary_name, test_output_dir, decompiler_types=["retdec"])
    #     main_logger.info(f"RetDec results: {json.dumps(retdec_results, indent=2)}")
    # else:
    #     main_logger.warning("RetDec not available. Skipping RetDec decompilation test.")

    # main_logger.info("\n--- Test Decompilation with IDA Pro (if available) ---")
    # if decompiler_integration.ida_available:
    #     main_logger.info(f"IDA Pro is available. IDA_HOME: {os.environ.get('IDA_HOME')}")
    #     decompiler_integration.ida_script_template_path = current_dir / "ida_decompile_script.py" # Adjust as necessary
    #     if not decompiler_integration.ida_script_template_path.exists():
    #         main_logger.warning(f"IDA script template not found at {decompiler_integration.ida_script_template_path}, IDA test might fail or use internal template.")

    #     ida_results = decompiler_integration.decompile(dummy_binary_name, test_output_dir, decompiler_types=["ida"])
    #     main_logger.info(f"IDA Pro results: {json.dumps(ida_results, indent=2)}")
    # else:
    #     main_logger.warning("IDA Pro not available or IDA_HOME not set. Skipping IDA Pro decompilation test.")

    # main_logger.info("\n--- Test Consensus Output Generation ---")
    # # Create dummy output files for consensus testing
    # # These would normally be created by the actual decompiler runs
    # dummy_ghidra_c = os.path.join(test_output_dir, "decompiled_ghidra.c")
    # dummy_retdec_c = os.path.join(test_output_dir, "decompiled_retdec.c")
    # with open(dummy_ghidra_c, "w") as f: f.write("void ghidra_func() {\n  int x = 1;\n}\n// Common line\n")
    # with open(dummy_retdec_c, "w") as f: f.write("void retdec_func() {\n  int y = 2;\n}\n// Common line\n")

    # all_results_for_consensus = {
    #     "ghidra": {"c_code": dummy_ghidra_c, "signatures": None, "cfg_file_path": None},
    #     "retdec": {"c_code": dummy_retdec_c, "signatures": None, "cfg_file_path": None}
    # }
    # consensus_path = decompiler_integration.produce_consensus_output(all_results_for_consensus, test_output_dir, preferred_decompiler_order=["ghidra", "retdec"])
    # main_logger.info(f"Consensus C code generated at: {consensus_path}")
    # if consensus_path and os.path.exists(consensus_path):
    #     with open(consensus_path, 'r') as f_consensus:
    #         main_logger.info(f"Consensus content:\n{f_consensus.read()}")
    #     assert os.path.exists(consensus_path) # Check if file was created

    # main_logger.info("\n--- Test CFG Refinement ---")
    # # Create a dummy CFG file (e.g., from Ghidra)
    # dummy_ghidra_cfg = os.path.join(test_output_dir, "decompiled_ghidra_cfg.dot")
    # with open(dummy_ghidra_cfg, "w") as f: f.write("digraph CFG { node1 -> node2; }")

    # all_results_for_cfg = {
    #     "ghidra": {"c_code": dummy_ghidra_c, "signatures": None, "cfg_file_path": dummy_ghidra_cfg},
    #     "retdec": {"c_code": dummy_retdec_c, "signatures": None, "cfg_file_path": None} # RetDec might not output CFG in this format
    # }
    # refined_cfg_path = decompiler_integration.refine_cfg(dummy_binary_name, all_results_for_cfg, test_output_dir, preferred_decompiler_order=["ghidra"])
    # main_logger.info(f"Refined/Selected CFG at: {refined_cfg_path}")
    # if refined_cfg_path:
    #     assert os.path.exists(refined_cfg_path)

    # main_logger.info("\n--- Test Type Normalization ---")
    # # Example of raw signature data that might come from a decompiler's JSON output
    # raw_signatures_data = [
    #     {"name": "example_func1", "return_type": "INT32", "parameters": [{"name": "p1", "type": "LPCSTR"}, {"name": "p2", "type": "_DWORD"}]},
    #     {"name": "example_func2", "return_type": "VOID*", "parameters": [{"name": "data", "type": "BYTE[]"}, {"name": "size", "type": "UINT"}]},
    #     {"name": "global_callback_func", "return_type": "void (*)(int, char **)", "parameters": []}, # Test for function pointer
    #     {"name": "struct_user", "return_type": "void", "parameters": [{"name": "my_struct_ptr", "type": "struct MyStruct*"}]},
    #     {"name": "const_ptr_const_ptr_func", "return_type": "const char * const *", "parameters": []} # Test for complex const pointer
    # ]
    # normalized_signatures = decompiler_integration.normalize_signatures(raw_signatures_data)
    # main_logger.info(f"Normalized signatures: {json.dumps(normalized_signatures, indent=2)}")
    # # Add asserts here to check specific normalizations
    # assert normalized_signatures[0]["return_type"] == "int" # INT32 -> int
    # assert normalized_signatures[0]["parameters"][0]["type"] == "const char*" # LPCSTR -> const char*
    # assert normalized_signatures[0]["parameters"][1]["type"] == "unsigned long" # _DWORD -> unsigned long
    # assert normalized_signatures[1]["return_type"] == "void*" # VOID* -> void*
    # assert normalized_signatures[1]["parameters"][0]["type"] == "unsigned char[]" # BYTE[] -> unsigned char[]
    # assert normalized_signatures[1]["parameters"][1]["type"] == "unsigned int" # UINT -> unsigned int
    # assert normalized_signatures[2]["return_type"] == "void(*)(int, char**)" # Function pointer
    # assert normalized_signatures[3]["parameters"][0]["type"] == "struct MyStruct*" # Struct pointer
    # assert normalized_signatures[4]["return_type"] == "const char* const*" # Complex const pointer

    # # Clean up
    # main_logger.info("\n--- Cleaning up test files ---")
    # if os.path.exists(dummy_binary_name): os.remove(dummy_binary_name)
    # if os.path.exists(test_output_dir): shutil.rmtree(test_output_dir) # Recursively remove
    # main_logger.info(f"Removed dummy binary and test output directory: {test_output_dir}")

    # main_logger.info("--- All decompiler_integration.py tests completed ---")
[end of stego-analyzer/utils/decompiler_integration.py]
