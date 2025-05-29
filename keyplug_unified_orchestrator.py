#!/usr/bin/env python3
"""
KEYPLUG Unified Analysis Orchestrator (Modular Architecture)
-----------------------------------------------------------
Main entry point for the KEYPLUG analysis system.
Coordinates the analysis workflow, module loading, and result processing.

This modular architecture separates:
1. Pipeline configuration (keyplug_pipeline_config.py)
2. Module loading and initialization (keyplug_module_loader.py)
3. Results processing and reporting (keyplug_results_processor.py)
4. Main orchestration logic (this file)
"""

import os
import sys
import glob
import json
import time
import argparse
import traceback
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

# Import from the modular components
from keyplug_pipeline_config import get_pipeline_config
from keyplug_module_loader import ModuleLoader, OPENVINO_AVAILABLE, OV_CORE, PREFERRED_DEVICE
from keyplug_results_processor import ResultsProcessor


class UnifiedOrchestrator:
    """
    Main orchestrator that coordinates the analysis process.
    Handles CLI arguments, module loading, file/memory analysis,
    and result generation.
    """
    
    def __init__(self, base_output_dir="keyplug_unified_analysis", cli_args=None):
        """
        Initialize the unified orchestrator.
        
        Args:
            base_output_dir: Base directory for all analysis outputs
            cli_args: Command-line arguments dictionary
        """
        self.base_output_dir = base_output_dir
        self.cli_args = cli_args if cli_args else {}
        
        # Initialize key components
        self.pipeline_config = get_pipeline_config()
        self.module_loader = ModuleLoader(
            self.pipeline_config["module_imports"],
            use_openvino=not self.cli_args.get("no_openvino", False)
        )
        self.results_processor = ResultsProcessor(base_output_dir)
        
        # Analysis state tracking
        self.module_instances = {}
        self.analyzed_files = set()
        self.execution_stats = {
            "start_time": datetime.now().isoformat(),
            "completed_modules": 0,
            "total_modules": 0,
            "analyzed_files": 0,
            "failed_files": 0,
        }
        
        # Decompiler preference from CLI or default
        self.decompiler_list_pref = self.cli_args.get("decompiler_list", ['ghidra', 'retdec', 'ida'])
        if "all" in self.decompiler_list_pref:
            self.decompiler_list_pref = ['ghidra', 'retdec', 'ida'] 


        # Create output directories and initialize modules
        self._setup_output_dirs()
        self._initialize_modules()
        
        # Store OpenVINO status in analysis context
        self.results_processor.update_analysis_context({
            "openvino_status": {
                "available": OPENVINO_AVAILABLE,
                "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE else "N/A",
            },
        })
        
        print(f"Unified Orchestrator initialized. Output base: {self.base_output_dir}")
    
    def _setup_output_dirs(self):
        """Create all necessary output directories."""
        os.makedirs(self.base_output_dir, exist_ok=True)
        for module_name in self.pipeline_config["module_imports"].keys():
            dir_name = module_name.lower().replace("keyplug", "").replace("detection", "").replace("analyzer", "")
            output_dir = os.path.join(self.base_output_dir, f"{dir_name}_analysis")
            os.makedirs(output_dir, exist_ok=True)
    
    def _initialize_modules(self):
        """Initialize all modules based on the pipeline configuration."""
        self.module_instances = {}
        for stage_name, module_names, _ in self.pipeline_config["pipeline_stages"]:
            stage_disabled = self.cli_args.get(f"disable_{stage_name}", False)
            if stage_disabled: print(f"Stage '{stage_name}' is disabled by command-line flag"); continue
            
            for module_name in module_names:
                module_details = self.pipeline_config["module_details"].get(module_name, {})
                cli_flag = module_details.get("cli_flag", "")
                default_enabled = module_details.get("default_enabled", True)
                disabled_flag = f"disable_{cli_flag}" if cli_flag else ""
                enabled_flag = f"enable_{cli_flag}" if cli_flag else ""
                
                if cli_flag and self.cli_args.get(disabled_flag, False): print(f"Module '{module_name}' is disabled by --{disabled_flag}"); continue
                if not default_enabled and cli_flag and not self.cli_args.get(enabled_flag, False): print(f"Module '{module_name}' is disabled by default and not enabled by --{enabled_flag}"); continue
                
                requires_openvino = module_details.get("requires_openvino", False)
                if requires_openvino and not OPENVINO_AVAILABLE and not self.cli_args.get("force_no_openvino", False):
                    if not self.cli_args.get("force_modules", False): print(f"Warning: Module '{module_name}' requires OpenVINO but it's not available. Skipping module. Use --force_modules to attempt."); continue
                    else: print(f"Warning: Module '{module_name}' requires OpenVINO but it's not available. Forcing load due to --force_modules.")

                output_dir = os.path.join(self.base_output_dir, f"{module_name.lower().replace('keyplug', '')}_analysis")
                
                try:
                    module_init_args = {}
                    if module_name == "CodeIntentClassifier":
                        if self.cli_args.get("intent_model_path"): module_init_args["model_path"] = self.cli_args["intent_model_path"]
                        if self.cli_args.get("intent_vectorizer_path"): module_init_args["vectorizer_path"] = self.cli_args["intent_vectorizer_path"]
                        if self.cli_args.get("intent_ir_model_xml_path"): module_init_args["ir_model_xml_path"] = self.cli_args["intent_ir_model_xml_path"]
                    elif module_name == "VulnerabilityDetector":
                        if self.cli_args.get("vuln_model_path"): module_init_args["ml_model_path"] = self.cli_args["vuln_model_path"]
                        if self.cli_args.get("vuln_vectorizer_path"): module_init_args["ml_vectorizer_path"] = self.cli_args["vuln_vectorizer_path"]
                        if self.cli_args.get("vuln_ir_model_xml_path"): module_init_args["ir_model_xml_path"] = self.cli_args["vuln_ir_model_xml_path"]
                    elif module_name == "MalwarePatternLearner":
                         if self.cli_args.get("pattern_db_path"): module_init_args["database_path"] = self.cli_args["pattern_db_path"] 
                    elif module_name == "ProgramSynthesisEngine":
                        if self.cli_args.get("llm_config_path"):
                            llm_config_p = self.cli_args["llm_config_path"]
                            if os.path.exists(llm_config_p):
                                try:
                                    with open(llm_config_p, 'r') as f_cfg: module_init_args["llm_config"] = json.load(f_cfg)
                                except Exception as e_json: print(f"Warning: Could not load LLM config from {llm_config_p}: {e_json}")
                            else: print(f"Warning: LLM config path {llm_config_p} not found.")
                    elif module_name == "CompilerSpecificRecovery":
                        if self.cli_args.get("compiler_idiom_db_path"): module_init_args["idiom_db_path"] = self.cli_args["compiler_idiom_db_path"]
                    elif module_name == "IntelPinToolRunner":
                        if self.cli_args.get("pin_executable_path"): module_init_args["pin_executable_path"] = self.cli_args["pin_executable_path"]
                    elif module_name == "SymbolicExecutor":
                        if self.cli_args.get("symbolic_engine_config_path"):
                            sym_config_p = self.cli_args["symbolic_engine_config_path"]
                            if os.path.exists(sym_config_p):
                                try:
                                    with open(sym_config_p, 'r') as f_cfg: module_init_args["engine_config"] = json.load(f_cfg)
                                except Exception as e_json: print(f"Warning: Could not load Symbolic Engine config from {sym_config_p}: {e_json}")
                            else: print(f"Warning: Symbolic Engine config path {sym_config_p} not found.")
                    instance = self.module_loader.create_instance(module_name, output_dir, component_name=module_name, **module_init_args)
                    self.module_instances[module_name] = instance
                except Exception as e: print(f"Error initializing module {module_name}: {e}\n{traceback.format_exc()}")
        
        print(f"Initialized {len(self.module_instances)} analysis modules")
        self.execution_stats["total_modules"] = len(self.module_instances)
    
    def get_stage_dependencies(self, stage_name):
        for s_name, _, deps in self.pipeline_config["pipeline_stages"]:
            if s_name == stage_name:
                if not deps: return set()
                direct_deps = {deps} if isinstance(deps, str) else set(deps)
                all_deps = direct_deps.copy()
                for dep in direct_deps: all_deps.update(self.get_stage_dependencies(dep))
                return all_deps
        return set()
    
    def get_stage_modules(self, stage_name):
        for s_name, modules, _ in self.pipeline_config["pipeline_stages"]:
            if s_name == stage_name: return modules
        return []
    
    def analyze_file(self, file_path):
        file_name = os.path.basename(file_path)
        print(f"\n[+] Analyzing File: {file_name}")
        self.results_processor.register_file(file_path)
        self.analyzed_files.add(file_name)
        self.execution_stats["analyzed_files"] = len(self.analyzed_files)
        file_context = {"file_path": file_path, "file_name": file_name, "analysis_started": datetime.now().isoformat()}
        self.results_processor.update_analysis_context(file_context)
        
        completed_stages = set()
        pending_stages = {stage[0] for stage in self.pipeline_config["pipeline_stages"]}
        if 'memory' in pending_stages: pending_stages.remove('memory')
        
        while pending_stages:
            for stage_name, _, _ in self.pipeline_config["pipeline_stages"]:
                if stage_name not in pending_stages or stage_name == 'memory': continue
                if not self.get_stage_dependencies(stage_name).issubset(completed_stages): continue
                print(f"\n--- Running Stage: {stage_name} ---")
                self._run_stage_modules_for_file(stage_name, file_path, file_name)
                completed_stages.add(stage_name)
                pending_stages.remove(stage_name)
        
        return self.results_processor.get_all_file_results(file_name)
    
    def _run_stage_modules_for_file(self, stage_name, file_path, file_name):
        module_names = self.get_stage_modules(stage_name)
        stage_success = True
        
        for module_name in module_names:
            instance = self.module_instances.get(module_name)
            if not instance: print(f"Module {module_name} not initialized, skipping"); continue
            
            context = self.results_processor.get_analysis_context() 
            file_specific_context = self.results_processor.get_analysis_context(True, file_name)

            print(f"Running: {module_name} on {file_name}")
            start_time = time.time()
            
            try:
                file_specific_output_base = os.path.join(self.base_output_dir, file_name + "_analysis")
                os.makedirs(file_specific_output_base, exist_ok=True)
                module_output_dir = os.path.join(file_specific_output_base, f"{module_name.lower().replace('keyplug', '').replace('engine','').replace('integration','').replace('analyzer','').replace('detection','').replace('recovery','').replace('extractor','').replace('decrypt','')}_outputs")
                os.makedirs(module_output_dir, exist_ok=True)

                if module_name == "DecompilerIntegration":
                    decompiler_outputs_dict = instance.decompile(file_path, module_output_dir, decompiler_types=self.decompiler_list_pref)
                    consensus_c_path = instance.produce_consensus_output(decompiler_outputs_dict, module_output_dir, preferred_decompiler_order=self.decompiler_list_pref) if sum(1 for o in decompiler_outputs_dict.values() if o and o.get("c_code")) >=1 else None
                    refined_cfg_path = instance.refine_cfg(file_path, decompiler_outputs_dict, module_output_dir, preferred_decompiler_order=self.decompiler_list_pref)
                    normalized_outputs = {}
                    for d_name, d_data in decompiler_outputs_dict.items():
                        current_out = d_data.copy() if d_data else {}
                        if d_data and d_data.get("signatures") and os.path.exists(d_data["signatures"]):
                            with open(d_data["signatures"], 'r', encoding='utf-8') as f_s: raw_sigs = json.load(f_s)
                            norm_sigs = instance.normalize_signatures(raw_sigs)
                            norm_sig_p = os.path.join(module_output_dir, f"{d_name}_norm_sigs.json")
                            with open(norm_sig_p, 'w', encoding='utf-8') as f_ns: json.dump(norm_sigs, f_ns, indent=2)
                            current_out["normalized_signatures"] = norm_sig_p
                        normalized_outputs[d_name] = current_out
                    module_res = {"status": "completed" if consensus_c_path or refined_cfg_path or any(v.get("c_code") for v in normalized_outputs.values()) else "error_no_output", 
                                  "decompiler_outputs": normalized_outputs, "consensus_c_code": consensus_c_path, "refined_cfg_path": refined_cfg_path}
                    self.results_processor.store_file_result(file_name, module_name, module_res)
                    c_file, sig_file = None, None
                    if consensus_c_path: c_file = consensus_c_path
                    for pref in self.decompiler_list_pref:
                        if c_file and normalized_outputs.get(pref, {}).get("normalized_signatures"): sig_file = normalized_outputs[pref]["normalized_signatures"]; break
                        if not c_file and normalized_outputs.get(pref, {}).get("c_code"): c_file = normalized_outputs[pref]["c_code"]; sig_file = normalized_outputs[pref].get("normalized_signatures"); break
                    self.results_processor.update_analysis_context({"primary_c_file_path": c_file, "primary_signatures_path": sig_file, "all_decompiler_outputs": normalized_outputs}, file_specific=True, file_name_filter=file_name)

                elif module_name == "TypePropagator":
                    if file_specific_context.get("primary_c_file_path") and os.path.exists(file_specific_context["primary_c_file_path"]):
                        res_types = instance.propagate_types(file_specific_context["primary_c_file_path"], file_specific_context.get("primary_signatures_path"), file_specific_context.get("existing_types"))
                        self.results_processor.store_file_result(file_name, module_name, {"status": "completed", "inferred_types": res_types})
                    else: self.results_processor.store_file_result(file_name, module_name, {"status": "error", "message": "Missing C file for TypePropagator."}); stage_success = False
                
                elif module_name == "VulnerabilityDetector":
                    c_file = file_specific_context.get("primary_c_file_path")
                    combined_res = {"status": "skipped_no_c_file", "pattern_scan": {}, "ml_scan": {}, "taint_analysis_scan": {}}
                    if c_file and os.path.exists(c_file):
                        with open(c_file, 'r', encoding='utf-8') as f: c_content = f.read()
                        full_scan_res = instance.scan_for_vulnerabilities(c_content, c_file)
                        pattern_res_list = full_scan_res.get("pattern_vulnerabilities_found", [])
                        ml_res_dict = full_scan_res.get("ml_vulnerability_analysis", {})
                        taint_input = list(pattern_res_list) 
                        if isinstance(ml_res_dict.get("ml_findings"), list): taint_input.extend(ml_res_dict["ml_findings"])
                        taint_placeholder_res = instance.perform_taint_analysis(c_content, c_file, taint_input)
                        combined_res = {"status":"completed", "pattern_scan": {"vulnerabilities_found":pattern_res_list}, "ml_scan":ml_res_dict, "taint_analysis_scan":{"status":"placeholder_executed", "findings":taint_placeholder_res}}
                    else: stage_success = False; combined_res["message"] = "Missing C file."
                    self.results_processor.store_file_result(file_name, module_name, combined_res)

                elif module_name == "CodeIntentClassifier":
                    c_file = file_specific_context.get("primary_c_file_path")
                    if c_file and os.path.exists(c_file):
                        with open(c_file, 'r', encoding='utf-8') as f: c_content = f.read()
                        class_res = instance.classify_code_block(c_content)
                        self.results_processor.store_file_result(file_name, module_name, class_res)
                    else: self.results_processor.store_file_result(file_name, module_name, {"status":"error", "message":"Missing C file."}); stage_success = False
                
                elif module_name == "ProgramSynthesisEngine":
                    observed_behavior = {"description": f"Synthesize code based on analysis of {file_name}", "file_path": file_path}
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8', errors='ignore') as f_c: 
                                observed_behavior["pseudo_code"] = f_c.read(2048) 
                        except Exception as e: print(f"Orchestrator: Could not read {primary_c_file} for ProgSynth: {e}")
                    
                    all_decomp_outputs = file_specific_context.get("all_decompiler_outputs", {})
                    func_signatures = []
                    if isinstance(all_decomp_outputs, dict): 
                        for decompiler_name_iter, decompiler_output in all_decomp_outputs.items(): 
                            if isinstance(decompiler_output, dict) and decompiler_output.get("normalized_signatures"):
                                sig_path = decompiler_output["normalized_signatures"]
                                if sig_path and os.path.exists(sig_path): 
                                    try:
                                        with open(sig_path, 'r', encoding='utf-8') as f_s: func_signatures.extend(json.load(f_s))
                                    except Exception as e_s: print(f"Orchestrator: Could not load signatures {sig_path}: {e_s}")
                    if func_signatures: observed_behavior["decompiled_function_signatures"] = func_signatures[:10] 
                    
                    vuln_detector_results_all = self.results_processor.get_file_results(file_name, "VulnerabilityDetector")
                    if vuln_detector_results_all:
                        pattern_vulns = vuln_detector_results_all.get("pattern_scan",{}).get("vulnerabilities_found",[])
                        ml_vulns = vuln_detector_results_all.get("ml_scan",{}).get("ml_findings",[])
                        if pattern_vulns or ml_vulns : observed_behavior["vulnerabilities_found"] = (pattern_vulns + ml_vulns)[:5] 

                    api_seq_results_all = self.results_processor.get_file_results(file_name, "KeyplugApiSequenceDetector") 
                    if api_seq_results_all and isinstance(api_seq_results_all, dict) and api_seq_results_all.get("status") == "completed":
                         observed_behavior["api_sequences"] = api_seq_results_all.get("suspicious_api_sequences", [])[:5]

                    target_lang = self.cli_args.get("synthesis_target_lang", "python")
                    result_code = instance.synthesize_code(observed_behavior=observed_behavior, target_language=target_lang)
                    self.results_processor.store_file_result(file_name, module_name, {"status": "placeholder_executed", "target_language": target_lang, "synthesized_code_placeholder": result_code})

                elif module_name == "CompilerSpecificRecovery": 
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    code_snippets = [] 
                    snippet_line_count = self.cli_args.get("compiler_snippet_lines", 50) 
                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8', errors='ignore') as f_c:
                                for _ in range(snippet_line_count): 
                                    line = f_c.readline()
                                    if not line: break
                                    code_snippets.append(line.strip())
                        except Exception as e_cs: print(f"Orchestrator: Could not read {primary_c_file} for CompilerSpecificRecovery: {e_cs}")
                    if not code_snippets: 
                        print("Orchestrator: CompilerSpecificRecovery: No C code snippets from primary_c_file, using default placeholder snippets.")
                        code_snippets = ["push ebp", "mov ebp, esp"] 
                    
                    identified_compiler = instance.identify_compiler_from_idioms(code_snippets=code_snippets)
                    self.results_processor.store_file_result(file_name, module_name, {"status": "executed", "identified_compiler": identified_compiler, "snippets_used_count": len(code_snippets)})

                elif module_name == "IntelPTAnalyzer":
                    pt_trace_suffix = self.cli_args.get("pt_trace_suffix", ".pt")
                    actual_trace_path = file_path + pt_trace_suffix 
                    if not os.path.exists(actual_trace_path):
                        print(f"Orchestrator: IntelPTAnalyzer: Trace file '{actual_trace_path}' not found for binary '{file_path}'. Module will report error internally.")
                    pt_res = instance.process_pt_trace(trace_file_path=actual_trace_path, binary_context_path=file_path)
                    self.results_processor.store_file_result(file_name, module_name, pt_res)
                
                elif module_name == "IntelPinToolRunner":
                    pintool_name = self.cli_args.get("default_pintool_name", "manual_trace.so")
                    options_str = self.cli_args.get("default_pintool_options", '{}') 
                    pintool_opts = None
                    try: pintool_opts = json.loads(options_str)
                    except json.JSONDecodeError as e_json: print(f"Orchestrator: Invalid JSON for pintool options: '{options_str}'. Error: {e_json}. Using no options.")
                    
                    pintool_prefix = self.cli_args.get("pintool_path_prefix", "") 
                    binary_arguments_for_pin = self.cli_args.get("pin_target_binary_args", []) 
                    
                    pin_res = instance.run_pin_tool(
                        binary_path=file_path, 
                        pintool_name=pintool_name, 
                        pintool_options=pintool_opts, 
                        pintool_path_prefix=pintool_prefix,
                        binary_args=binary_arguments_for_pin
                    )
                    self.results_processor.store_file_result(file_name, module_name, pin_res)

                elif hasattr(instance, 'analyze'): 
                    result = instance.analyze(file_path, context=context) 
                    self.results_processor.store_file_result(file_name, module_name, result)
                else:
                    error_msg = f"Module {module_name} does not have a recognized analysis method."
                    print(f"  Warning: {error_msg}")
                    self.results_processor.store_file_result(file_name, module_name, {"status": "skipped", "message": error_msg})
                
                self.execution_stats["completed_modules"] += 1 
                if module_name not in ["DecompilerIntegration"]: 
                    output_filepath = self.results_processor.save_component_result_to_file(file_name, module_name, module_output_dir)
                    if output_filepath: print(f"  Results for {module_name} also saved to: {output_filepath}")
            
            except Exception as e:
                print(f"Error running {module_name} on {file_name}: {e}\n{traceback.format_exc()}")
                self.results_processor.store_file_result(file_name, module_name, {"status": "error", "message": str(e), "traceback": traceback.format_exc()})
                stage_success = False
            
            exec_time = time.time() - start_time
            print(f"  Completed in {exec_time:.2f} seconds")
        
        return stage_success
    
    def analyze_memory_dump(self, dump_path, profile=None):
        dump_name = os.path.basename(dump_path)
        print(f"\n[+] Analyzing Memory Dump: {dump_name}")
        self.results_processor.register_memory_dump(dump_path)
        if self.cli_args.get("disable_memory", False): print("Memory analysis disabled."); return self.results_processor.get_memory_results()
        
        mem_analyzer = self.module_instances.get("KeyplugMemoryAnalyzer")
        if not mem_analyzer: print("Memory analyzer not initialized."); return self.results_processor.get_memory_results()
        
        print(f"Running Memory Analysis on {dump_name}")
        start_time = time.time()
        try:
            if hasattr(mem_analyzer, 'analyze_dump'):
                result = mem_analyzer.analyze_dump(dump_path, profile, self.results_processor.get_analysis_context())
                self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", result)
                self.execution_stats["completed_modules"] += 1
            else: self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", {"status":"error", "message":"analyze_dump not found"})
        except Exception as e:
            print(f"Error in memory analysis: {e}\n{traceback.format_exc()}")
            self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", {"status":"error", "message":str(e), "traceback":traceback.format_exc()})
        print(f"Memory Analysis completed in {time.time() - start_time:.2f}s")
        return self.results_processor.get_memory_results()
    
    def analyze_files(self, file_paths):
        if not file_paths: print("No files to analyze"); return {}
        total = len(file_paths); print(f"\n[+] Starting batch analysis of {total} files")
        if self.cli_args.get("parallel", False):
            workers = min(os.cpu_count() or 4, total, 8); print(f"Using parallel execution with {workers} workers")
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                f_to_f = {executor.submit(self._analyze_file_wrapper, fp): fp for fp in file_paths}
                for i, future in enumerate(concurrent.futures.as_completed(f_to_f)):
                    fp, fn = f_to_f[future], os.path.basename(f_to_f[future])
                    try: future.result(); print(f"[{i+1}/{total}] Completed {fn}")
                    except Exception as e: print(f"[{i+1}/{total}] Error analyzing {fn}: {e}"); self.execution_stats["failed_files"]+=1
        else:
            for i, fp in enumerate(file_paths):
                fn = os.path.basename(fp); print(f"\n[{i+1}/{total}] Analyzing {fn}")
                try: self.analyze_file(fp)
                except Exception as e: print(f"Error analyzing {fn}: {e}\n{traceback.format_exc()}"); self.execution_stats["failed_files"]+=1
        print(f"\n[+] Completed analysis of {total} files")
        return self.results_processor.file_results
    
    def _analyze_file_wrapper(self, file_path):
        orchestrator = UnifiedOrchestrator(self.base_output_dir, self.cli_args) 
        return orchestrator.analyze_file(file_path)
    
    def run_global_analysis(self):
        print("\n[+] Running Global Analysis")
        if self.cli_args.get("disable_global", False): print("Global analysis disabled."); return self.results_processor.global_results
        
        for stage_name, modules, _ in self.pipeline_config["pipeline_stages"]:
            if stage_name != "global": continue
            for mod_name in modules:
                instance = self.module_instances.get(mod_name)
                if not instance: print(f"Global module {mod_name} not initialized."); continue
                print(f"Running Global Analysis: {mod_name}"); start_time = time.time()
                try:
                    all_file_results = self.results_processor.file_results
                    memory_results = self.results_processor.get_memory_results()
                    # Pass general context too, which might include OpenVINO status etc.
                    global_context_for_module = {
                        "file_results": all_file_results,
                        "memory_results": memory_results, 
                        **self.results_processor.get_analysis_context() 
                    }
                    res = None

                    if mod_name == "HybridAnalyzer" and hasattr(instance, 'analyze'):
                        # Correctly passing specific parts of context to HybridAnalyzer
                        res = instance.analyze(
                            static_results=global_context_for_module["file_results"], 
                            dynamic_results=global_context_for_module["memory_results"] # Or other dynamic sources if structured differently
                        )
                    elif hasattr(instance, 'analyze_all'): 
                        res = instance.analyze_all(context=global_context_for_module)
                    elif hasattr(instance, 'correlate'): 
                        res = instance.correlate(all_file_results=all_file_results, all_global_results=self.results_processor.global_results, context=global_context_for_module)
                    elif hasattr(instance, 'update_database'): 
                        res = instance.update_database(context=global_context_for_module)
                    elif mod_name == "MalwarePatternLearner" and hasattr(instance, 'learn_from_analysis'):
                        for file_data in all_file_results.values(): 
                            instance.learn_from_analysis(file_data)
                        res = {"status":"learning_complete", "patterns_count": len(instance.patterns_db.get("patterns",[]))}
                    else: 
                        print(f"Warning: {mod_name} has no recognized global method.")
                        res = {"status":"error", "message":"No recognized global method"}
                    
                    self.results_processor.store_global_result(mod_name, res)
                    self.execution_stats["completed_modules"] += 1
                except Exception as e:
                    print(f"Error in global {mod_name}: {e}\n{traceback.format_exc()}")
                    self.results_processor.store_global_result(mod_name, {"status":"error", "message":str(e), "traceback":traceback.format_exc()})
                print(f"Global {mod_name} completed in {time.time() - start_time:.2f}s")
        return self.results_processor.global_results
    
    def generate_reports(self):
        print("\n[+] Generating Consolidated Reports")
        self.execution_stats["end_time"] = datetime.now().isoformat()
        self.results_processor.update_analysis_context({"execution_stats": self.execution_stats, "total_execution_time": self._calculate_total_execution_time()})
        report_paths = self.results_processor.generate_consolidated_report()
        for fmt, path in report_paths.items(): print(f"  {fmt.upper()}: {path}")
        return report_paths
    
    def _calculate_total_execution_time(self):
        start_time = datetime.fromisoformat(self.execution_stats["start_time"])
        end_time = datetime.fromisoformat(self.execution_stats["end_time"])
        return (end_time - start_time).total_seconds()

def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Unified Analysis Orchestrator', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    input_group = parser.add_argument_group('Input Sources')
    input_group.add_argument('-f', '--file', help='Analyze a single file')
    input_group.add_argument('-d', '--dir', help='Directory containing files to analyze')
    input_group.add_argument('-p', '--pattern', default='*', help='File pattern in directory')
    input_group.add_argument('--memory-dump', help='Path to memory dump file')
    input_group.add_argument('--memory-profile', help='Memory dump profile (Volatility)')
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default='keyplug_unified_analysis', help='Base output directory')
    
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO')
    perf_group.add_argument('--parallel', action='store_true', help='Enable parallel file analysis')
    perf_group.add_argument('--force-modules', action='store_true', help='Force load modules if requirements not met')
    
    pipeline_group = parser.add_argument_group('Pipeline Control')
    pipeline_config = get_pipeline_config()
    for stage_name, _, _ in pipeline_config["pipeline_stages"]:
        pipeline_group.add_argument(f'--disable-{stage_name}', action='store_true', help=f'Disable {stage_name} stage')
    for mod_name, details in pipeline_config["module_details"].items():
        flag, enabled_by_default = details.get("cli_flag"), details.get("default_enabled", True)
        if flag:
            action = 'store_true' 
            help_text = f'Enable {mod_name}' if not enabled_by_default else f'Disable {mod_name}'
            arg_name = f'--enable-{flag}' if not enabled_by_default else f'--disable-{flag}'
            pipeline_group.add_argument(arg_name, action=action, help=help_text)

    decompiler_group = parser.add_argument_group('Decompiler Options')
    decompiler_group.add_argument('--decompiler-list', nargs='+', default=['ghidra', 'retdec', 'ida'], choices=['ghidra', 'retdec', 'ida', 'all'], help='Decompilers to try. Order implies preference.')

    module_config_group = parser.add_argument_group('Module Configurations')
    module_config_group.add_argument('--intent-model-path', help="Path to CodeIntentClassifier model.")
    module_config_group.add_argument('--intent-vectorizer-path', help="Path to CodeIntentClassifier vectorizer.")
    module_config_group.add_argument('--intent-ir-model-xml-path', help="Path to CodeIntentClassifier OpenVINO IR XML.")
    module_config_group.add_argument('--train-vuln-model', metavar='PATH', help="Path to data for VulnerabilityDetector ML training.")
    module_config_group.add_argument('--vuln-model-path', help="Path to VulnerabilityDetector ML model.")
    module_config_group.add_argument('--vuln-vectorizer-path', help="Path to VulnerabilityDetector ML vectorizer.")
    module_config_group.add_argument('--vuln-ir-model-xml-path', help="Path to VulnerabilityDetector OpenVINO IR XML.")
    module_config_group.add_argument('--pattern-db-path', help="Path to MalwarePatternLearner DB JSON.")
    module_config_group.add_argument('--llm-config-path', help="Path to JSON config for ProgramSynthesisEngine LLM.")
    module_config_group.add_argument('--compiler-idiom-db-path', help="Path to JSON DB for CompilerSpecificRecovery.")
    module_config_group.add_argument('--pin-executable-path', default="pin", help="Path to Intel Pin executable.")
    module_config_group.add_argument('--symbolic-engine-config-path', help="Path to JSON config for SymbolicExecutor.")
    
    module_config_group.add_argument('--synthesis-target-lang', default="python", choices=["python", "c", "auto"], help="Target language for ProgramSynthesisEngine.")
    module_config_group.add_argument('--compiler-snippet-lines', type=int, default=50, help="Number of lines from C file for CompilerSpecificRecovery snippets.") 
    module_config_group.add_argument('--pt-trace-suffix', default=".pt", help="Suffix to append to binary path to find Intel PT trace file.")
    module_config_group.add_argument('--default-pintool-name', default="manual_trace.so", help="Default Pintool name for IntelPinToolRunner.")
    module_config_group.add_argument('--default-pintool-options', type=str, default='{"-o": "pintool_default_output.txt"}', help="JSON string of default Pintool options for IntelPinToolRunner.")
    module_config_group.add_argument('--pintool-path-prefix', default="", help="Path prefix for Pintools for IntelPinToolRunner.")
    module_config_group.add_argument('--pin-target-binary-args', nargs='*', default=[], help="Arguments for the target binary when run with Pin (list of strings).")


    args = parser.parse_args()
    cli_args_dict = vars(args)
    
    if not os.path.exists(args.output): os.makedirs(args.output)
    
    orchestrator = UnifiedOrchestrator(args.output, cli_args_dict)
    
    start_time_main = time.time()
    files_to_analyze_main = []
    
    if args.file:
        if os.path.exists(args.file): files_to_analyze_main.append(args.file)
        else: print(f"Error: File {args.file} not found"); return 1
    elif args.dir:
        if os.path.exists(args.dir):
            files_to_analyze_main.extend([os.path.join(args.dir, f) for f in glob.glob(os.path.join(args.dir, args.pattern)) if os.path.isfile(os.path.join(args.dir, f))])
            if not files_to_analyze_main: print(f"No files matching '{args.pattern}' in '{args.dir}'")
        else: print(f"Error: Directory {args.dir} not found"); return 1
    
    if files_to_analyze_main: orchestrator.analyze_files(files_to_analyze_main)
    
    if args.memory_dump:
        if os.path.exists(args.memory_dump): orchestrator.analyze_memory_dump(args.memory_dump, profile=args.memory_profile)
        else: print(f"Error: Memory dump {args.memory_dump} not found"); return 1
    
    if files_to_analyze_main or args.memory_dump: orchestrator.run_global_analysis()
    
    orchestrator.generate_reports()
    
    total_time_main = time.time() - start_time_main
    print(f"\n[+] Analysis Complete. Total execution time: {total_time_main:.2f} seconds ({total_time_main/60:.2f} minutes)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

```
