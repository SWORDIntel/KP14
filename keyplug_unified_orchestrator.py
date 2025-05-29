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
        # Create base output directory
        os.makedirs(self.base_output_dir, exist_ok=True)
        
        # Create a directory for each module
        for module_name in self.pipeline_config["module_imports"].keys():
            # Sanitize module name for directory
            dir_name = module_name.lower().replace("keyplug", "").replace("detection", "").replace("analyzer", "")
            output_dir = os.path.join(self.base_output_dir, f"{dir_name}_analysis")
            os.makedirs(output_dir, exist_ok=True)
    
    def _initialize_modules(self):
        """Initialize all modules based on the pipeline configuration."""
        # Reset module instances
        self.module_instances = {}
        
        # Loop through all stages in the pipeline
        for stage_name, module_names, _ in self.pipeline_config["pipeline_stages"]:
            # Check if this stage is disabled entirely
            stage_disabled = self.cli_args.get(f"disable_{stage_name}", False)
            if stage_disabled:
                print(f"Stage '{stage_name}' is disabled by command-line flag")
                continue
            
            for module_name in module_names:
                # Check if module is disabled individually
                module_details = self.pipeline_config["module_details"].get(module_name, {})
                cli_flag = module_details.get("cli_flag", "")
                default_enabled = module_details.get("default_enabled", True)
                
                # Check if module is disabled
                disabled_flag = f"disable_{cli_flag}"
                enabled_flag = f"enable_{cli_flag}"
                
                if self.cli_args.get(disabled_flag, False):
                    print(f"Module '{module_name}' is disabled by --{disabled_flag}")
                    continue
                
                # For modules disabled by default, check if explicitly enabled
                if not default_enabled and not self.cli_args.get(enabled_flag, False):
                    print(f"Module '{module_name}' is disabled by default and not enabled by --{enabled_flag}")
                    continue
                
                # Check if module requires OpenVINO and it's not available
                requires_openvino = module_details.get("requires_openvino", False)
                if requires_openvino and not OPENVINO_AVAILABLE and not self.cli_args.get("force_no_openvino", False):
                    print(f"Warning: Module '{module_name}' requires OpenVINO but it's not available")
                    if not self.cli_args.get("force_modules", False):
                        print(f"  Skipping module. Use --force_modules to attempt to load it anyway.")
                        continue
                
                # Create module output directory
                output_dir = os.path.join(
                    self.base_output_dir, 
                    f"{module_name.lower().replace('keyplug', '')}_analysis"
                )
                
                # Create and store module instance
                try:
                    instance = self.module_loader.create_instance(module_name, output_dir, component_name=module_name)
                    self.module_instances[module_name] = instance
                except Exception as e:
                    print(f"Error initializing module {module_name}: {e}")
                    print(traceback.format_exc())
        
        print(f"Initialized {len(self.module_instances)} analysis modules")
        self.execution_stats["total_modules"] = len(self.module_instances)
    
    def get_stage_dependencies(self, stage_name):
        """
        Get all dependencies for a stage, including transitive dependencies.
        
        Args:
            stage_name: Name of the stage to get dependencies for
            
        Returns:
            Set of stage names that this stage depends on
        """
        # Find the stage's direct dependencies
        for s_name, _, deps in self.pipeline_config["pipeline_stages"]:
            if s_name == stage_name:
                if not deps:
                    return set()
                
                # Handle single string or list
                if isinstance(deps, str):
                    direct_deps = {deps}
                else:
                    direct_deps = set(deps)
                
                # Recursively get dependencies of dependencies
                all_deps = direct_deps.copy()
                for dep in direct_deps:
                    all_deps.update(self.get_stage_dependencies(dep))
                
                return all_deps
        
        return set()
    
    def get_stage_modules(self, stage_name):
        """
        Get all module names for a stage.
        
        Args:
            stage_name: Name of the stage
            
        Returns:
            List of module names in the stage
        """
        for s_name, modules, _ in self.pipeline_config["pipeline_stages"]:
            if s_name == stage_name:
                return modules
        return []
    
    def analyze_file(self, file_path):
        """
        Analyze a single file using all appropriate modules.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of analysis results
        """
        file_name = os.path.basename(file_path)
        print(f"\n[+] Analyzing File: {file_name}")
        
        # Register file with results processor
        self.results_processor.register_file(file_path)
        
        # Track file for stats
        self.analyzed_files.add(file_name)
        self.execution_stats["analyzed_files"] = len(self.analyzed_files)
        
        # Initialize analysis context for this file
        file_context = {
            "file_path": file_path,
            "file_name": file_name,
            "analysis_started": datetime.now().isoformat(),
        }
        self.results_processor.update_analysis_context(file_context)
        
        # Execute modules by stage, respecting dependencies
        completed_stages = set()
        pending_stages = {stage[0] for stage in self.pipeline_config["pipeline_stages"]}
        
        # Special case: 'memory' stage doesn't apply to file analysis
        if 'memory' in pending_stages:
            pending_stages.remove('memory')
        
        # Process stages until all are completed
        while pending_stages:
            for stage_name, module_names, deps in self.pipeline_config["pipeline_stages"]:
                # Skip if not a pending stage or memory stage
                if stage_name not in pending_stages or stage_name == 'memory':
                    continue
                
                # Check if dependencies are satisfied
                required_stages = self.get_stage_dependencies(stage_name)
                if not required_stages.issubset(completed_stages):
                    # Dependencies not met, skip for now
                    continue
                
                # Run all modules in this stage
                print(f"\n--- Running Stage: {stage_name} ---")
                stage_success = self._run_stage_modules_for_file(stage_name, file_path, file_name)
                
                # Mark stage as completed regardless of success
                # (We don't want to block the pipeline if a stage fails)
                completed_stages.add(stage_name)
                pending_stages.remove(stage_name)
        
        # All stages completed, return consolidated results
        return self.results_processor.get_all_file_results(file_name)
    
    def _run_stage_modules_for_file(self, stage_name, file_path, file_name):
        """
        Run all modules for a specific stage on a file.
        
        Args:
            stage_name: Name of the stage
            file_path: Path to the file
            file_name: Name of the file
            
        Returns:
            True if all modules ran successfully, False otherwise
        """
        module_names = self.get_stage_modules(stage_name)
        stage_success = True
        
        for module_name in module_names:
            # Get the module instance
            instance = self.module_instances.get(module_name)
            if not instance:
                print(f"Module {module_name} not initialized, skipping")
                continue
            
            # Get the current analysis context
            context = self.results_processor.get_analysis_context()
            
            # Run the module
            print(f"Running: {module_name} on {file_name}")
            start_time = time.time()
            
            try:
                # Construct a unique output directory for this module and this specific file
                file_specific_output_base = os.path.join(self.base_output_dir, file_name + "_analysis")
                os.makedirs(file_specific_output_base, exist_ok=True)
                module_output_dir = os.path.join(
                    file_specific_output_base,
                    f"{module_name.lower().replace('keyplug', '').replace('engine','').replace('integration','').replace('analyzer','').replace('detection','').replace('recovery','').replace('extractor','').replace('decrypt','')}_outputs"
                )
                os.makedirs(module_output_dir, exist_ok=True)

                if module_name == "DecompilerIntegration":
                    decompiler_outputs_dict = instance.decompile(
                        file_path, 
                        module_output_dir, 
                        decompiler_types=self.decompiler_list_pref,
                        functions=None 
                    )
                    
                    consensus_c_path = None
                    successful_c_outputs_count = sum(
                        1 for out_data in decompiler_outputs_dict.values() 
                        if out_data and out_data.get("c_code") and os.path.exists(out_data["c_code"])
                    )
                    
                    if successful_c_outputs_count >= 1:
                        consensus_c_path = instance.produce_consensus_output(
                            decompiler_outputs_dict, 
                            module_output_dir 
                        )
                    
                    refined_cfg_path = instance.refine_cfg(
                        file_path, 
                        decompiler_outputs_dict, 
                        module_output_dir 
                    )
                    
                    normalized_decompiler_outputs = {}
                    for decomp_name, out_data in decompiler_outputs_dict.items():
                        current_decomp_output = out_data.copy() if out_data else {}
                        if out_data and out_data.get("signatures") and os.path.exists(out_data["signatures"]):
                            try:
                                with open(out_data["signatures"], 'r', encoding='utf-8') as f_sig:
                                    raw_sigs = json.load(f_sig)
                                normalized_sigs_list = instance.normalize_signatures(raw_sigs) 
                                
                                norm_sig_filename = f"{decomp_name}_normalized_signatures.json"
                                norm_sig_path = os.path.join(module_output_dir, norm_sig_filename)
                                with open(norm_sig_path, 'w', encoding='utf-8') as f_norm_sig:
                                    json.dump(normalized_sigs_list, f_norm_sig, indent=2)
                                current_decomp_output["normalized_signatures"] = norm_sig_path
                            except Exception as e_norm:
                                print(f"  Error normalizing signatures for {decomp_name}: {e_norm}")
                                current_decomp_output["normalized_signatures"] = None
                        else:
                            current_decomp_output["normalized_signatures"] = None
                        normalized_decompiler_outputs[decomp_name] = current_decomp_output

                    module_result_data = {
                        "status": "completed" if successful_c_outputs_count > 0 else "error",
                        "decompiler_outputs": normalized_decompiler_outputs,
                        "consensus_c_code": consensus_c_path,
                        "refined_cfg_path": refined_cfg_path
                    }
                    self.results_processor.store_file_result(file_name, module_name, module_result_data)

                    # --- Context Update for TypePropagator ---
                    chosen_c_file_for_typeprop = None
                    chosen_sig_file_for_typeprop = None # This should be the *normalized* signature file

                    if consensus_c_path and os.path.exists(consensus_c_path):
                        chosen_c_file_for_typeprop = consensus_c_path
                        for pref_decomp in self.decompiler_list_pref:
                            outputs = normalized_decompiler_outputs.get(pref_decomp)
                            if outputs and outputs.get("normalized_signatures") and os.path.exists(outputs["normalized_signatures"]):
                                chosen_sig_file_for_typeprop = outputs["normalized_signatures"]
                                print(f"  TypePropagator using consensus C and normalized signatures from {pref_decomp}.")
                                break
                        if not chosen_sig_file_for_typeprop:
                             print(f"  TypePropagator using consensus C, but no suitable normalized signature file found.")
                    else:
                        for pref_decomp in self.decompiler_list_pref:
                            outputs = normalized_decompiler_outputs.get(pref_decomp)
                            if outputs and outputs.get("c_code") and os.path.exists(outputs["c_code"]):
                                chosen_c_file_for_typeprop = outputs["c_code"]
                                chosen_sig_file_for_typeprop = outputs.get("normalized_signatures")
                                if chosen_sig_file_for_typeprop and not os.path.exists(chosen_sig_file_for_typeprop):
                                    chosen_sig_file_for_typeprop = None 
                                print(f"  TypePropagator using C code and normalized signatures from {pref_decomp}.")
                                break
                    
                    context_updates_for_file = {
                        "primary_c_file_path": chosen_c_file_for_typeprop,
                        "primary_signatures_path": chosen_sig_file_for_typeprop, 
                        "all_decompiler_outputs": normalized_decompiler_outputs 
                    }
                    self.results_processor.update_analysis_context(context_updates_for_file, file_specific=True, file_name_filter=file_name)
                    # --- End Context Update ---
                    self.execution_stats["completed_modules"] += 1

                elif module_name == "TypePropagator":
                    file_specific_context = self.results_processor.get_analysis_context(file_specific=True, file_name_filter=file_name)
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    primary_sig_file = file_specific_context.get("primary_signatures_path") 
                    
                    existing_types = file_specific_context.get("existing_types") 

                    if primary_c_file and os.path.exists(primary_c_file):
                        result_types = instance.propagate_types(
                            primary_c_file,
                            signature_data_path=primary_sig_file, 
                            existing_types=existing_types
                        )
                        # Store the dictionary of inferred types
                        self.results_processor.store_file_result(file_name, module_name, {"status": "completed", "inferred_types": result_types})
                        self.execution_stats["completed_modules"] += 1
                    else:
                        error_msg = f"TypePropagator: Missing or inaccessible primary C file path ('{primary_c_file}') for {file_name}. Skipping."
                        print(f"  Error: {error_msg}")
                        self.results_processor.store_file_result(file_name, module_name, {"status": "error", "message": error_msg})
                        stage_success = False # Mark stage as failed if TypePropagator couldn't run
                
                elif module_name == "VulnerabilityDetector":
                    file_specific_context = self.results_processor.get_analysis_context(file_specific=True, file_name_filter=file_name)
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    pattern_scan_results = {"status": "skipped_no_c_file", "vulnerabilities_found": []}
                    ml_scan_results = {"status": "skipped_no_c_file", "ml_findings": []}

                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8') as f_c:
                                c_code_content = f_c.read()
                            
                            # 1. Pattern-based scan (already part of VulnerabilityDetector)
                            pattern_scan_results = instance.scan_for_vulnerabilities(c_code_content, primary_c_file)

                            # 2. Conditional Training (Placeholder - typically offline)
                            train_vuln_model_data_path = self.cli_args.get("train_vuln_model")
                            if train_vuln_model_data_path:
                                print(f"  Attempting (dummy) training for VulnerabilityDetector ML model using data from: {train_vuln_model_data_path}")
                                # In a real scenario, output names might be configurable or derived
                                training_outcome = instance.train_vulnerability_model(
                                    training_data_path=train_vuln_model_data_path,
                                    output_model_name=f"{file_name}_trained_vuln_model.dummy.joblib",
                                    output_vectorizer_name=f"{file_name}_vuln_vectorizer.dummy.pkl"
                                )
                                print(f"  VulnerabilityDetector ML training simulation outcome: {training_outcome['status']}")
                                if training_outcome.get("model_path"):
                                    print(f"    Dummy model saved to: {training_outcome['model_path']}")
                                # Re-load components if training happened and paths were updated internally
                                if training_outcome['status'] == 'simulated_vuln_training_complete' and \
                                   instance.ml_model_path and instance.ml_vectorizer_path:
                                   print(f"  Reloading VulnerabilityDetector ML components after training...")
                                   instance.load_trained_ml_components(instance.ml_model_path, instance.ml_vectorizer_path)


                            # 3. ML-based prediction
                            ml_scan_results = instance.predict_vulnerabilities_ml(c_code_content, primary_c_file)

                        except Exception as e_vuln:
                            error_msg = f"VulnerabilityDetector: Error processing C code from {primary_c_file} for {file_name}: {e_vuln}"
                            print(f"  Error: {error_msg}\n{traceback.format_exc()}")
                            pattern_scan_results = {"status": "error", "message": error_msg, "vulnerabilities_found": []}
                            ml_scan_results = {"status": "error", "message": error_msg, "ml_findings": []}
                            stage_success = False
                    else:
                        error_msg = f"VulnerabilityDetector: Missing or inaccessible primary C file path ('{primary_c_file}') for {file_name}. Skipping."
                        print(f"  Error: {error_msg}")
                        pattern_scan_results["message"] = error_msg
                        ml_scan_results["message"] = error_msg
                        stage_success = False

                    combined_results = {
                        "status": "completed" if stage_success else "error",
                        "pattern_scan": pattern_scan_results,
                        "ml_scan": ml_scan_results
                    }
                    self.results_processor.store_file_result(file_name, module_name, combined_results)
                    self.execution_stats["completed_modules"] += 1

                elif module_name == "CodeIntentClassifier":
                    file_specific_context = self.results_processor.get_analysis_context(file_specific=True, file_name_filter=file_name)
                    primary_c_file = file_specific_context.get("primary_c_file_path")

                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8') as f_c:
                                c_code_content = f_c.read()
                            
                            classification_result = instance.classify_code_block(c_code_content)
                            # The result from classify_code_block is already a dictionary
                            self.results_processor.store_file_result(file_name, module_name, classification_result)
                            self.execution_stats["completed_modules"] += 1
                        except Exception as e_intent:
                            error_msg = f"CodeIntentClassifier: Error processing file {primary_c_file} for {file_name}: {e_intent}"
                            print(f"  Error: {error_msg}")
                            traceback.print_exc()
                            self.results_processor.store_file_result(file_name, module_name, {"status": "error", "message": error_msg, "traceback": traceback.format_exc()})
                            stage_success = False
                    else:
                        error_msg = f"CodeIntentClassifier: Missing or inaccessible primary C file path ('{primary_c_file}') for {file_name}. Skipping."
                        print(f"  Error: {error_msg}")
                        self.results_processor.store_file_result(file_name, module_name, {"status": "error", "message": error_msg})
                        stage_success = False
                
                elif module_name == "ProgramSynthesisEngine":
                    file_specific_context = self.results_processor.get_analysis_context(file_specific=True, file_name_filter=file_name)
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    behavior_dict = {
                        "description": f"Synthesize based on decompiled output of {file_name}",
                        "source_file_path_for_analysis": primary_c_file if primary_c_file else "N/A"
                    }
                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8') as f_c:
                                behavior_dict["pseudo_code"] = f_c.read(1024) # First 1KB as pseudo-code example
                        except Exception as e_read:
                            behavior_dict["pseudo_code_error"] = str(e_read)
                    
                    result_code = instance.synthesize_code(observed_behavior=behavior_dict, target_language="c")
                    self.results_processor.store_file_result(file_name, module_name, {"status": "placeholder_executed", "synthesized_code_placeholder": result_code})
                    self.execution_stats["completed_modules"] += 1

                elif module_name == "CompilerSpecificRecovery":
                    file_specific_context = self.results_processor.get_analysis_context(file_specific=True, file_name_filter=file_name)
                    primary_c_file = file_specific_context.get("primary_c_file_path")
                    code_snippets_for_compiler_id = ["push ebp", "mov ebp, esp"] # Dummy snippet
                    if primary_c_file and os.path.exists(primary_c_file):
                        try:
                            with open(primary_c_file, 'r', encoding='utf-8') as f_c:
                                # Using first few lines as representative snippets for placeholder
                                code_snippets_for_compiler_id = [f_c.readline().strip() for _ in range(5) if f_c.readable()]
                                code_snippets_for_compiler_id = [s for s in code_snippets_for_compiler_id if s] # Filter empty lines
                                if not code_snippets_for_compiler_id : code_snippets_for_compiler_id = ["dummy_line_1;", "dummy_line_2;"]
                        except Exception as e_read:
                            print(f"  Could not read C file for CompilerSpecificRecovery snippets: {e_read}")
                    
                    identified_compiler = instance.identify_compiler_from_idioms(code_snippets=code_snippets_for_compiler_id)
                    self.results_processor.store_file_result(file_name, module_name, {"status": "placeholder_executed", "identified_compiler": identified_compiler})
                    self.execution_stats["completed_modules"] += 1

                elif module_name == "IntelPTAnalyzer":
                    dummy_pt_path = f"{file_path}.pt_trace" # Non-existent, placeholder will handle
                    # Simulate creating an empty dummy file for the placeholder to "find"
                    # open(dummy_pt_path, 'w').close() 
                    # ^ Decided against creating file, placeholder handles non-existence.
                    pt_result = instance.process_pt_trace(trace_file_path=dummy_pt_path)
                    self.results_processor.store_file_result(file_name, module_name, pt_result)
                    self.execution_stats["completed_modules"] += 1
                    # if os.path.exists(dummy_pt_path): os.remove(dummy_pt_path) # Clean up if created

                elif module_name == "IntelPinToolRunner":
                    pin_result = instance.run_pin_tool(binary_path=file_path, pintool_name="keyplug_pintracer.so", pintool_options={"-o": f"{file_name}.pin_trace.txt"})
                    self.results_processor.store_file_result(file_name, module_name, pin_result)
                    self.execution_stats["completed_modules"] += 1

                elif hasattr(instance, 'analyze'): # Standard module execution for other modules
                    result = instance.analyze(file_path, context=context) 
                    self.results_processor.store_file_result(file_name, module_name, result)
                    self.execution_stats["completed_modules"] += 1
                else:
                    error_msg = f"Module {module_name} does not have a recognized analysis method (analyze, decompile, propagate_types)."
                    print(f"  Warning: {error_msg}")
                    self.results_processor.store_file_result(file_name, module_name, {"status": "skipped", "message": error_msg})
                    # Not necessarily a stage failure, but a skip.
                
                # Save individual component result to its dedicated file if not already handled by module logic
                # For DecompilerIntegration, the main result dict is stored. Individual files are in module_output_dir.
                # For TypePropagator, its dict of types is stored.
                if module_name not in ["DecompilerIntegration"]: # TypePropagator result is a dict, can be saved.
                    try:
                        output_filepath = self.results_processor.save_component_result_to_file(file_name, module_name, module_specific_output_dir=module_output_dir)
                        if output_filepath: print(f"  Results for {module_name} also saved to: {output_filepath}")
                    except Exception as e:
                        print(f"  Warning: Could not save results to dedicated file for {module_name}: {e}")
                    try:
                        # Pass module_output_dir for modules that might want to save additional artifacts there
                        output_filepath = self.results_processor.save_component_result_to_file(file_name, module_name, module_specific_output_dir=module_output_dir)
                        if output_filepath: print(f"  Results for {module_name} also saved to: {output_filepath}")
                    except Exception as e:
                        print(f"  Warning: Could not save results to dedicated file for {module_name}: {e}")
            
            except Exception as e:
                print(f"Error running {module_name} on {file_name}: {e}")
                print(traceback.format_exc())
                
                # Store error result
                error_result = {
                    "status": "error",
                    "message": str(e),
                    "traceback": traceback.format_exc()
                }
                self.results_processor.store_file_result(file_name, module_name, error_result)
                stage_success = False
            
            # Record execution time
            exec_time = time.time() - start_time
            print(f"  Completed in {exec_time:.2f} seconds")
        
        return stage_success
    
    def analyze_memory_dump(self, dump_path, profile=None):
        """
        Analyze a memory dump using the memory forensics modules.
        
        Args:
            dump_path: Path to the memory dump
            profile: Optional Volatility profile for the memory dump
            
        Returns:
            Dictionary of memory analysis results
        """
        dump_name = os.path.basename(dump_path)
        print(f"\n[+] Analyzing Memory Dump: {dump_name}")
        
        # Register memory dump with results processor
        self.results_processor.register_memory_dump(dump_path)
        
        # Check if memory analysis stage is enabled
        if self.cli_args.get("disable_memory", False):
            print("Memory analysis is disabled by command-line flag")
            return self.results_processor.get_memory_results()
        
        # Get the memory analyzer instance
        memory_analyzer = None
        for module_name, instance in self.module_instances.items():
            if module_name == "KeyplugMemoryAnalyzer":
                memory_analyzer = instance
                break
        
        if not memory_analyzer:
            print("Memory analyzer not found or not initialized")
            return self.results_processor.get_memory_results()
        
        # Run the memory analyzer
        print(f"Running Memory Analysis on {dump_name}")
        start_time = time.time()
        
        try:
            # Get the current analysis context
            context = self.results_processor.get_analysis_context()
            
            # Check if the module has the analyze_dump method
            if hasattr(memory_analyzer, 'analyze_dump'):
                result = memory_analyzer.analyze_dump(dump_path, profile=profile, context=context)
                
                # Store the result
                self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", result)
                
                # Update module execution count
                self.execution_stats["completed_modules"] += 1
            else:
                print(f"Warning: Memory analyzer does not have an 'analyze_dump' method")
                result = {
                    "status": "error",
                    "message": "Memory analyzer does not have an 'analyze_dump' method"
                }
                self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", result)
        
        except Exception as e:
            print(f"Error running memory analysis on {dump_name}: {e}")
            print(traceback.format_exc())
            
            # Store error result
            error_result = {
                "status": "error",
                "message": str(e),
                "traceback": traceback.format_exc()
            }
            self.results_processor.store_memory_result("KeyplugMemoryAnalyzer", error_result)
        
        # Record execution time
        exec_time = time.time() - start_time
        print(f"Memory Analysis completed in {exec_time:.2f} seconds")
        
        return self.results_processor.get_memory_results()
    
    def analyze_files(self, file_paths):
        """
        Analyze multiple files, optionally in parallel.
        
        Args:
            file_paths: List of paths to files to analyze
            
        Returns:
            Dictionary of analysis results for all files
        """
        if not file_paths:
            print("No files to analyze")
            return {}
        
        total_files = len(file_paths)
        print(f"\n[+] Starting batch analysis of {total_files} files")
        
        # Check if parallel execution is enabled
        use_parallel = self.cli_args.get("parallel", False)
        
        if use_parallel:
            # Determine the number of workers
            max_workers = min(os.cpu_count() or 4, len(file_paths), 8)  # Limit to 8 workers
            print(f"Using parallel execution with {max_workers} workers")
            
            # Create a separate results processor for each worker to avoid conflicts
            # This is a simplified approach - in practice, you might need a more
            # sophisticated synchronization mechanism
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Submit all files for analysis
                future_to_file = {
                    executor.submit(self._analyze_file_wrapper, file_path): file_path
                    for file_path in file_paths
                }
                
                # Process results as they complete
                for i, future in enumerate(concurrent.futures.as_completed(future_to_file)):
                    file_path = future_to_file[future]
                    file_name = os.path.basename(file_path)
                    
                    try:
                        # Get result from future
                        _ = future.result()
                        print(f"[{i+1}/{total_files}] Completed analysis of {file_name}")
                    except Exception as e:
                        print(f"[{i+1}/{total_files}] Error analyzing {file_name}: {e}")
                        self.execution_stats["failed_files"] += 1
        else:
            # Sequential execution
            for i, file_path in enumerate(file_paths):
                file_name = os.path.basename(file_path)
                print(f"\n[{i+1}/{total_files}] Analyzing file: {file_name}")
                
                try:
                    self.analyze_file(file_path)
                except Exception as e:
                    print(f"Error analyzing {file_name}: {e}")
                    print(traceback.format_exc())
                    self.execution_stats["failed_files"] += 1
        
        print(f"\n[+] Completed analysis of {total_files} files")
        return self.results_processor.file_results
    
    def _analyze_file_wrapper(self, file_path):
        """
        Wrapper for analyze_file to be used with ProcessPoolExecutor.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of analysis results
        """
        # Create a new orchestrator instance for this process
        orchestrator = UnifiedOrchestrator(self.base_output_dir, self.cli_args)
        return orchestrator.analyze_file(file_path)
    
    def run_global_analysis(self):
        """
        Run global analysis modules that operate on all results.
        
        Returns:
            Dictionary of global analysis results
        """
        print("\n[+] Running Global Analysis")
        
        # Check if global analysis is disabled
        if self.cli_args.get("disable_global", False):
            print("Global analysis is disabled by command-line flag")
            return self.results_processor.global_results
        
        # Get global analysis modules
        global_modules = []
        for module_name, instance in self.module_instances.items():
            for stage_name, stage_modules, _ in self.pipeline_config["pipeline_stages"]:
                if stage_name == "global" and module_name in stage_modules:
                    global_modules.append((module_name, instance))
        
        # Run each global module
        for module_name, instance in global_modules:
            print(f"Running Global Analysis: {module_name}")
            start_time = time.time()
            
            try:
                # Get all file results and memory results
                all_file_results = self.results_processor.file_results
                memory_results = self.results_processor.get_memory_results()
                
                # Prepare global context
                global_context = {
                    "file_results": all_file_results,
                    "memory_results": memory_results,
                    **self.results_processor.get_analysis_context()
                }
                
                # Check the module interface
                # Different global modules might have different methods
                elif hasattr(instance, 'analyze_all'): # Generic global analyzer
                    result = instance.analyze_all(context=global_context)
                elif hasattr(instance, 'correlate'): # For correlators
                    result = instance.correlate(
                        all_file_results=all_file_results,
                        all_global_results=self.results_processor.global_results, # Pass previous global results
                        context=global_context
                    )
                elif hasattr(instance, 'update_database'): # For DB updaters (like old pattern_db)
                    result = instance.update_database(context=global_context)
                
                elif module_name == "MalwarePatternLearner" and hasattr(instance, 'learn_from_analysis'):
                    print(f"  MalwarePatternLearner processing {len(all_file_results)} file results.")
                    patterns_before = len(instance.patterns_db.get("patterns", []))
                    for f_name, file_result_dict in all_file_results.items():
                        # We need to pass the full result dict for that file, which includes 'file_name' and 'components'
                        # The learn_from_analysis method expects a dict similar to what one file analysis produces
                        # So, we pass the value part of the all_file_results dict
                        instance.learn_from_analysis(file_result_dict) 
                    
                    patterns_after = len(instance.patterns_db.get("patterns", []))
                    result = {
                        "status": "learning_complete_placeholder",
                        "patterns_in_db_start": patterns_before,
                        "patterns_in_db_end": patterns_after,
                        "new_patterns_attempted_this_run": patterns_after - patterns_before, # More accurate count
                        "files_processed_for_learning": len(all_file_results)
                    }
                    print(f"  MalwarePatternLearner finished. DB now has {patterns_after} patterns.")

                else:
                    print(f"Warning: Module {module_name} does not have a recognized global analysis method (analyze_all, correlate, update_database, or specific MalwarePatternLearner logic).")
                    result = {
                        "status": "error",
                        "message": f"Module {module_name} does not have a recognized global analysis method"
                    }
                
                # Store the result
                self.results_processor.store_global_result(module_name, result)
                
                # Update module execution count
                self.execution_stats["completed_modules"] += 1
            
            except Exception as e:
                print(f"Error running global analysis {module_name}: {e}")
                print(traceback.format_exc())
                
                # Store error result
                error_result = {
                    "status": "error",
                    "message": str(e),
                    "traceback": traceback.format_exc()
                }
                self.results_processor.store_global_result(module_name, error_result)
            
            # Record execution time
            exec_time = time.time() - start_time
            print(f"Global Analysis {module_name} completed in {exec_time:.2f} seconds")
        
        return self.results_processor.global_results
    
    def generate_reports(self):
        """
        Generate consolidated reports for all analysis results.
        
        Returns:
            Dictionary with paths to the generated reports
        """
        print("\n[+] Generating Consolidated Reports")
        
        # Update execution stats
        self.execution_stats["end_time"] = datetime.now().isoformat()
        
        # Update analysis context with execution stats
        self.results_processor.update_analysis_context({
            "execution_stats": self.execution_stats,
            "total_execution_time": self._calculate_total_execution_time()
        })
        
        # Generate reports
        report_paths = self.results_processor.generate_consolidated_report()
        
        print("Reports generated:")
        for fmt, path in report_paths.items():
            print(f"  {fmt.upper()}: {path}")
        
        return report_paths
    
    def _calculate_total_execution_time(self):
        """
        Calculate the total execution time.
        
        Returns:
            Total execution time in seconds
        """
        start_time = datetime.fromisoformat(self.execution_stats["start_time"])
        end_time = datetime.fromisoformat(self.execution_stats["end_time"])
        return (end_time - start_time).total_seconds()


def main():
    """Main entry point for the unified orchestrator."""
    parser = argparse.ArgumentParser(
        description='KEYPLUG Unified Analysis Orchestrator (Modular Architecture)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input sources
    input_group = parser.add_argument_group('Input Sources')
    input_group.add_argument('-f', '--file', help='Analyze a single file')
    input_group.add_argument('-d', '--dir', help='Directory containing files to analyze')
    input_group.add_argument('-p', '--pattern', default='*', help='File pattern to match in directory')
    input_group.add_argument('--memory-dump', help='Path to memory dump file for analysis')
    input_group.add_argument('--memory-profile', help='Memory dump profile (for Volatility)')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default='keyplug_unified_analysis', help='Base output directory')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    perf_group.add_argument('--parallel', action='store_true', help='Enable parallel file analysis')
    perf_group.add_argument('--force-modules', action='store_true', help='Force loading modules even if requirements not met')
    
    # Pipeline control
    pipeline_group = parser.add_argument_group('Pipeline Control')
    
    # Add enable/disable flags for all stages
    pipeline_config = get_pipeline_config()
    for stage_name, _, _ in pipeline_config["pipeline_stages"]:
        pipeline_group.add_argument(
            f'--disable-{stage_name}', 
            action='store_true',
            help=f'Disable the entire {stage_name} stage'
        )
    
    # Add enable/disable flags for specific modules
    for module_name, details in pipeline_config["module_details"].items():
        cli_flag = details.get("cli_flag", "")
        if not cli_flag:
            continue
        
        default_enabled = details.get("default_enabled", True)
        if default_enabled:
            pipeline_group.add_argument(
                f'--disable-{cli_flag}',
                action='store_true',
                help=f'Disable {module_name} module'
            )
        else:
            pipeline_group.add_argument(
                f'--enable-{cli_flag}',
                action='store_true',
                help=f'Enable {module_name} module (disabled by default)'
            )

    # Decompiler specific arguments
    decompiler_group = parser.add_argument_group('Decompiler Options')
    decompiler_group.add_argument('--decompiler-list', 
                                  nargs='+', 
                                  default=['ghidra', 'retdec', 'ida'], 
                                  choices=['ghidra', 'retdec', 'ida', 'all'], 
                                  help='List of decompilers to try (e.g., ghidra retdec ida). Order can imply preference. "all" attempts all available.')

    # Module-specific configurations
    module_config_group = parser.add_argument_group('Module Configurations')
    module_config_group.add_argument(
        '--intent-model-path',
        default=None, # Let the module define its default or handle None
        help="Path to the trained Code Intent Classifier model file (e.g., .joblib)."
    )
    module_config_group.add_argument(
        '--intent-vectorizer-path',
        default=None, # Let the module define its default or handle None
        help="Path to the trained Code Intent Classifier TF-IDF vectorizer file (e.g., .pkl)."
    )
    module_config_group.add_argument(
        '--train-vuln-model',
        metavar='TRAINING_DATA_PATH', # For help text clarity
        default=None,
        help="Path to training data to trigger (dummy) training for VulnerabilityDetector's ML model."
    )
    module_config_group.add_argument(
        '--vuln-model-path',
        default=None,
        help="Path to a pre-trained VulnerabilityDetector ML model file."
    )
    module_config_group.add_argument(
        '--vuln-vectorizer-path',
        default=None,
        help="Path to a pre-trained VulnerabilityDetector ML vectorizer file."
    )
    module_config_group.add_argument(
        '--pattern-db-path',
        default=None, # MalwarePatternLearner will use its default if None
        help="Path to the malware pattern database JSON file for MalwarePatternLearner."
    )
    
    args = parser.parse_args()
    
    # Convert args to dictionary
    cli_args = vars(args)
    
    # Create output directory
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Initialize orchestrator
    orchestrator = UnifiedOrchestrator(args.output, cli_args)
    
    start_time = time.time()
    
    # Collect file paths to analyze
    files_to_analyze = []
    
    if args.file:
        if os.path.exists(args.file):
            files_to_analyze.append(args.file)
        else:
            print(f"Error: File {args.file} not found")
            return 1
    
    elif args.dir:
        if os.path.exists(args.dir):
            pattern = os.path.join(args.dir, args.pattern)
            matching_files = glob.glob(pattern)
            files_to_analyze.extend([f for f in matching_files if os.path.isfile(f)])
            
            if not files_to_analyze:
                print(f"No files matching pattern '{args.pattern}' found in directory '{args.dir}'")
        else:
            print(f"Error: Directory {args.dir} not found")
            return 1
    
    # Analyze files if any
    if files_to_analyze:
        orchestrator.analyze_files(files_to_analyze)
    
    # Analyze memory dump if specified
    if args.memory_dump:
        if os.path.exists(args.memory_dump):
            orchestrator.analyze_memory_dump(args.memory_dump, profile=args.memory_profile)
        else:
            print(f"Error: Memory dump file {args.memory_dump} not found")
            return 1
    
    # Run global analysis if any files or memory dumps were analyzed
    if files_to_analyze or args.memory_dump:
        orchestrator.run_global_analysis()
    
    # Generate reports
    orchestrator.generate_reports()
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n[+] Analysis Complete")
    print(f"Total execution time: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
