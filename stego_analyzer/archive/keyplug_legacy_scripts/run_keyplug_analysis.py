#!/usr/bin/env python3
"""
KEYPLUG Comprehensive Analysis Suite
-----------------------------------
Unified analysis pipeline for KEYPLUG malware with source code extraction,
multi-layer decryption, and behavioral analysis using OpenVINO acceleration.

This script combines all KEYPLUG analysis components into a single pipeline
for maximum performance and comprehensive analysis.
"""

import os
import sys
import glob
import json
import shutil
import argparse
import subprocess
import time
import concurrent.futures
from datetime import datetime

# Import KEYPLUG components
from keyplug_source_extractor import SourceCodeExtractor
from keyplug_multilayer_extractor import MultiLayerExtractor
from keyplug_pattern_database import PatternDatabase
from keyplug_api_sequence_detector import APISequenceDetector
from keyplug_behavioral_analyzer import BehavioralAnalyzer
from keyplug_cross_sample_correlator import CrossSampleCorrelator
from keyplug_openvino_accelerator import OpenVINOAccelerator
from keyplug_memory_forensics import KeyplugMemoryAnalyzer # Added for memory forensics

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration")
    
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

# Constants
EXTRACTED_PE_DIR = "extracted_pe"
OUTPUT_BASE_DIR = "keyplug_analysis_results"
MAX_WORKERS = os.cpu_count()
MAX_DEPTH = 5  # Maximum decryption depth
print(f"Using maximum CPU cores: {MAX_WORKERS}")

class KEYPLUGAnalyzer:
    """
    Unified KEYPLUG analysis pipeline with OpenVINO acceleration
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the KEYPLUG analyzer
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.max_workers = MAX_WORKERS
        
        # Initialize accelerator
        self.accelerator = OpenVINOAccelerator(use_openvino=self.use_openvino)
        
        # Initialize components
        self.multilayer_extractor = MultiLayerExtractor(use_openvino=self.use_openvino)
        self.pattern_db = PatternDatabase(use_openvino=self.use_openvino)
        self.api_detector = APISequenceDetector(use_openvino=self.use_openvino)
        self.behavioral_analyzer = BehavioralAnalyzer(use_openvino=self.use_openvino)
        self.cross_correlator = CrossSampleCorrelator(use_openvino=self.use_openvino)
        self.source_extractor = SourceCodeExtractor(use_openvino=self.use_openvino)
        
        # Initialize Memory Analyzer
        if OPENVINO_AVAILABLE:
            self.memory_analyzer = KeyplugMemoryAnalyzer(ov_core=core, device_name=PREFERRED_DEVICE)
            print("Memory Forensics Analyzer initialized with OpenVINO.")
        else:
            # Assuming KeyplugMemoryAnalyzer can handle ov_core=None
            self.memory_analyzer = KeyplugMemoryAnalyzer(ov_core=None, device_name="CPU")
            print("Memory Forensics Analyzer initialized without OpenVINO.")

    def analyze_sample(self, sample_path, output_dir, 
                      extract_layers=True, 
                      analyze_behavior=True, 
                      extract_source=True,
                      decompiler="ghidra",
                      max_depth=MAX_DEPTH,
                      memory_dump_path=None): # New parameter for memory dump
        """
        Analyze a single malware sample
        
        Args:
            sample_path: Path to the malware sample
            output_dir: Directory to save analysis results
            extract_layers: Whether to extract and analyze layers
            analyze_behavior: Whether to analyze behavior
            extract_source: Whether to extract source code
            decompiler: Decompiler to use for source extraction
            max_depth: Maximum recursion depth for layer extraction
            
        Returns:
            Dictionary with analysis results
        """
        if not os.path.exists(sample_path):
            print(f"Error: Sample {sample_path} not found")
            return None
        
        sample_name = os.path.basename(sample_path)
        sample_output_dir = os.path.join(output_dir, sample_name + "_analysis")
        
        if not os.path.exists(sample_output_dir):
            os.makedirs(sample_output_dir)
        
        print(f"Starting comprehensive analysis of {sample_name}...")
        start_time = time.time()
        
        results = {
            "sample": sample_name,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "openvino_acceleration": self.use_openvino,
            "preferred_device": PREFERRED_DEVICE if self.use_openvino else "None",
            "layers": [],
            "behavior": {},
            "source_code": {},
            "cross_correlations": [],
            "memory_forensics": {"info": "Memory analysis not performed."} # Initialize memory_forensics
        }
        
        try:
            # Step 0: Optional Memory Forensics (if dump provided)
            # This is placed early as it might provide context, though it's independent of sample file layers
            if memory_dump_path and hasattr(self, 'memory_analyzer') and self.memory_analyzer:
                if os.path.exists(memory_dump_path):
                    print(f"[*] Starting memory forensics for {memory_dump_path} related to sample {sample_name}...")
                    try:
                        mem_results = self.memory_analyzer.analyze_dump(memory_dump_path)
                        results["memory_forensics"] = mem_results
                        print(f"[*] Memory forensics complete for {memory_dump_path}.")
                    except Exception as e:
                        print(f"Error during memory analysis of {memory_dump_path}: {e}")
                        results["memory_forensics"] = {"info": f"Error during memory analysis: {e}", "error": True}
                else:
                    print(f"Warning: Memory dump file {memory_dump_path} not found. Skipping memory analysis.")
                    results["memory_forensics"] = {"info": f"Memory dump file {memory_dump_path} not found.", "skipped": True}
            elif memory_dump_path:
                 results["memory_forensics"] = {"info": "Memory analyzer not available.", "skipped": True}


            # Step 1: Extract layers
            layers = []
            if extract_layers:
                print(f"[1/5] Extracting layers from {sample_name}...") # Updated step numbering
                layers_dir = os.path.join(sample_output_dir, "layers")
                
                if not os.path.exists(layers_dir):
                    os.makedirs(layers_dir)
                
                layers = self.multilayer_extractor.extract_layers(
                    sample_path, 
                    layers_dir, 
                    max_depth=max_depth
                )
                
                print(f"Extracted {len(layers)} layers from {sample_name}")
                
                # Add layers to results
                results["layers"] = [
                    {
                        "path": layer,
                        "name": os.path.basename(layer)
                    } for layer in layers
                ]
            else:
                # Use the original sample as the only layer
                layers = [sample_path]
                results["layers"] = [
                    {
                        "path": sample_path,
                        "name": sample_name
                    }
                ]
            
            # Step 2: Analyze behavior
            if analyze_behavior:
                print(f"[2/5] Analyzing behavior of {sample_name}...") # Updated step numbering
                behavior_dir = os.path.join(sample_output_dir, "behavior")
                
                if not os.path.exists(behavior_dir):
                    os.makedirs(behavior_dir)
                
                # Analyze each layer in parallel
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_layer = {
                        executor.submit(
                            self.behavioral_analyzer.analyze_binary,
                            layer
                        ): layer for layer in layers
                    }
                    
                    layer_behaviors = {}
                    for future in concurrent.futures.as_completed(future_to_layer):
                        layer = future_to_layer[future]
                        layer_name = os.path.basename(layer)
                        try:
                            behavior = future.result()
                            if behavior:
                                layer_behaviors[layer_name] = behavior
                                print(f"Successfully analyzed behavior of {layer_name}")
                            else:
                                print(f"No significant behavior found in {layer_name}")
                        except Exception as e:
                            print(f"Error analyzing behavior of {layer_name}: {e}")
                
                # Save behavior analysis results
                behavior_path = os.path.join(behavior_dir, "behavior_analysis.json")
                with open(behavior_path, 'w') as f:
                    json.dump(layer_behaviors, f, indent=2)
                
                # Add behavior to results
                results["behavior"] = layer_behaviors
                
                print(f"Behavior analysis complete. Results saved to {behavior_dir}")
            
            # Step 3: Extract source code
            if extract_source:
                print(f"[3/5] Extracting source code from {sample_name}...") # Updated step numbering
                source_dir = os.path.join(sample_output_dir, "source_code")
                
                if not os.path.exists(source_dir):
                    os.makedirs(source_dir)
                
                # Extract source code from each layer in parallel
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_layer = {
                        executor.submit(
                            self.source_extractor.extract_source_code,
                            layer,
                            source_dir,
                            decompiler_type=decompiler,
                            detect_boundaries=True,
                            infer_types=True,
                            recover_control_flow=True,
                            detect_idioms=True
                        ): layer for layer in layers
                    }
                    
                    layer_sources = {}
                    for future in concurrent.futures.as_completed(future_to_layer):
                        layer = future_to_layer[future]
                        layer_name = os.path.basename(layer)
                        try:
                            source_output_dir = future.result()
                            if source_output_dir:
                                # Count source files
                                source_files = []
                                for root, _, files in os.walk(source_output_dir):
                                    for file in files:
                                        if file.endswith(".c") or file.endswith(".h"):
                                            source_files.append(os.path.join(root, file))
                                
                                layer_sources[layer_name] = {
                                    "output_dir": source_output_dir,
                                    "file_count": len(source_files),
                                    "files": [os.path.basename(f) for f in source_files]
                                }
                                print(f"Successfully extracted source code from {layer_name}")
                            else:
                                print(f"Failed to extract source code from {layer_name}")
                        except Exception as e:
                            print(f"Error extracting source code from {layer_name}: {e}")
                
                # Add source code to results
                results["source_code"] = layer_sources
                
                print(f"Source code extraction complete. Results saved to {source_dir}")
            
            # Step 4: Perform cross-sample correlation
            print(f"[4/5] Performing cross-sample correlation...") # Updated step numbering
            
            # Get all previously analyzed samples
            analyzed_samples = []
            for root, dirs, _ in os.walk(output_dir):
                for dir_name in dirs:
                    if dir_name.endswith("_analysis") and dir_name != sample_name + "_analysis":
                        sample_dir = os.path.join(root, dir_name)
                        sample_json = os.path.join(sample_dir, "analysis_results.json")
                        if os.path.exists(sample_json):
                            analyzed_samples.append(sample_json)
            
            if analyzed_samples:
                # Convert analyzed_samples from paths to sample data
                sample_paths = [sample_path] + analyzed_samples
                correlation_results = self.cross_correlator.analyze_samples(
                    sample_paths,
                    min_confidence=0.5
                )
                
                # Extract correlations related to the current sample
                correlations = []
                if correlation_results and 'correlations' in correlation_results:
                    sample_name = os.path.basename(sample_path)
                    for corr in correlation_results['correlations']:
                        if corr['sample1'] == sample_name or corr['sample2'] == sample_name:
                            correlations.append(corr)
                
                if correlations:
                    # Save correlations
                    correlations_path = os.path.join(sample_output_dir, "cross_correlations.json")
                    with open(correlations_path, 'w') as f:
                        json.dump(correlations, f, indent=2)
                    
                    # Add correlations to results
                    results["cross_correlations"] = correlations
                    
                    print(f"Found {len(correlations)} cross-sample correlations")
                else:
                    print("No significant cross-sample correlations found")
            else:
                print("No previous samples to correlate with")
            
            # Save final results
            results_path = os.path.join(sample_output_dir, "analysis_results.json")
            with open(results_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Generate human-readable report
            report_path = os.path.join(sample_output_dir, "analysis_report.txt")
            self._generate_report(results, report_path)
            
            end_time = time.time()
            print(f"Analysis of {sample_name} complete in {end_time - start_time:.2f} seconds")
            print(f"Results saved to {sample_output_dir}")
            
            return results
        
        except Exception as e:
            print(f"Error analyzing {sample_name}: {e}")
            return None
    
    def _generate_report(self, results, report_path):
        """
        Generate a human-readable report from analysis results
        
        Args:
            results: Analysis results dictionary
            report_path: Path to save the report
        """
        with open(report_path, 'w') as f:
            f.write("KEYPLUG Comprehensive Analysis Report\n")
            f.write("====================================\n\n")
            
            f.write(f"Sample: {results['sample']}\n")
            f.write(f"Analysis Time: {results['analysis_time']}\n")
            f.write(f"OpenVINO Acceleration: {'Enabled - ' + results['preferred_device'] if results['openvino_acceleration'] else 'Disabled'}\n\n")
            
            # Layer information
            f.write(f"Extracted Layers: {len(results['layers'])}\n")
            for i, layer in enumerate(results['layers']):
                f.write(f"  {i+1}. {layer['name']}\n")
            f.write("\n")

            # Memory Forensics (if performed)
            if "memory_forensics" in results and results["memory_forensics"].get("info") != "Memory analysis not performed.":
                f.write("Memory Forensics Analysis\n")
                f.write("-------------------------\n")
                mem_info = results["memory_forensics"]
                f.write(f"  Status: {mem_info.get('info', 'N/A')}\n")
                if mem_info.get("error"):
                    f.write(f"  Error: {mem_info.get('error_details', 'Unknown error')}\n")
                elif mem_info.get("skipped"):
                     f.write(f"  Skipped: Yes\n")
                else:
                    # Basic summary of memory findings - can be expanded
                    if "processes" in mem_info and isinstance(mem_info["processes"], dict):
                         f.write(f"  Processes Listed: {len(mem_info['processes'].get('processes', []))}\n")
                         suspicious_procs = mem_info['processes'].get('suspicious_processes_identified', [])
                         if suspicious_procs:
                             f.write(f"  Suspicious Processes Identified: {len(suspicious_procs)}\n")
                             for i, p_susp in enumerate(suspicious_procs[:2]): # Show first 2
                                 f.write(f"    - PID: {p_susp.get('pid')}, Name: {p_susp.get('name')}, Reason: {p_susp.get('suspicious_reason')}\n")
                    
                    if "keyplug_artifacts" in mem_info and isinstance(mem_info["keyplug_artifacts"], dict):
                        found_artifacts = mem_info['keyplug_artifacts'].get('found_keyplug_artifacts', [])
                        if found_artifacts:
                            f.write(f"  KEYPLUG Artifacts Found in Memory: {len(found_artifacts)}\n")
                            for i, art in enumerate(found_artifacts[:2]): # Show first 2
                                f.write(f"    - PID: {art.get('pid')}, Process: {art.get('process_name')}, Pattern: {art.get('pattern_name')} at {art.get('absolute_offset')}\n")
                    
                    if "module_analysis" in mem_info and isinstance(mem_info["module_analysis"], dict):
                        suspicious_mods = mem_info['module_analysis'].get('suspicious_modules_summary', [])
                        if suspicious_mods:
                            f.write(f"  Suspicious Modules Identified: {len(suspicious_mods)}\n")
                            for i, m_susp in enumerate(suspicious_mods[:2]): # Show first 2
                                f.write(f"    - PID: {m_susp.get('pid')}, Module: {m_susp.get('module_path', 'N/A')}, Reason: {m_susp.get('reason')}\n")

                    if "network_info" in mem_info and isinstance(mem_info["network_info"], dict):
                        connections = mem_info['network_info'].get('connections_and_listeners', [])
                        if connections:
                             f.write(f"  Network Connections/Listeners Found: {len(connections)}\n")
                    
                    if "api_hooks" in mem_info and isinstance(mem_info["api_hooks"], dict):
                        hooks = mem_info['api_hooks'].get('detected_hooks', [])
                        if hooks:
                            f.write(f"  API Hooks Detected: {len(hooks)}\n")
                            for i, hook in enumerate(hooks[:2]): # Show first 2
                                f.write(f"    - PID: {hook.get('pid')}, Victim: {hook.get('victim_module')}, Func: {hook.get('victim_function')}\n")
                f.write("\n")

            # Behavior analysis
            f.write("Behavior Analysis (Sample File)\n")
            f.write("-----------------\n")
            
            if results['behavior']:
                for layer_name, behavior in results['behavior'].items():
                    f.write(f"\nLayer: {layer_name}\n")
                    
                    if 'api_sequences' in behavior:
                        f.write(f"  API Sequences: {len(behavior['api_sequences'])}\n")
                        for i, seq in enumerate(behavior['api_sequences'][:3]):  # Show top 3
                            f.write(f"    {i+1}. {seq['description']} (Confidence: {seq['confidence']})\n")
                        
                        if len(behavior['api_sequences']) > 3:
                            f.write(f"    ... and {len(behavior['api_sequences']) - 3} more sequences\n")
                    
                    if 'c2_indicators' in behavior:
                        f.write(f"  C2 Indicators: {len(behavior['c2_indicators'])}\n")
                        for i, c2 in enumerate(behavior['c2_indicators'][:3]):  # Show top 3
                            f.write(f"    {i+1}. {c2['address']} (Confidence: {c2['confidence']})\n")
                        
                        if len(behavior['c2_indicators']) > 3:
                            f.write(f"    ... and {len(behavior['c2_indicators']) - 3} more indicators\n")
                    
                    if 'injection_points' in behavior:
                        f.write(f"  Injection Points: {len(behavior['injection_points'])}\n")
                        for i, point in enumerate(behavior['injection_points'][:3]):  # Show top 3
                            f.write(f"    {i+1}. {point['description']} (Confidence: {point['confidence']})\n")
                        
                        if len(behavior['injection_points']) > 3:
                            f.write(f"    ... and {len(behavior['injection_points']) - 3} more points\n")
            else:
                f.write("No significant behavior detected\n")
            
            f.write("\n")
            
            # Source code extraction
            f.write("Source Code Extraction\n")
            f.write("---------------------\n")
            
            if results['source_code']:
                total_files = sum(layer['file_count'] for layer in results['source_code'].values())
                f.write(f"Total Source Files: {total_files}\n\n")
                
                for layer_name, source in results['source_code'].items():
                    f.write(f"Layer: {layer_name}\n")
                    f.write(f"  Files: {source['file_count']}\n")
                    
                    if source['files']:
                        f.write("  Source Files:\n")
                        for i, file in enumerate(source['files'][:5]):  # Show top 5
                            f.write(f"    {i+1}. {file}\n")
                        
                        if len(source['files']) > 5:
                            f.write(f"    ... and {len(source['files']) - 5} more files\n")
            else:
                f.write("No source code extracted\n")
            
            f.write("\n")
            
            # Cross-sample correlations
            f.write("Cross-Sample Correlations\n")
            f.write("------------------------\n")
            
            if results['cross_correlations']:
                for i, corr in enumerate(results['cross_correlations']):
                    f.write(f"{i+1}. Correlation with {corr['sample']}\n")
                    f.write(f"   Similarity: {corr['similarity']:.2f}\n")
                    f.write(f"   Shared Features: {len(corr['shared_features'])}\n")
                    
                    if corr['shared_features']:
                        f.write("   Key Shared Features:\n")
                        for j, feature in enumerate(corr['shared_features'][:3]):  # Show top 3
                            f.write(f"     {j+1}. {feature['description']}\n")
                        
                        if len(corr['shared_features']) > 3:
                            f.write(f"     ... and {len(corr['shared_features']) - 3} more features\n")
            else:
                f.write("No significant cross-sample correlations found\n")
            
            f.write("\n")
            f.write("Analysis complete! Check the analysis directory for detailed results.\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="KEYPLUG Comprehensive Analysis Suite")
    parser.add_argument('-f', '--file', help='Malware sample to analyze')
    parser.add_argument('-d', '--dir', help='Directory containing malware samples to analyze')
    parser.add_argument('-p', '--pattern', help='File pattern to match in directory', default='*.bin')
    parser.add_argument('-o', '--output', help='Output directory', default=OUTPUT_BASE_DIR)
    parser.add_argument('--max-depth', type=int, help='Maximum decryption depth', default=MAX_DEPTH)
    parser.add_argument('--no-layers', action='store_true', help='Disable layer extraction')
    parser.add_argument('--no-behavior', action='store_true', help='Disable behavior analysis')
    parser.add_argument('--no-source', action='store_true', help='Disable source code extraction')
    parser.add_argument('--decompiler', help='Decompiler to use (ghidra, retdec, ida)', default='ghidra')
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    parser.add_argument('--memory-dump', help='Path to a memory dump file for forensics analysis (optional)')
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.dir:
        parser.error("Either --file or --dir must be specified")
    
    # Create output directory
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Initialize analyzer
    analyzer = KEYPLUGAnalyzer(use_openvino=not args.no_openvino)
    
    start_time = time.time()
    
    # Process a single file
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
        
        print(f"[+] Analyzing file: {args.file}")
        results = analyzer.analyze_sample(
            args.file,
            args.output,
            extract_layers=not args.no_layers,
            analyze_behavior=not args.no_behavior,
            extract_source=not args.no_source,
            decompiler=args.decompiler,
            max_depth=args.max_depth,
            memory_dump_path=args.memory_dump # Pass memory dump path
        )
        
        if not results:
            print(f"Error analyzing {args.file}")
            return 1
        
        print(f"[+] Analysis complete for: {args.file}")
    
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
        
        # Use ThreadPoolExecutor instead of ProcessPoolExecutor to avoid OpenVINO Core pickling issues
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(
                    analyzer.analyze_sample,
                    file_path,
                    args.output,
                    not args.no_layers,
                    not args.no_behavior,
                    not args.no_source,
                    args.decompiler,
                    args.max_depth,
                    args.memory_dump # Pass memory dump path to each sample analysis in directory
                ): file_path for file_path in files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    results = future.result()
                    if results:
                        successful += 1
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
            "total_files": len(files),
            "successful": successful,
            "failed": failed,
            "max_depth": args.max_depth,
            "layer_extraction": not args.no_layers,
            "behavior_analysis": not args.no_behavior,
            "source_extraction": not args.no_source,
            "decompiler": args.decompiler,
            "memory_dump_provided": True if args.memory_dump else False
        }
        
        # Save summary
        summary_path = os.path.join(args.output, "analysis_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Successfully analyzed {successful} of {len(files)} files")
        print(f"[+] Summary saved to: {summary_path}")
    
    end_time = time.time()
    print(f"[+] Total execution time: {end_time - start_time:.2f} seconds")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
