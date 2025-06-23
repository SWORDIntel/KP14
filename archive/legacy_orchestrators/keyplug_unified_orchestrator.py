#!/usr/bin/env python3
"""
KEYPLUG Unified Analysis Orchestrator
-----------------------------------
Comprehensive orchestration system for all KEYPLUG analysis components
utilizing OpenVINO acceleration for maximum performance.

This advanced orchestrator integrates all analysis components into a
unified pipeline, optimizing hardware resource allocation and providing
consolidated reporting with cross-component correlation.
"""

import os
import sys
import glob
import json
import time
import shutil
import argparse
import concurrent.futures
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm

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
    elif "VPU" in core.available_devices:
        PREFERRED_DEVICE = "VPU"
        print(f"Using VPU acceleration ({PREFERRED_DEVICE})")
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

class AnalysisComponent:
    """Base class for analysis components"""
    
    def __init__(self, name, script_path, output_dir, priority=5):
        self.name = name
        self.script_path = script_path
        self.output_dir = output_dir
        self.priority = priority  # 1-10, higher is more important
        self.results = {}
        self.execution_time = 0
        
    def run(self, file_path):
        """Run the analysis component on a file"""
        start_time = time.time()
        
        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Run the analysis script
        cmd = f"python {self.script_path} -f \"{file_path}\" -o \"{self.output_dir}\""
        print(f"Executing: {cmd}")
        exit_code = os.system(cmd)
        
        end_time = time.time()
        self.execution_time = end_time - start_time
        
        # Try to load results
        result_file = os.path.join(self.output_dir, f"{os.path.basename(file_path)}_{self.name}_analysis.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    self.results = json.load(f)
                return True
            except Exception as e:
                print(f"Error loading {self.name} analysis results: {e}")
        
        return exit_code == 0

class UnifiedOrchestrator:
    """
    Unified orchestrator for KEYPLUG analysis components
    with OpenVINO acceleration and maximum CPU utilization
    """
    
    def __init__(self, base_output_dir="keyplug_unified_analysis"):
        self.base_output_dir = base_output_dir
        self.components = []
        self.results = {}
        
        # Set up output directories
        self.output_dirs = {
            "peb": os.path.join(base_output_dir, "peb_analysis"),
            "hash": os.path.join(base_output_dir, "hash_analysis"),
            "string": os.path.join(base_output_dir, "string_analysis"),
            "decoder": os.path.join(base_output_dir, "decoder_analysis"),
            "api_flow": os.path.join(base_output_dir, "api_flow_analysis"),
            "pattern_db": os.path.join(base_output_dir, "pattern_database"),
            "consolidated": base_output_dir
        }
        
        # Create output directories
        for dir_path in self.output_dirs.values():
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize analysis components"""
        # PEB Traversal Detector
        if os.path.exists("keyplug_peb_detector.py"):
            self.components.append(AnalysisComponent(
                "peb", 
                "keyplug_peb_detector.py", 
                self.output_dirs["peb"],
                priority=8
            ))
        
        # API Hash Detector
        if os.path.exists("analyze_api_hashing.py"):
            self.components.append(AnalysisComponent(
                "hash", 
                "analyze_api_hashing.py", 
                self.output_dirs["hash"],
                priority=7
            ))
        
        # String Decoder
        if os.path.exists("analyze_encoded_strings.py"):
            self.components.append(AnalysisComponent(
                "string", 
                "analyze_encoded_strings.py --strings-only", 
                self.output_dirs["string"],
                priority=6
            ))
        
        # Decoder Function Identifier
        if os.path.exists("analyze_encoded_strings.py"):
            self.components.append(AnalysisComponent(
                "decoder", 
                "analyze_encoded_strings.py --decoders-only", 
                self.output_dirs["decoder"],
                priority=5
            ))
        
        # API Flow Analyzer (if available)
        if os.path.exists("keyplug_api_flow_analyzer.py"):
            self.components.append(AnalysisComponent(
                "api_flow", 
                "keyplug_api_flow_analyzer.py", 
                self.output_dirs["api_flow"],
                priority=4
            ))
        
        # Sort components by priority (highest first)
        self.components.sort(key=lambda x: x.priority, reverse=True)
    
    def analyze_file(self, file_path):
        """Run all analysis components on a single file"""
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found")
            return None
        
        print(f"\n[+] Starting comprehensive analysis of {os.path.basename(file_path)}")
        
        file_results = {
            "file": os.path.basename(file_path),
            "file_path": file_path,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "components": [],
            "findings": {}
        }
        
        # Run components in order of priority
        for component in self.components:
            print(f"\n[+] Running {component.name.upper()} analysis on {os.path.basename(file_path)}")
            success = component.run(file_path)
            
            component_result = {
                "name": component.name,
                "execution_time": component.execution_time,
                "success": success
            }
            
            # Add component-specific findings
            if success and component.results:
                component_result["findings"] = self._extract_key_findings(component)
                
                # Add to consolidated findings
                for key, value in component_result["findings"].items():
                    file_results["findings"][f"{component.name}_{key}"] = value
            
            file_results["components"].append(component_result)
        
        # Cross-component correlation
        file_results["correlations"] = self._correlate_findings(file_results)
        
        return file_results
    
    def _extract_key_findings(self, component):
        """Extract key findings from component results"""
        findings = {}
        
        if component.name == "peb":
            # Extract PEB traversal findings
            findings["traversal_instances"] = len(component.results.get("function_analysis", []))
            findings["likely_api_resolution"] = component.results.get("summary", {}).get("likely_api_resolution", 0)
        
        elif component.name == "hash":
            # Extract API hash findings
            findings["hash_algorithms"] = len(component.results.get("hash_algorithms", []))
            findings["api_hashes"] = len(component.results.get("api_hashes", []))
            
            # Extract specific API names if available
            api_names = []
            for hash_entry in component.results.get("api_hashes", []):
                if "api_matches" in hash_entry:
                    api_names.extend(hash_entry["api_matches"])
            findings["api_names"] = api_names
        
        elif component.name == "string":
            # Extract string findings
            findings["plain_strings"] = len(component.results.get("plain_strings", []))
            findings["encoded_strings"] = len(component.results.get("encoded_strings", []))
            
            # Extract high-confidence strings
            high_conf_strings = []
            for string in component.results.get("encoded_strings", []):
                if string.get("score", 0) >= 0.8:
                    high_conf_strings.append(string.get("decoded", ""))
            findings["high_confidence_strings"] = high_conf_strings
        
        elif component.name == "decoder":
            # Extract decoder findings
            findings["decoder_functions"] = len(component.results.get("decoders", []))
            findings["high_confidence_decoders"] = component.results.get("summary", {}).get("high_confidence_decoders", 0)
            findings["decoder_types"] = component.results.get("summary", {}).get("decoder_types", {})
        
        elif component.name == "api_flow":
            # Extract API flow findings
            findings["api_sequences"] = len(component.results.get("api_sequences", []))
            findings["potential_c2"] = len(component.results.get("potential_c2", []))
            findings["injection_patterns"] = len(component.results.get("injection_patterns", []))
        
        return findings
    
    def _correlate_findings(self, file_results):
        """Correlate findings across components"""
        correlations = []
        
        # Get component findings
        findings = file_results["findings"]
        
        # Correlation 1: PEB traversal + API hashing
        if findings.get("peb_traversal_instances", 0) > 0 and findings.get("hash_hash_algorithms", 0) > 0:
            correlations.append({
                "type": "api_resolution_mechanism",
                "confidence": "high",
                "description": "PEB traversal combined with API hashing indicates sophisticated API resolution mechanism",
                "components": ["peb", "hash"]
            })
        
        # Correlation 2: Encoded strings + Decoder functions
        if findings.get("string_encoded_strings", 0) > 0 and findings.get("decoder_decoder_functions", 0) > 0:
            correlations.append({
                "type": "string_decoding_capability",
                "confidence": "high",
                "description": "Encoded strings combined with decoder functions indicates runtime string decoding capability",
                "components": ["string", "decoder"]
            })
        
        # Correlation 3: API hashing + API flow
        if findings.get("hash_api_hashes", 0) > 0 and findings.get("api_flow_api_sequences", 0) > 0:
            correlations.append({
                "type": "api_usage_pattern",
                "confidence": "medium",
                "description": "API hashing combined with API sequences indicates sophisticated API usage patterns",
                "components": ["hash", "api_flow"]
            })
        
        # Correlation 4: C2 communication capability
        if "api_flow_potential_c2" in findings and findings["api_flow_potential_c2"] > 0:
            # Check if network-related APIs were found
            network_apis = ["socket", "connect", "send", "recv", "WSAStartup", "InternetOpen"]
            found_network_apis = [api for api in findings.get("hash_api_names", []) if any(net_api in api for net_api in network_apis)]
            
            if found_network_apis:
                correlations.append({
                    "type": "command_and_control",
                    "confidence": "high",
                    "description": f"Network APIs ({', '.join(found_network_apis)}) combined with C2 patterns indicates command & control capability",
                    "components": ["hash", "api_flow"]
                })
        
        # Correlation 5: Process injection capability
        if "api_flow_injection_patterns" in findings and findings["api_flow_injection_patterns"] > 0:
            # Check if injection-related APIs were found
            injection_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection"]
            found_injection_apis = [api for api in findings.get("hash_api_names", []) if any(inj_api in api for inj_api in injection_apis)]
            
            if found_injection_apis:
                correlations.append({
                    "type": "process_injection",
                    "confidence": "high",
                    "description": f"Injection APIs ({', '.join(found_injection_apis)}) combined with injection patterns indicates process injection capability",
                    "components": ["hash", "api_flow"]
                })
        
        return correlations
    
    def analyze_files(self, files):
        """Analyze multiple files"""
        all_results = []
        
        for file_path in tqdm(files, desc="Processing files", unit="file"):
            try:
                result = self.analyze_file(file_path)
                if result:
                    all_results.append(result)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
        
        # Generate consolidated report
        consolidated_results = {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_count": len(files),
            "file_results": all_results,
            "openvino_acceleration": OPENVINO_AVAILABLE,
            "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE else "None",
            "cpu_cores": MAX_WORKERS
        }
        
        self._generate_consolidated_report(consolidated_results)
        
        return consolidated_results
    
    def _generate_consolidated_report(self, results):
        """Generate consolidated reports"""
        # Save JSON report
        json_path = os.path.join(self.output_dirs["consolidated"], "unified_analysis_results.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate human-readable report
        report_path = os.path.join(self.output_dirs["consolidated"], "unified_analysis_report.txt")
        with open(report_path, 'w') as f:
            f.write("KEYPLUG Unified Analysis Report\n")
            f.write("==============================\n\n")
            
            f.write(f"Analysis Time: {results['analysis_time']}\n")
            f.write(f"Files Analyzed: {results['file_count']}\n")
            f.write(f"OpenVINO Acceleration: {'Enabled - ' + results['preferred_device'] if OPENVINO_AVAILABLE else 'Disabled'}\n")
            f.write(f"CPU Cores Utilized: {results['cpu_cores']}\n\n")
            
            # Aggregate findings across all files
            total_findings = defaultdict(int)
            all_correlations = []
            
            for file_result in results['file_results']:
                # Aggregate findings
                for key, value in file_result.get("findings", {}).items():
                    if isinstance(value, (int, float)):
                        total_findings[key] += value
                    elif isinstance(value, list):
                        total_findings[key] += len(value)
                
                # Collect correlations
                all_correlations.extend(file_result.get("correlations", []))
            
            # Write summary
            f.write("Summary of Findings\n")
            f.write("-----------------\n")
            
            # PEB findings
            if "peb_traversal_instances" in total_findings:
                f.write(f"PEB Traversal Instances: {total_findings['peb_traversal_instances']}\n")
                f.write(f"Likely API Resolution Mechanisms: {total_findings['peb_likely_api_resolution']}\n")
            
            # Hash findings
            if "hash_hash_algorithms" in total_findings:
                f.write(f"API Hash Algorithms: {total_findings['hash_hash_algorithms']}\n")
                f.write(f"API Hashes Identified: {total_findings['hash_api_hashes']}\n")
            
            # String findings
            if "string_plain_strings" in total_findings:
                f.write(f"Plain Strings: {total_findings['string_plain_strings']}\n")
                f.write(f"Encoded Strings: {total_findings['string_encoded_strings']}\n")
            
            # Decoder findings
            if "decoder_decoder_functions" in total_findings:
                f.write(f"Decoder Functions: {total_findings['decoder_decoder_functions']}\n")
                f.write(f"High Confidence Decoders: {total_findings['decoder_high_confidence_decoders']}\n")
            
            # API flow findings
            if "api_flow_api_sequences" in total_findings:
                f.write(f"API Sequences: {total_findings['api_flow_api_sequences']}\n")
                f.write(f"Potential C2 Patterns: {total_findings['api_flow_potential_c2']}\n")
                f.write(f"Injection Patterns: {total_findings['api_flow_injection_patterns']}\n")
            
            # Write correlations
            if all_correlations:
                f.write("\nKey Correlations\n")
                f.write("--------------\n")
                
                # Group correlations by type
                correlation_types = defaultdict(list)
                for corr in all_correlations:
                    correlation_types[corr["type"]].append(corr)
                
                for corr_type, correlations in correlation_types.items():
                    f.write(f"\n{corr_type.replace('_', ' ').title()}:\n")
                    for i, corr in enumerate(correlations[:3]):  # Show top 3 of each type
                        f.write(f"  {i+1}. {corr['description']} (Confidence: {corr['confidence']})\n")
                    
                    if len(correlations) > 3:
                        f.write(f"  ... and {len(correlations) - 3} more similar correlations\n")
            
            # Per-file breakdown
            f.write("\nPer-File Analysis Results\n")
            f.write("------------------------\n")
            
            for file_result in results['file_results']:
                f.write(f"\nFile: {file_result['file']}\n")
                
                # Write key findings for this file
                findings = file_result.get("findings", {})
                
                # PEB findings
                if "peb_traversal_instances" in findings:
                    f.write(f"  PEB Traversal Instances: {findings['peb_traversal_instances']}\n")
                
                # Hash findings
                if "hash_hash_algorithms" in findings:
                    f.write(f"  API Hash Algorithms: {findings['hash_hash_algorithms']}\n")
                    f.write(f"  API Hashes Identified: {findings['hash_api_hashes']}\n")
                
                # String findings
                if "string_plain_strings" in findings:
                    f.write(f"  Plain Strings: {findings['string_plain_strings']}\n")
                    f.write(f"  Encoded Strings: {findings['string_encoded_strings']}\n")
                
                # Decoder findings
                if "decoder_decoder_functions" in findings:
                    f.write(f"  Decoder Functions: {findings['decoder_decoder_functions']}\n")
                
                # File-specific correlations
                if file_result.get("correlations"):
                    f.write("  Key Correlations:\n")
                    for corr in file_result["correlations"]:
                        f.write(f"    - {corr['description']}\n")
            
            f.write("\n\nDetailed analysis reports for each component are available in their respective directories.\n")
        
        print(f"Consolidated JSON report saved to: {json_path}")
        print(f"Consolidated text report saved to: {report_path}")
        
        return json_path, report_path
    
    def generate_pattern_database(self, results):
        """Generate a pattern database from analysis results"""
        print("\n[+] Generating pattern database")
        
        patterns_db = {
            "creation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "patterns": {
                "peb_traversal": [],
                "api_hashing": [],
                "string_encoding": [],
                "decoder_functions": [],
                "api_sequences": []
            },
            "metadata": {
                "openvino_acceleration": OPENVINO_AVAILABLE,
                "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE else "None"
            }
        }
        
        # Extract patterns from results
        for file_result in results['file_results']:
            file_name = file_result['file']
            
            # Extract PEB traversal patterns
            for component in file_result.get("components", []):
                if component["name"] == "peb" and component.get("success", False):
                    # Look for the detailed JSON file
                    json_path = os.path.join(self.output_dirs["peb"], f"{file_name}_peb_analysis.json")
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r') as f:
                                peb_data = json.load(f)
                                
                                # Extract patterns from raw matches
                                for match in peb_data.get("raw_peb_matches", [])[:20]:  # Limit to top 20
                                    patterns_db["patterns"]["peb_traversal"].append({
                                        "pattern": match.get("pattern", ""),
                                        "description": match.get("description", ""),
                                        "source_file": file_name
                                    })
                        except Exception as e:
                            print(f"Error extracting PEB patterns: {e}")
            
            # Extract API hashing patterns
            for component in file_result.get("components", []):
                if component["name"] == "hash" and component.get("success", False):
                    # Look for the detailed JSON file
                    json_path = os.path.join(self.output_dirs["hash"], f"{file_name}_hash_analysis.json")
                    if os.path.exists(json_path):
                        try:
                            with open(json_path, 'r') as f:
                                hash_data = json.load(f)
                                
                                # Extract patterns from hash algorithms
                                for algo in hash_data.get("hash_algorithms", []):
                                    patterns_db["patterns"]["api_hashing"].append({
                                        "algorithm": algo.get("algorithm", "unknown"),
                                        "confidence": algo.get("confidence", 0),
                                        "patterns": algo.get("patterns", []),
                                        "source_file": file_name
                                    })
                        except Exception as e:
                            print(f"Error extracting hash patterns: {e}")
        
        # Save pattern database
        db_path = os.path.join(self.output_dirs["pattern_db"], "keyplug_pattern_database.json")
        with open(db_path, 'w') as f:
            json.dump(patterns_db, f, indent=2)
        
        print(f"Pattern database saved to: {db_path}")
        
        # Generate human-readable pattern report
        report_path = os.path.join(self.output_dirs["pattern_db"], "keyplug_pattern_report.txt")
        with open(report_path, 'w') as f:
            f.write("KEYPLUG Pattern Database Report\n")
            f.write("==============================\n\n")
            
            f.write(f"Creation Time: {patterns_db['creation_time']}\n")
            f.write(f"OpenVINO Acceleration: {'Enabled - ' + patterns_db['metadata']['preferred_device'] if OPENVINO_AVAILABLE else 'Disabled'}\n\n")
            
            # PEB traversal patterns
            peb_patterns = patterns_db["patterns"]["peb_traversal"]
            f.write(f"PEB Traversal Patterns: {len(peb_patterns)}\n")
            f.write("------------------------\n")
            for i, pattern in enumerate(peb_patterns[:10]):  # Show top 10
                f.write(f"{i+1}. Pattern: {pattern['pattern']}\n")
                f.write(f"   Description: {pattern['description']}\n")
                f.write(f"   Source: {pattern['source_file']}\n\n")
            
            if len(peb_patterns) > 10:
                f.write(f"... and {len(peb_patterns) - 10} more PEB traversal patterns\n\n")
            
            # API hashing patterns
            hash_patterns = patterns_db["patterns"]["api_hashing"]
            f.write(f"API Hashing Patterns: {len(hash_patterns)}\n")
            f.write("---------------------\n")
            for i, pattern in enumerate(hash_patterns[:10]):  # Show top 10
                f.write(f"{i+1}. Algorithm: {pattern['algorithm']}\n")
                f.write(f"   Confidence: {pattern['confidence']}\n")
                f.write(f"   Patterns: {', '.join(pattern['patterns'][:5])}")
                if len(pattern['patterns']) > 5:
                    f.write(f" ... and {len(pattern['patterns']) - 5} more")
                f.write(f"\n   Source: {pattern['source_file']}\n\n")
            
            if len(hash_patterns) > 10:
                f.write(f"... and {len(hash_patterns) - 10} more API hashing patterns\n")
        
        print(f"Pattern report saved to: {report_path}")
        
        return db_path, report_path

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='KEYPLUG Unified Analysis Orchestrator')
    parser.add_argument('-d', '--dir', help='Directory containing files to analyze', default='extracted_pe')
    parser.add_argument('-o', '--output', help='Base output directory for analysis results', default='keyplug_unified_analysis')
    parser.add_argument('-p', '--pattern', help='File pattern to match', default='*.bin')
    parser.add_argument('-f', '--file', help='Analyze a single file instead of a directory')
    parser.add_argument('--generate-db', help='Generate pattern database from results', action='store_true')
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = UnifiedOrchestrator(args.output)
    
    # Analyze a single file if specified
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
            
        print(f"[+] Analyzing single file: {args.file}")
        orchestrator.analyze_file(args.file)
        return 0
    
    # Validate input directory
    if not os.path.exists(args.dir):
        print(f"Error: Directory {args.dir} not found")
        return 1
    
    # Find files to analyze
    file_pattern = os.path.join(args.dir, args.pattern)
    files = glob.glob(file_pattern)
    
    if not files:
        print(f"No files matching {args.pattern} found in {args.dir}")
        return 1
    
    print(f"[+] Found {len(files)} files to analyze")
    print(f"[+] Using maximum {MAX_WORKERS} CPU cores for parallel processing")
    print(f"[+] Results will be saved to {args.output}")
    
    # Run analysis
    results = orchestrator.analyze_files(files)
    
    # Generate pattern database if requested
    if args.generate_db:
        orchestrator.generate_pattern_database(results)
    
    print("\n[+] Analysis Complete")
    print(f"Results saved to: {args.output}")
    
    return 0

if __name__ == "__main__":
    start_time = time.time()
    exit_code = main()
    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
    sys.exit(exit_code)
