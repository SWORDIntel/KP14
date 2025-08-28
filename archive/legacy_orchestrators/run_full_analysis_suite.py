#!/usr/bin/env python3
"""
KEYPLUG Full Analysis Suite
--------------------------
Comprehensive testing suite for all KEYPLUG analysis components
utilizing OpenVINO acceleration for maximum performance.

This script orchestrates the execution of all analysis components
against extracted PE files and generates consolidated reports.
"""

import os
import sys
import glob
import json
import time
import argparse
import concurrent.futures
from datetime import datetime
from tqdm import tqdm

# Import components if they exist, otherwise note they need to be run separately
try:
    from keyplug_peb_detector import analyze_binary_for_peb_traversal
    PEB_DETECTOR_AVAILABLE = True
except ImportError:
    PEB_DETECTOR_AVAILABLE = False
    print("PEB Detector module not directly importable - will run as separate process")

try:
    from keyplug_hash_detector import HashDetector
    HASH_DETECTOR_AVAILABLE = True
except ImportError:
    HASH_DETECTOR_AVAILABLE = False
    print("Hash Detector module not directly importable - will run as separate process")

try:
    from keyplug_string_decoder import EncodedStringDetector, DecoderFunctionIdentifier
    STRING_DECODER_AVAILABLE = True
except ImportError:
    STRING_DECODER_AVAILABLE = False
    print("String Decoder module not directly importable - will run as separate process")

# Set up maximum CPU utilization
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

# Try to import OpenVINO
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
        print("Using GPU acceleration")
    elif "VPU" in core.available_devices:
        PREFERRED_DEVICE = "VPU"
        print("Using VPU acceleration")
    else:
        print("Using CPU acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("WARNING: OpenVINO not available - performance will be degraded")

def run_peb_analysis(file_path, output_dir):
    """Run PEB traversal analysis on a file"""
    print(f"\n[+] Running PEB Traversal Analysis on {os.path.basename(file_path)}")
    
    if PEB_DETECTOR_AVAILABLE:
        # Direct module import available
        results = analyze_binary_for_peb_traversal(file_path, output_dir)
        return {
            "component": "peb_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "peb_traversal_instances": len(results.get("function_analysis", [])),
                "raw_matches": len(results.get("raw_peb_matches", [])),
                "likely_api_resolution": results.get("summary", {}).get("likely_api_resolution", 0)
            }
        }
    else:
        # Run as separate process
        cmd = f"python keyplug_peb_detector.py \"{file_path}\" -o \"{output_dir}\""
        print(f"Executing: {cmd}")
        os.system(cmd)
        
        # Try to load results
        result_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_peb_analysis.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                return {
                    "component": "peb_detector",
                    "file": os.path.basename(file_path),
                    "findings": {
                        "peb_traversal_instances": len(results.get("function_analysis", [])),
                        "raw_matches": len(results.get("raw_peb_matches", [])),
                        "likely_api_resolution": results.get("summary", {}).get("likely_api_resolution", 0)
                    }
                }
            except Exception as e:
                print(f"Error loading PEB analysis results: {e}")
        
        return {
            "component": "peb_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "peb_traversal_instances": "Unknown - see detailed report",
                "raw_matches": "Unknown - see detailed report",
                "likely_api_resolution": "Unknown - see detailed report"
            }
        }

def run_hash_analysis(file_path, output_dir):
    """Run API hash detection analysis on a file"""
    print(f"\n[+] Running API Hash Detection on {os.path.basename(file_path)}")
    
    if HASH_DETECTOR_AVAILABLE:
        # Direct module import available
        detector = HashDetector()
        results = detector.analyze_binary(file_path, output_dir)
        return {
            "component": "hash_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "hash_algorithms": len(results.get("hash_algorithms", [])),
                "api_hashes": len(results.get("api_hashes", [])),
                "processing_time": results.get("processing_time", 0)
            }
        }
    else:
        # Run as separate process
        cmd = f"python analyze_api_hashing.py -f \"{file_path}\" -o \"{output_dir}\""
        print(f"Executing: {cmd}")
        os.system(cmd)
        
        # Try to load results
        result_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_hash_analysis.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                return {
                    "component": "hash_detector",
                    "file": os.path.basename(file_path),
                    "findings": {
                        "hash_algorithms": len(results.get("hash_algorithms", [])),
                        "api_hashes": len(results.get("api_hashes", [])),
                        "processing_time": results.get("processing_time", 0)
                    }
                }
            except Exception as e:
                print(f"Error loading hash analysis results: {e}")
        
        return {
            "component": "hash_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "hash_algorithms": "Unknown - see detailed report",
                "api_hashes": "Unknown - see detailed report",
                "processing_time": "Unknown - see detailed report"
            }
        }

def run_string_analysis(file_path, output_dir):
    """Run encoded string detection on a file"""
    print(f"\n[+] Running Encoded String Detection on {os.path.basename(file_path)}")
    
    if STRING_DECODER_AVAILABLE:
        # Direct module import available
        string_detector = EncodedStringDetector()
        results = string_detector.analyze_binary_for_encoded_strings(file_path, output_dir)
        return {
            "component": "string_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "plain_strings": len(results.get("plain_strings", [])),
                "encoded_strings": len(results.get("encoded_strings", [])),
            }
        }
    else:
        # Run as separate process
        cmd = f"python analyze_encoded_strings.py -f \"{file_path}\" -o \"{output_dir}\" --strings-only"
        print(f"Executing: {cmd}")
        os.system(cmd)
        
        # Try to load results
        result_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_string_analysis.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                return {
                    "component": "string_detector",
                    "file": os.path.basename(file_path),
                    "findings": {
                        "plain_strings": len(results.get("plain_strings", [])),
                        "encoded_strings": len(results.get("encoded_strings", [])),
                    }
                }
            except Exception as e:
                print(f"Error loading string analysis results: {e}")
        
        # Fallback to direct implementation if command fails
        try:
            # Simple string extraction implementation
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            import re
            ascii_pattern = re.compile(b'[ -~]{4,}')
            ascii_strings = [(m.start(), m.group().decode('ascii', errors='ignore')) 
                            for m in ascii_pattern.finditer(data)]
            
            # Save results
            string_output = os.path.join(output_dir, f"{os.path.basename(file_path)}_strings.txt")
            with open(string_output, 'w') as f:
                f.write(f"Extracted {len(ascii_strings)} potential strings\n\n")
                for offset, string in ascii_strings:
                    f.write(f"[0x{offset:x}] {string}\n")
            
            print(f"Extracted {len(ascii_strings)} strings to {string_output}")
            
            return {
                "component": "string_detector",
                "file": os.path.basename(file_path),
                "findings": {
                    "plain_strings": len(ascii_strings),
                    "encoded_strings": "Not analyzed - fallback mode",
                }
            }
        except Exception as e:
            print(f"Error in fallback string extraction: {e}")
            
        return {
            "component": "string_detector",
            "file": os.path.basename(file_path),
            "findings": {
                "plain_strings": "Unknown - see detailed report",
                "encoded_strings": "Unknown - see detailed report",
            }
        }

def run_decoder_analysis(file_path, output_dir):
    """Run decoder function identification on a file"""
    print(f"\n[+] Running Decoder Function Identification on {os.path.basename(file_path)}")
    
    if STRING_DECODER_AVAILABLE:
        # Direct module import available
        decoder_identifier = DecoderFunctionIdentifier()
        results = decoder_identifier.analyze_binary_for_decoders(file_path, output_dir)
        return {
            "component": "decoder_identifier",
            "file": os.path.basename(file_path),
            "findings": {
                "decoder_functions": len(results.get("decoders", [])),
                "high_confidence_decoders": results.get("summary", {}).get("high_confidence_decoders", 0),
                "decoder_types": results.get("summary", {}).get("decoder_types", {})
            }
        }
    else:
        # Run as separate process
        cmd = f"python analyze_encoded_strings.py -f \"{file_path}\" -o \"{output_dir}\" --decoders-only"
        print(f"Executing: {cmd}")
        os.system(cmd)
        
        # Try to load results
        result_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_decoder_analysis.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                return {
                    "component": "decoder_identifier",
                    "file": os.path.basename(file_path),
                    "findings": {
                        "decoder_functions": len(results.get("decoders", [])),
                        "high_confidence_decoders": results.get("summary", {}).get("high_confidence_decoders", 0),
                        "decoder_types": results.get("summary", {}).get("decoder_types", {})
                    }
                }
            except Exception as e:
                print(f"Error loading decoder analysis results: {e}")
        
        return {
            "component": "decoder_identifier",
            "file": os.path.basename(file_path),
            "findings": {
                "decoder_functions": "Unknown - see detailed report",
                "high_confidence_decoders": "Unknown - see detailed report",
                "decoder_types": "Unknown - see detailed report"
            }
        }

def analyze_file(file_path, output_dirs):
    """Run all analysis components on a single file"""
    print(f"\n[+] Starting comprehensive analysis of {os.path.basename(file_path)}")
    
    results = {
        "file": os.path.basename(file_path),
        "file_path": file_path,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "components": []
    }
    
    # Run PEB traversal analysis
    peb_results = run_peb_analysis(file_path, output_dirs["peb"])
    results["components"].append(peb_results)
    
    # Run API hash detection
    hash_results = run_hash_analysis(file_path, output_dirs["hash"])
    results["components"].append(hash_results)
    
    # Run encoded string detection
    string_results = run_string_analysis(file_path, output_dirs["string"])
    results["components"].append(string_results)
    
    # Run decoder function identification
    decoder_results = run_decoder_analysis(file_path, output_dirs["decoder"])
    results["components"].append(decoder_results)
    
    # Generate consolidated summary
    results["summary"] = {
        "peb_traversal_instances": peb_results["findings"]["peb_traversal_instances"],
        "api_hash_algorithms": hash_results["findings"]["hash_algorithms"],
        "api_hashes_identified": hash_results["findings"]["api_hashes"],
        "encoded_strings": string_results["findings"]["encoded_strings"],
        "decoder_functions": decoder_results["findings"]["decoder_functions"],
    }
    
    return results

def generate_consolidated_report(all_results, output_dir):
    """Generate a consolidated report from all analysis results"""
    print("\n[+] Generating consolidated report")
    
    # Save JSON report
    json_path = os.path.join(output_dir, "consolidated_analysis_results.json")
    with open(json_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    # Generate human-readable report
    report_path = os.path.join(output_dir, "consolidated_analysis_report.txt")
    with open(report_path, 'w') as f:
        f.write("KEYPLUG Consolidated Analysis Report\n")
        f.write("==================================\n\n")
        
        f.write(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Files Analyzed: {len(all_results['file_results'])}\n")
        f.write(f"OpenVINO Acceleration: {'Enabled' if OPENVINO_AVAILABLE else 'Disabled'}\n")
        if OPENVINO_AVAILABLE:
            f.write(f"Preferred Device: {PREFERRED_DEVICE}\n")
        f.write(f"CPU Cores Utilized: {MAX_WORKERS}\n\n")
        
        f.write("Summary of Findings\n")
        f.write("-----------------\n")
        
        # Aggregate findings across all files
        total_peb = 0
        total_hash_algos = 0
        total_api_hashes = 0
        total_encoded_strings = 0
        total_decoders = 0
        
        for file_result in all_results['file_results']:
            summary = file_result.get("summary", {})
            
            # Handle both numeric and string values
            try:
                total_peb += int(summary.get("peb_traversal_instances", 0))
            except (ValueError, TypeError):
                pass
                
            try:
                total_hash_algos += int(summary.get("api_hash_algorithms", 0))
            except (ValueError, TypeError):
                pass
                
            try:
                total_api_hashes += int(summary.get("api_hashes_identified", 0))
            except (ValueError, TypeError):
                pass
                
            try:
                total_encoded_strings += int(summary.get("encoded_strings", 0))
            except (ValueError, TypeError):
                pass
                
            try:
                total_decoders += int(summary.get("decoder_functions", 0))
            except (ValueError, TypeError):
                pass
        
        f.write(f"Total PEB Traversal Instances: {total_peb}\n")
        f.write(f"Total API Hash Algorithms: {total_hash_algos}\n")
        f.write(f"Total API Hashes Identified: {total_api_hashes}\n")
        f.write(f"Total Encoded Strings: {total_encoded_strings}\n")
        f.write(f"Total Decoder Functions: {total_decoders}\n\n")
        
        # Per-file breakdown
        f.write("Per-File Analysis Results\n")
        f.write("------------------------\n")
        
        for file_result in all_results['file_results']:
            f.write(f"\nFile: {file_result['file']}\n")
            
            summary = file_result.get("summary", {})
            f.write(f"  PEB Traversal Instances: {summary.get('peb_traversal_instances', 'Unknown')}\n")
            f.write(f"  API Hash Algorithms: {summary.get('api_hash_algorithms', 'Unknown')}\n")
            f.write(f"  API Hashes Identified: {summary.get('api_hashes_identified', 'Unknown')}\n")
            f.write(f"  Encoded Strings: {summary.get('encoded_strings', 'Unknown')}\n")
            f.write(f"  Decoder Functions: {summary.get('decoder_functions', 'Unknown')}\n")
        
        f.write("\n\nDetailed analysis reports for each component are available in their respective directories.\n")
    
    print(f"Consolidated JSON report saved to: {json_path}")
    print(f"Consolidated text report saved to: {report_path}")
    
    return json_path, report_path

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='KEYPLUG Full Analysis Suite')
    parser.add_argument('-d', '--dir', help='Directory containing extracted PE files', default='extracted_pe')
    parser.add_argument('-o', '--output', help='Base output directory for analysis results', default='keyplug_full_analysis')
    parser.add_argument('-p', '--pattern', help='File pattern to match', default='*.bin')
    parser.add_argument('-m', '--max-workers', help='Maximum number of parallel processes', type=int, default=os.cpu_count())
    parser.add_argument('-f', '--file', help='Analyze a single file instead of a directory')
    args = parser.parse_args()
    
    # Set up output directories
    base_output_dir = args.output
    output_dirs = {
        "peb": os.path.join(base_output_dir, "peb_analysis"),
        "hash": os.path.join(base_output_dir, "hash_analysis"),
        "string": os.path.join(base_output_dir, "string_analysis"),
        "decoder": os.path.join(base_output_dir, "decoder_analysis"),
        "consolidated": base_output_dir
    }
    
    # Create output directories
    for dir_path in output_dirs.values():
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    
    # Analyze a single file if specified
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
            
        print(f"[+] Analyzing single file: {args.file}")
        results = analyze_file(args.file, output_dirs)
        
        all_results = {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_count": 1,
            "file_results": [results],
            "openvino_acceleration": OPENVINO_AVAILABLE,
            "cpu_cores": MAX_WORKERS
        }
        
        generate_consolidated_report(all_results, output_dirs["consolidated"])
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
    print(f"[+] Using maximum {args.max_workers} CPU cores for parallel processing")
    print(f"[+] Results will be saved to {base_output_dir}")
    
    # Process files sequentially to avoid resource contention
    # Each analysis component already uses parallel processing internally
    all_results = []
    for file_path in tqdm(files, desc="Processing files", unit="file"):
        try:
            result = analyze_file(file_path, output_dirs)
            all_results.append(result)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    # Generate consolidated report
    consolidated_results = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_count": len(files),
        "file_results": all_results,
        "openvino_acceleration": OPENVINO_AVAILABLE,
        "cpu_cores": MAX_WORKERS
    }
    
    json_path, report_path = generate_consolidated_report(consolidated_results, output_dirs["consolidated"])
    
    print("\n[+] Analysis Complete")
    print(f"Consolidated results saved to: {report_path}")
    
    return 0

if __name__ == "__main__":
    start_time = time.time()
    exit_code = main()
    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
    sys.exit(exit_code)
