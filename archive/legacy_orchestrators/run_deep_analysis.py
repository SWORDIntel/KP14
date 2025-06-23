#!/usr/bin/env python3
"""
Run Deep Multi-Layer Analysis on KEYPLUG Extracted PE Files
This script automates the process of analyzing all extracted PE files using
the OpenVINO-accelerated unified orchestrator with maximum CPU utilization.

Enhanced with source code extraction capabilities for comprehensive analysis.
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

# Import source code extractor components
from keyplug_source_extractor import SourceCodeExtractor

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
OUTPUT_BASE_DIR = "keyplug_deep_analysis"
MAX_WORKERS = os.cpu_count()
MAX_DEPTH = 5  # Maximum decryption depth
SOURCE_EXTRACTION_ENABLED = True  # Enable source code extraction
print(f"Using maximum CPU cores: {MAX_WORKERS}")

def analyze_file(file_path, use_unified=True, extract_source=True):
    """Analyze a single file with deep multi-layer analysis"""
    file_name = os.path.basename(file_path)
    output_dir = os.path.join(OUTPUT_BASE_DIR, file_name + "_analysis")
    
    print(f"Starting deep analysis of {file_name}...")
    
    try:
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # First run multi-layer decryption to extract all layers
        multilayer_dir = os.path.join(output_dir, "multilayer")
        if not os.path.exists(multilayer_dir):
            os.makedirs(multilayer_dir)
        
        # Run the multi-layer extractor with maximum depth and OpenVINO acceleration
        print(f"[1/3] Running multi-layer decryption on {file_name}...")
        cmd = [
            "python", 
            "keyplug_multilayer_extractor.py", 
            "-f", file_path, 
            "-o", multilayer_dir,
            "--max-depth", str(MAX_DEPTH)
        ]
        
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Error in multi-layer decryption: {result.stderr}")
            return False, file_name, result.stderr
        
        # Find all extracted layers
        layers = glob.glob(os.path.join(multilayer_dir, f"{file_name}_layer_*.bin"))
        if not layers:
            print(f"No layers extracted from {file_name}")
            layers = [file_path]  # Analyze original file if no layers extracted
        
        print(f"Extracted {len(layers)} layers from {file_name}")
        
        # Run unified analysis on each layer
        if use_unified:
            print(f"[2/4] Running unified analysis on all extracted layers...")
            unified_dir = os.path.join(output_dir, "unified_analysis")
            
            # Run the unified orchestrator on all layers
            cmd = [
                "python", 
                "keyplug_unified_orchestrator.py", 
                "-o", unified_dir,
                "--generate-db"
            ]
            
            # Add each layer as a file to analyze
            for layer in layers:
                cmd.extend(["-f", layer])
            
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                print(f"Error in unified analysis: {result.stderr}")
                return False, file_name, result.stderr
            
            print(f"Unified analysis complete. Results saved to {unified_dir}")
        
        # Extract source code from each layer if requested
        if extract_source and SOURCE_EXTRACTION_ENABLED:
            print(f"[3/4] Extracting source code from all layers...")
            source_dir = os.path.join(output_dir, "source_code")
            
            # Initialize source code extractor with OpenVINO acceleration
            extractor = SourceCodeExtractor(use_openvino=OPENVINO_AVAILABLE)
            
            # Process each layer in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_layer = {
                    executor.submit(
                        extractor.extract_source_code,
                        layer,
                        source_dir,
                        decompiler_type="ghidra",  # Default to Ghidra
                        detect_boundaries=True,
                        infer_types=True,
                        recover_control_flow=True,
                        detect_idioms=True
                    ): layer for layer in layers
                }
                
                for future in concurrent.futures.as_completed(future_to_layer):
                    layer = future_to_layer[future]
                    try:
                        layer_output_dir = future.result()
                        if layer_output_dir:
                            print(f"Successfully extracted source code from {os.path.basename(layer)}")
                        else:
                            print(f"Failed to extract source code from {os.path.basename(layer)}")
                    except Exception as e:
                        print(f"Error extracting source code from {os.path.basename(layer)}: {e}")
            
            print(f"Source code extraction complete. Results saved to {source_dir}")
        
        # Run API flow analysis
        print(f"[4/4] Running API flow analysis on all extracted layers...")
        api_flow_dir = os.path.join(output_dir, "api_flow")
        if not os.path.exists(api_flow_dir):
            os.makedirs(api_flow_dir)
        
        for layer in layers:
            layer_name = os.path.basename(layer)
            cmd = [
                "python", 
                "keyplug_advanced_analysis.py", 
                "-f", layer, 
                "-o", os.path.join(api_flow_dir, f"{layer_name}_api_flow.json"),
                "--use-openvino"
            ]
            
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Generate consolidated report
        generate_consolidated_report(file_name, output_dir, layers)
        
        print(f"Successfully completed deep analysis of {file_name}")
        return True, file_name, output_dir
    
    except Exception as e:
        print(f"Exception analyzing {file_name}: {str(e)}")
        return False, file_name, str(e)

def generate_consolidated_report(file_name, output_dir, layers, include_source=True):
    """Generate a consolidated report of all analysis results"""
    report = {
        "file": file_name,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "openvino_acceleration": OPENVINO_AVAILABLE,
        "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE else "None",
        "cpu_cores": MAX_WORKERS,
        "layers": [],
        "summary": {
            "total_layers": len(layers),
            "potential_c2_endpoints": 0,
            "potential_injection_points": 0,
            "api_hashing_algorithms": 0,
            "encoded_strings": 0,
            "decoder_functions": 0
        }
    }
    
    # Collect data from each layer
    for layer in layers:
        layer_name = os.path.basename(layer)
        layer_data = {
            "name": layer_name,
            "size": os.path.getsize(layer),
            "findings": {}
        }
        
        # Check for unified analysis results
        unified_dir = os.path.join(output_dir, "unified_analysis")
        unified_json = os.path.join(unified_dir, "unified_analysis_results.json")
        if os.path.exists(unified_json):
            try:
                with open(unified_json, 'r') as f:
                    unified_data = json.load(f)
                    
                    # Find this layer's results
                    for file_result in unified_data.get("file_results", []):
                        if file_result.get("file") == layer_name:
                            layer_data["findings"].update(file_result.get("findings", {}))
                            layer_data["correlations"] = file_result.get("correlations", [])
            except Exception as e:
                print(f"Error loading unified analysis results: {e}")
        
        # Check for API flow results
        api_flow_dir = os.path.join(output_dir, "api_flow")
        api_flow_json = os.path.join(api_flow_dir, f"{layer_name}_api_flow.json")
        if os.path.exists(api_flow_json):
            try:
                with open(api_flow_json, 'r') as f:
                    api_flow_data = json.load(f)
                    
                    # Add API flow findings
                    layer_data["findings"]["api_flow"] = {
                        "potential_c2": len(api_flow_data.get("potential_c2", [])),
                        "injection_points": len(api_flow_data.get("injection_points", [])),
                        "api_sequences": len(api_flow_data.get("api_sequences", []))
                    }
                    
                    # Update summary
                    report["summary"]["potential_c2_endpoints"] += len(api_flow_data.get("potential_c2", []))
                    report["summary"]["potential_injection_points"] += len(api_flow_data.get("injection_points", []))
            except Exception as e:
                print(f"Error loading API flow results: {e}")
        
        # Add layer data to report
        report["layers"].append(layer_data)
    
    # Save consolidated report
    report_path = os.path.join(output_dir, f"{file_name}_consolidated_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Generate human-readable report
    txt_report_path = os.path.join(output_dir, f"{file_name}_deep_analysis_report.txt")
    with open(txt_report_path, 'w') as f:
        f.write(f"KEYPLUG Deep Analysis Report for {file_name}\n")
        f.write("=" * (35 + len(file_name)) + "\n\n")
        
        f.write(f"Analysis Time: {report['analysis_time']}\n")
        f.write(f"OpenVINO Acceleration: {'Enabled - ' + report['preferred_device'] if OPENVINO_AVAILABLE else 'Disabled'}\n")
        f.write(f"CPU Cores Utilized: {report['cpu_cores']}\n\n")
        
        f.write("Summary\n-------\n")
        f.write(f"Total Layers Extracted: {report['summary']['total_layers']}\n")
        f.write(f"Potential C2 Endpoints: {report['summary']['potential_c2_endpoints']}\n")
        f.write(f"Potential Injection Points: {report['summary']['potential_injection_points']}\n")
        f.write(f"API Hashing Algorithms: {report['summary']['api_hashing_algorithms']}\n")
        f.write(f"Encoded Strings: {report['summary']['encoded_strings']}\n")
        f.write(f"Decoder Functions: {report['summary']['decoder_functions']}\n\n")
        
        f.write("Layer Analysis\n-------------\n")
        for layer_data in report["layers"]:
            f.write(f"\nLayer: {layer_data['name']}\n")
            f.write(f"Size: {layer_data['size']} bytes\n")
            
            # Write findings
            if layer_data.get("findings"):
                f.write("Findings:\n")
                for category, values in layer_data["findings"].items():
                    if isinstance(values, dict):
                        f.write(f"  {category.replace('_', ' ').title()}:\n")
                        for key, value in values.items():
                            f.write(f"    - {key.replace('_', ' ').title()}: {value}\n")
                    else:
                        f.write(f"  {category.replace('_', ' ').title()}: {values}\n")
            
            # Write correlations
            if layer_data.get("correlations"):
                f.write("\nKey Correlations:\n")
                for corr in layer_data["correlations"]:
                    f.write(f"  - {corr.get('description', 'Unknown correlation')} ")
                    f.write(f"(Confidence: {corr.get('confidence', 'unknown')})\n")
        
        f.write("\n\nDetailed analysis reports for each component are available in their respective directories.\n")
    
    print(f"Consolidated report saved to: {report_path}")
    print(f"Human-readable report saved to: {txt_report_path}")

def main():
    """Main function to analyze all extracted PE files"""
    global OUTPUT_BASE_DIR, MAX_DEPTH
    
    parser = argparse.ArgumentParser(description='KEYPLUG Deep Analysis Tool')
    parser.add_argument('-d', '--dir', help='Directory containing files to analyze', default=EXTRACTED_PE_DIR)
    parser.add_argument('-o', '--output', help='Base output directory for analysis results', default=OUTPUT_BASE_DIR)
    parser.add_argument('-f', '--file', help='Analyze a single file instead of a directory')
    parser.add_argument('--max-depth', type=int, help='Maximum decryption depth', default=MAX_DEPTH)
    parser.add_argument('--no-unified', action='store_true', help='Skip unified analysis')
    parser.add_argument('--no-source', action='store_true', help='Disable source code extraction')
    parser.add_argument('--decompiler', help='Decompiler to use (ghidra, retdec, ida)', default='ghidra')
    args = parser.parse_args()
    
    # Update global variables based on arguments
    OUTPUT_BASE_DIR = args.output
    MAX_DEPTH = args.max_depth
    
    if not os.path.exists(OUTPUT_BASE_DIR):
        os.makedirs(OUTPUT_BASE_DIR)
    
    # Analyze a single file if specified
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
            
        print(f"[+] Running deep analysis on single file: {args.file}")
        success, file_name, output_dir = analyze_file(args.file, not args.no_unified, not args.no_source)
        
        if success:
            print(f"\nDeep analysis complete for {file_name}")
            print(f"Results saved to: {output_dir}")
        else:
            print(f"\nDeep analysis failed for {file_name}")
        
        return 0 if success else 1
    
    # Validate input directory
    if not os.path.exists(args.dir):
        print(f"Error: Directory {args.dir} not found")
        return 1
    
    # Find all files to analyze
    pe_files = glob.glob(os.path.join(args.dir, "*.bin"))
    
    if not pe_files:
        print(f"No .bin files found in {args.dir}")
        return 1
    
    print(f"Found {len(pe_files)} files to analyze")
    print(f"Using OpenVINO acceleration with up to {MAX_DEPTH} decryption layers")
    print(f"Utilizing {MAX_WORKERS} CPU cores for maximum performance")
    
    start_time = time.time()
    
    # Process files in parallel
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(analyze_file, file_path, not args.no_unified, not args.no_source): file_path for file_path in pe_files}
        
        for future in concurrent.futures.as_completed(futures):
            file_path = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Print summary
    successful = [r for r in results if r[0]]
    failed = [r for r in results if not r[0]]
    
    print("\n===== ANALYSIS SUMMARY =====")
    print(f"Total files processed: {len(pe_files)}")
    print(f"Successfully analyzed: {len(successful)}")
    print(f"Failed to analyze: {len(failed)}")
    print(f"Total processing time: {total_time:.2f} seconds")
    print(f"Average time per file: {total_time/len(pe_files):.2f} seconds")
    
    if successful:
        print("\nSuccessfully analyzed files:")
        for _, file_name, output_dir in successful:
            print(f"  - {file_name} (results in {output_dir})")
    
    if failed:
        print("\nFailed to analyze files:")
        for _, file_name, error in failed:
            print(f"  - {file_name}: {error[:100]}...")
    
    # Generate master report combining all file results
    master_report_path = os.path.join(OUTPUT_BASE_DIR, "master_report.json")
    master_txt_path = os.path.join(OUTPUT_BASE_DIR, "master_report.txt")
    
    master_report = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": len(pe_files),
        "successful": len(successful),
        "failed": len(failed),
        "openvino_acceleration": OPENVINO_AVAILABLE,
        "preferred_device": PREFERRED_DEVICE if OPENVINO_AVAILABLE else "None",
        "cpu_cores": MAX_WORKERS,
        "processing_time": total_time,
        "file_results": []
    }
    
    # Collect all file results
    for success, file_name, output_dir in successful:
        report_path = os.path.join(output_dir, f"{file_name}_consolidated_report.json")
        if os.path.exists(report_path):
            try:
                with open(report_path, 'r') as f:
                    file_report = json.load(f)
                    master_report["file_results"].append(file_report)
            except Exception as e:
                print(f"Error loading report for {file_name}: {e}")
    
    # Save master report
    with open(master_report_path, 'w') as f:
        json.dump(master_report, f, indent=2)
    
    # Generate human-readable master report
    with open(master_txt_path, 'w') as f:
        f.write("KEYPLUG Master Analysis Report\n")
        f.write("=============================\n\n")
        
        f.write(f"Analysis Time: {master_report['analysis_time']}\n")
        f.write(f"Total Files Analyzed: {master_report['total_files']}\n")
        f.write(f"Successfully Analyzed: {master_report['successful']}\n")
        f.write(f"Failed to Analyze: {master_report['failed']}\n")
        f.write(f"OpenVINO Acceleration: {'Enabled - ' + master_report['preferred_device'] if OPENVINO_AVAILABLE else 'Disabled'}\n")
        f.write(f"CPU Cores Utilized: {master_report['cpu_cores']}\n")
        f.write(f"Total Processing Time: {master_report['processing_time']:.2f} seconds\n\n")
        
        f.write("Summary of Findings\n")
        f.write("-----------------\n")
        
        # Aggregate findings across all files
        total_layers = 0
        total_c2 = 0
        total_injection = 0
        total_hash_algos = 0
        total_encoded_strings = 0
        total_decoders = 0
        total_source_files = 0
        
        for file_result in master_report.get("file_results", []):
            summary = file_result.get("summary", {})
            total_layers += summary.get("total_layers", 0)
            total_c2 += summary.get("potential_c2_endpoints", 0)
            total_injection += summary.get("potential_injection_points", 0)
            total_hash_algos += summary.get("api_hashing_algorithms", 0)
            total_encoded_strings += summary.get("encoded_strings", 0)
            total_decoders += summary.get("decoder_functions", 0)
        
        f.write(f"Total Layers Extracted: {total_layers}\n")
        f.write(f"Potential C2 Endpoints: {total_c2}\n")
        f.write(f"Potential Injection Points: {total_injection}\n")
        f.write(f"API Hashing Algorithms: {total_hash_algos}\n")
        f.write(f"Encoded Strings: {total_encoded_strings}\n")
        f.write(f"Decoder Functions: {total_decoders}\n")
        
        # Add source code extraction summary if enabled
        if SOURCE_EXTRACTION_ENABLED:
            for layer_result in master_report.get("layers", []):
                if "source_code" in layer_result:
                    total_source_files += layer_result["source_code"].get("file_count", 0)
            f.write(f"Source Code Files Extracted: {total_source_files}\n\n")
        else:
            f.write("\n")
        
        f.write("Per-File Summary\n")
        f.write("--------------\n")
        
        for file_result in master_report.get("file_results", []):
            f.write(f"\nFile: {file_result.get('file', 'Unknown')}\n")
            summary = file_result.get("summary", {})
            f.write(f"  Layers: {summary.get('total_layers', 0)}\n")
            f.write(f"  C2 Endpoints: {summary.get('potential_c2_endpoints', 0)}\n")
            f.write(f"  Injection Points: {summary.get('potential_injection_points', 0)}\n")
            
            # List the most significant findings
            significant_findings = []
            for layer in file_result.get("layers", []):
                for corr in layer.get("correlations", []):
                    if corr.get("confidence") == "high":
                        significant_findings.append(corr.get("description", "Unknown correlation"))
            
            if significant_findings:
                f.write("  Significant Findings:\n")
                for i, finding in enumerate(significant_findings[:3]):  # Show top 3
                    f.write(f"    {i+1}. {finding}\n")
                
                if len(significant_findings) > 3:
                    f.write(f"    ... and {len(significant_findings) - 3} more findings\n")
        
        f.write("\n\nComplete! Check individual file reports for detailed analysis results.\n")
    
    print(f"\nMaster report saved to: {master_report_path}")
    print(f"Human-readable master report saved to: {master_txt_path}")
    print("\nComplete! Check the output directories for detailed analysis results.")
    
    return 0

if __name__ == "__main__":
    start_time = time.time()
    exit_code = main()
    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
    sys.exit(exit_code)
