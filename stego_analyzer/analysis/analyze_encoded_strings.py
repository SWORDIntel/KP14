#!/usr/bin/env python3
"""
KEYPLUG Encoded String and Decoder Function Analyzer
--------------------------------------------------
Advanced tool for detecting encoded strings and decoder functions in KEYPLUG malware
using statistical analysis and OpenVINO hardware acceleration for maximum performance.
"""

import os
import sys
import glob
import json
import time
import argparse
from concurrent.futures import ProcessPoolExecutor
from tqdm import tqdm

# Import our custom string decoder modules
from keyplug_string_decoder import EncodedStringDetector, DecoderFunctionIdentifier

def analyze_file(file_path, output_dir, analyze_strings=True, analyze_decoders=True):
    """
    Analyze a single file for encoded strings and decoder functions
    
    Args:
        file_path: Path to the binary file
        output_dir: Directory to save results
        analyze_strings: Whether to analyze encoded strings
        analyze_decoders: Whether to analyze decoder functions
    
    Returns:
        Dict with summary of findings
    """
    print(f"\n[+] Analyzing {os.path.basename(file_path)}")
    
    results = {
        "file": os.path.basename(file_path),
        "file_path": file_path,
        "processing_time": 0,
        "encoded_strings": {
            "count": 0,
            "high_confidence_count": 0
        },
        "decoder_functions": {
            "count": 0,
            "high_confidence_count": 0,
            "types": {}
        }
    }
    
    start_time = time.time()
    
    # Analyze encoded strings
    if analyze_strings:
        print("[+] Analyzing encoded strings...")
        string_detector = EncodedStringDetector()
        string_results = string_detector.analyze_binary_for_encoded_strings(file_path, output_dir)
        
        if string_results:
            results["encoded_strings"]["count"] = len(string_results["encoded_strings"])
            results["encoded_strings"]["high_confidence_count"] = sum(
                1 for s in string_results["encoded_strings"] if s["score"] >= 0.8
            )
    
    # Analyze decoder functions
    if analyze_decoders:
        print("[+] Analyzing decoder functions...")
        decoder_identifier = DecoderFunctionIdentifier()
        decoder_results = decoder_identifier.analyze_binary_for_decoders(file_path, output_dir)
        
        if decoder_results:
            results["decoder_functions"]["count"] = len(decoder_results["decoders"])
            results["decoder_functions"]["high_confidence_count"] = sum(
                1 for d in decoder_results["decoders"] if d["decoder_score"] >= 0.8
            )
            results["decoder_functions"]["types"] = dict(decoder_results["summary"]["decoder_types"])
    
    end_time = time.time()
    results["processing_time"] = end_time - start_time
    
    return results

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='KEYPLUG Encoded String and Decoder Function Analyzer')
    parser.add_argument('-d', '--dir', help='Directory containing extracted PE files', default='extracted_pe')
    parser.add_argument('-o', '--output', help='Output directory for analysis results', default='string_decoder_analysis')
    parser.add_argument('-p', '--pattern', help='File pattern to match', default='*.bin')
    parser.add_argument('-m', '--max-workers', help='Maximum number of parallel processes', type=int, default=os.cpu_count())
    parser.add_argument('--strings-only', help='Only analyze encoded strings', action='store_true')
    parser.add_argument('--decoders-only', help='Only analyze decoder functions', action='store_true')
    parser.add_argument('-f', '--file', help='Analyze a single file instead of a directory')
    args = parser.parse_args()
    
    # Determine what to analyze
    analyze_strings = not args.decoders_only
    analyze_decoders = not args.strings_only
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Analyze a single file if specified
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
            
        print(f"[+] Analyzing single file: {args.file}")
        results = analyze_file(args.file, args.output, analyze_strings, analyze_decoders)
        
        # Save summary
        summary_path = os.path.join(args.output, f"{os.path.basename(args.file)}_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"[+] Analysis complete. Results saved to {args.output}")
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
    print(f"[+] Results will be saved to {args.output}")
    
    if analyze_strings:
        print("[+] Will analyze encoded strings")
    if analyze_decoders:
        print("[+] Will analyze decoder functions")
    
    # Process files in parallel for maximum performance
    start_time = time.time()
    summaries = []
    
    with ProcessPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {
            executor.submit(
                analyze_file, 
                file_path, 
                args.output,
                analyze_strings,
                analyze_decoders
            ): file_path for file_path in files
        }
        
        for future in tqdm(futures, desc="Processing files", unit="file"):
            try:
                result = future.result()
                summaries.append(result)
            except Exception as e:
                print(f"Error processing {futures[future]}: {e}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Generate overall summary
    total_encoded_strings = sum(s["encoded_strings"]["count"] for s in summaries)
    total_high_conf_strings = sum(s["encoded_strings"]["high_confidence_count"] for s in summaries)
    total_decoders = sum(s["decoder_functions"]["count"] for s in summaries)
    total_high_conf_decoders = sum(s["decoder_functions"]["high_confidence_count"] for s in summaries)
    
    # Aggregate decoder types
    decoder_types = {}
    for summary in summaries:
        for decoder_type, count in summary["decoder_functions"].get("types", {}).items():
            if decoder_type not in decoder_types:
                decoder_types[decoder_type] = 0
            decoder_types[decoder_type] += count
    
    print("\n[+] Analysis Complete")
    print(f"Total files analyzed: {len(files)}")
    
    if analyze_strings:
        print(f"Total encoded strings detected: {total_encoded_strings}")
        print(f"High confidence encoded strings: {total_high_conf_strings}")
    
    if analyze_decoders:
        print(f"Total decoder functions detected: {total_decoders}")
        print(f"High confidence decoder functions: {total_high_conf_decoders}")
        
        print("\nDecoder function types:")
        for decoder_type, count in decoder_types.items():
            print(f"  - {decoder_type}: {count}")
    
    print(f"Total processing time: {total_time:.2f} seconds")
    
    # Save overall summary
    summary_path = os.path.join(args.output, "analysis_summary.json")
    with open(summary_path, 'w') as f:
        summary_data = {
            "total_files": len(files),
            "total_encoded_strings": total_encoded_strings,
            "high_confidence_encoded_strings": total_high_conf_strings,
            "total_decoder_functions": total_decoders,
            "high_confidence_decoder_functions": total_high_conf_decoders,
            "decoder_types": decoder_types,
            "total_time": total_time,
            "file_summaries": summaries
        }
        json.dump(summary_data, f, indent=2)
    
    print(f"Summary saved to {summary_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
