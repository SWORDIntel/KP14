#!/usr/bin/env python3
"""
KEYPLUG API Hash Detection Launcher
----------------------------------
Analyzes extracted PE files to detect API hashing techniques used in KEYPLUG malware
utilizing OpenVINO acceleration for maximum performance.
"""

import os
import sys
import glob
import json
import time
import argparse
from concurrent.futures import ProcessPoolExecutor
from tqdm import tqdm

# Import our custom hash detector modules
from keyplug_hash_detector import HashDetector

def analyze_file(file_path, output_dir):
    """
    Analyze a single file for API hashing techniques
    
    Args:
        file_path: Path to the binary file
        output_dir: Directory to save results
    
    Returns:
        Dict with summary of findings
    """
    print(f"\n[+] Analyzing {os.path.basename(file_path)}")
    
    # Initialize the hash detector
    detector = HashDetector()
    
    # Analyze the file
    results = detector.analyze_binary(file_path, output_dir)
    
    summary = {
        "file": os.path.basename(file_path),
        "hash_algorithms_count": len(results["hash_algorithms"]),
        "api_hashes_count": len(results["api_hashes"]),
        "processing_time": results["processing_time"]
    }
    
    return summary

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='KEYPLUG API Hash Detection Tool')
    parser.add_argument('-d', '--dir', help='Directory containing extracted PE files', default='extracted_pe')
    parser.add_argument('-o', '--output', help='Output directory for analysis results', default='api_hash_analysis')
    parser.add_argument('-p', '--pattern', help='File pattern to match', default='*.bin')
    parser.add_argument('-m', '--max-workers', help='Maximum number of parallel processes', type=int, default=os.cpu_count())
    args = parser.parse_args()
    
    # Validate input directory
    if not os.path.exists(args.dir):
        print(f"Error: Directory {args.dir} not found")
        return 1
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Find files to analyze
    file_pattern = os.path.join(args.dir, args.pattern)
    files = glob.glob(file_pattern)
    
    if not files:
        print(f"No files matching {args.pattern} found in {args.dir}")
        return 1
    
    print(f"[+] Found {len(files)} files to analyze")
    print(f"[+] Using maximum {args.max_workers} CPU cores for parallel processing")
    print(f"[+] Results will be saved to {args.output}")
    
    # Process files in parallel for maximum performance
    start_time = time.time()
    summaries = []
    
    with ProcessPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {executor.submit(analyze_file, file_path, args.output): file_path for file_path in files}
        
        for future in tqdm(futures, desc="Processing files", unit="file"):
            try:
                result = future.result()
                summaries.append(result)
            except Exception as e:
                print(f"Error processing {futures[future]}: {e}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Generate overall summary
    total_hash_algorithms = sum(s["hash_algorithms_count"] for s in summaries)
    total_api_hashes = sum(s["api_hashes_count"] for s in summaries)
    
    print("\n[+] Analysis Complete")
    print(f"Total files analyzed: {len(files)}")
    print(f"Total hash algorithms detected: {total_hash_algorithms}")
    print(f"Total API hashes identified: {total_api_hashes}")
    print(f"Total processing time: {total_time:.2f} seconds")
    
    # Save overall summary
    summary_path = os.path.join(args.output, "hash_analysis_summary.json")
    with open(summary_path, 'w') as f:
        summary_data = {
            "total_files": len(files),
            "total_hash_algorithms": total_hash_algorithms,
            "total_api_hashes": total_api_hashes,
            "total_time": total_time,
            "file_summaries": summaries
        }
        json.dump(summary_data, f, indent=2)
    
    print(f"Summary saved to {summary_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
