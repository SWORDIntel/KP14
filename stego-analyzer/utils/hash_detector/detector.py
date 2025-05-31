"""
Hash Algorithm Detector Module
----------------------------
Main detection logic for identifying API hashing algorithms
in malware binaries using OpenVINO acceleration.
"""

import os
import json
import time
import binascii
import struct
from tqdm import tqdm
import concurrent.futures
# import numpy as np # Not used directly in this file
from collections import defaultdict

from stego_analyzer.utils.hash_detector.accelerator import OpenVINOAccelerator
from stego_analyzer.utils.hash_detector.patterns import HashPatterns
from stego_analyzer.utils.hash_detector.algorithms import HashAlgorithms

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class HashDetector:
    """
    Main detector for API hashing algorithms in malware binaries
    
    This class combines pattern detection, algorithm identification,
    and API hash lookup to provide a comprehensive analysis of
    API resolution techniques used in malware.
    """
    
    def __init__(self):
        """Initialize the hash detector"""
        self.accelerator = OpenVINOAccelerator()
        self.api_hash_db = None
    
    def detect_hash_algorithms(self, binary_data):
        """
        Detect potential API hashing algorithms in binary data
        
        Args:
            binary_data: Binary data to analyze
            
        Returns:
            List of detected hash algorithm candidates
        """
        # Get all hash-related patterns
        all_patterns = HashPatterns.get_all_patterns()
        
        # Find pattern matches using OpenVINO acceleration
        print("Searching for hash algorithm patterns...")
        matches = self.accelerator.accelerated_pattern_search(binary_data, all_patterns)
        print("Found {} potential hash pattern matches".format(len(matches)))
        
        # Group matches by proximity to identify potential hash algorithms
        print("Grouping pattern matches by proximity...")
        grouped_matches = self.accelerator.group_matches_by_proximity(matches, max_distance=50)
        print("Identified {} potential hash algorithm groups".format(len(grouped_matches)))
        
        # Analyze each group of matches
        hash_candidates = []
        for group in tqdm(grouped_matches, desc="Analyzing pattern groups"):
            # Need at least 3 patterns to identify a hash algorithm
            if len(group) < 3:
                continue
                
            # Extract pattern descriptions
            pattern_descriptions = [m["description"] for m in group]
            
            # Detect algorithm from patterns
            algorithm_info = HashAlgorithms.detect_algorithm_from_pattern(pattern_descriptions)
            
            # Only include if confidence is reasonable
            if algorithm_info['confidence'] >= 0.5:
                # Calculate boundaries of the potential hash function
                start_offset = min(m["offset"] for m in group)
                end_offset = max(m["offset"] + m["pattern_length"] for m in group)
                
                hash_candidates.append({
                    'offset': start_offset,
                    'size': end_offset - start_offset,
                    'patterns': pattern_descriptions,
                    'algorithm': algorithm_info['algorithm'],
                    'confidence': algorithm_info['confidence'],
                    'match_count': len(group)
                })
        
        # Sort by confidence
        hash_candidates.sort(key=lambda x: x['confidence'], reverse=True)
        
        return hash_candidates
    
    def identify_api_hashes(self, binary_data, hash_algorithms):
        """
        Identify potential API hash values in the binary
        
        Args:
            binary_data: Binary data to analyze
            hash_algorithms: List of detected hash algorithms
            
        Returns:
            List of identified API hashes
        """
        if not hash_algorithms:
            return []
            
        # Initialize API hash database if needed
        if self.api_hash_db is None:
            print("Creating API hash database...")
            self.api_hash_db = HashAlgorithms.create_api_hash_database()
            print("API hash database created with {} entries".format(len(self.api_hash_db)))
        
        # Extract potential hash values (32-bit constants) following comparison instructions
        print("Searching for potential API hash values...")
        potential_hashes = []
        
        # Process each hash algorithm in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for algo in hash_algorithms:
                futures.append(executor.submit(
                    self._find_potential_hashes, 
                    binary_data, 
                    algo
                ))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    potential_hashes.extend(result)
                except Exception as e:
                    print("Error finding potential hashes: {}".format(e))
        
        # Identify API names from hash values
        print("Looking up API names from hash values...")
        identified_apis = []
        
        for hash_entry in tqdm(potential_hashes, desc="Identifying APIs"):
            # Look up API names
            algorithm = hash_entry['algorithm']
            hash_value = hash_entry['value']
            
            api_matches = HashAlgorithms.reverse_lookup_hash(
                hash_value, 
                algorithm, 
                self.api_hash_db
            )
            
            if api_matches:
                hash_entry['api_matches'] = api_matches
                identified_apis.append(hash_entry)
        
        return identified_apis
    
    def _find_potential_hashes(self, binary_data, algorithm_info):
        """
        Find potential hash values for a specific algorithm
        
        Args:
            binary_data: Binary data to analyze
            algorithm_info: Information about the hash algorithm
            
        Returns:
            List of potential hash values
        """
        algorithm_name = algorithm_info['algorithm']
        region_start = algorithm_info['offset']
        region_size = algorithm_info['size']
        region_end = min(region_start + region_size + 100, len(binary_data))  # Look a bit beyond
        
        # Focus on the region containing the hash algorithm plus a bit extra
        region_data = binary_data[region_start:region_end]
        
        # Look for comparison instructions (CMP, TEST) followed by 32-bit values
        potential_hashes = []
        
        # Common comparison instructions
        cmp_instructions = [
            b"\x3D",           # CMP EAX, imm32
            b"\x81\xF9",       # CMP ECX, imm32
            b"\x81\xFA",       # CMP EDX, imm32
            b"\x81\xFB",       # CMP EBX, imm32
            b"\x81\xFE",       # CMP ESI, imm32
            b"\x81\xFF",       # CMP EDI, imm32
        ]
        
        for instr in cmp_instructions:
            offset = 0
            while True:
                offset = region_data.find(instr, offset)
                if offset == -1:
                    break
                
                # Extract the 32-bit value that follows
                value_offset = offset + len(instr)
                if value_offset + 4 <= len(region_data):
                    hash_value = struct.unpack("<I", region_data[value_offset:value_offset+4])[0]
                    
                    potential_hashes.append({
                        'offset': region_start + offset,
                        'value': hash_value,
                        'algorithm': algorithm_name,
                        'confidence': algorithm_info['confidence'],
                        'instruction': binascii.hexlify(instr).decode()
                    })
                
                offset += 1
        
        return potential_hashes
    
    def analyze_binary(self, file_path, output_dir=None):
        """
        Analyze a binary file for API hashing algorithms
        
        Args:
            file_path: Path to the binary file
            output_dir: Directory to save output files (optional)
            
        Returns:
            Dict with analysis results
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found")
            return None
        
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print(f"Analyzing file: {file_path}")
        file_name = os.path.basename(file_path)
        
        # Read binary data
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Record start time
        start_time = time.time()
        
        # Detect hash algorithms
        hash_algorithms = self.detect_hash_algorithms(data)
        print("Found {} potential API hashing algorithms".format(len(hash_algorithms)))
        
        # Identify API hashes
        api_hashes = []
        if hash_algorithms:
            api_hashes = self.identify_api_hashes(data, hash_algorithms)
            print("Identified {} potential API hashes".format(len(api_hashes)))
        
        # Record end time
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Generate results
        results = {
            "file_path": file_path,
            "file_size": len(data),
            "hash_algorithms": hash_algorithms,
            "api_hashes": api_hashes,
            "processing_time": processing_time,
            "summary": {
                "total_hash_algorithms": len(hash_algorithms),
                "total_api_hashes": len(api_hashes)
            }
        }
        
        # Save results if output directory specified
        if output_dir:
            output_path = os.path.join(output_dir, file_name + "_hash_analysis.json")
            with open(output_path, 'w') as f:
                # Convert binary data to hex strings for JSON serialization
                serializable_results = self._prepare_for_serialization(results)
                json.dump(serializable_results, f, indent=2)
            
            print("Analysis results saved to: {}".format(output_path))
            
            # Generate human-readable report
            report_path = os.path.join(output_dir, file_name + "_hash_analysis_report.txt")
            self._generate_report(results, report_path)
            print("Human-readable report saved to: {}".format(report_path))
        
        return results
    
    def _prepare_for_serialization(self, obj):
        """Prepare results for JSON serialization by converting binary data to hex"""
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode()
        elif isinstance(obj, dict):
            return {k: self._prepare_for_serialization(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._prepare_for_serialization(item) for item in obj]
        elif isinstance(obj, tuple): # Added tuple for completeness
            return tuple(self._prepare_for_serialization(item) for item in obj)
        else:
            return obj
    
    def _generate_report(self, results, output_path):
        """
        Generate a human-readable report of the hash algorithm analysis
        
        Args:
            results: Analysis results
            output_path: Path to save the report
        """
        with open(output_path, 'w') as f:
            f.write("KEYPLUG API Hash Algorithm Analysis Report\n")
            f.write("=========================================\n\n")
            
            f.write("File: {}\n".format(results['file_path']))
            f.write("Size: {} bytes\n".format(results['file_size']))
            f.write("Processing Time: {:.2f} seconds\n\n".format(results['processing_time']))
            
            f.write("Summary\n")
            f.write("-------\n")
            summary = results['summary']
            f.write("Total API hashing algorithms found: {}\n".format(summary['total_hash_algorithms']))
            f.write("Total API hashes identified: {}\n\n".format(summary['total_api_hashes']))
            
            if results['hash_algorithms']:
                f.write("Hash Algorithms Detected\n")
                f.write("----------------------\n")
                for i, algo in enumerate(results['hash_algorithms']):
                    f.write("\n[{}] Algorithm at offset 0x{:x}\n".format(i+1, algo['offset']))
                    f.write("    Type: {}\n".format(algo['algorithm']))
                    f.write("    Confidence: {:.2f}\n".format(algo['confidence']))
                    f.write("    Size: {} bytes\n".format(algo['size']))
                    f.write("    Patterns:\n")
                    for pattern in algo['patterns'][:5]:  # Limit to 5 patterns
                        f.write("      - {}\n".format(pattern))
                    if len(algo['patterns']) > 5:
                        f.write("      - (and {} more patterns)\n".format(len(algo['patterns'])-5))
            else:
                f.write("No API hashing algorithms detected.\n\n")
            
            if results['api_hashes']:
                f.write("\nAPI Hashes Identified\n")
                f.write("--------------------\n")
                for i, hash_entry in enumerate(results['api_hashes']):
                    f.write("\n[{}] Hash at offset 0x{:x}\n".format(i+1, hash_entry['offset']))
                    f.write("    Value: 0x{:08x}\n".format(hash_entry['value']))
                    f.write("    Algorithm: {}\n".format(hash_entry['algorithm']))
                    if 'api_matches' in hash_entry:
                        f.write("    Potential APIs:\n")
                        for api in hash_entry['api_matches']:
                            f.write("      - {}\n".format(api))
                    else:
                        f.write("    No API matches found.\n")
            else:
                f.write("\nNo API hashes identified.\n")
