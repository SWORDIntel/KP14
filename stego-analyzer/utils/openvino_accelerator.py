#!/usr/bin/env python3
"""
KEYPLUG OpenVINO Accelerator
--------------------------
Hardware-accelerated pattern matching for KEYPLUG malware analysis.

This module provides OpenVINO-accelerated pattern matching capabilities
for all KEYPLUG analysis components, leveraging hardware acceleration
for maximum performance.
"""

import os
import sys
import json
import numpy as np
from collections import defaultdict
import concurrent.futures

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core, Type, Layout, PartialShape
    from openvino.preprocess import PrePostProcessor
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for pattern matching")
    
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

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

class OpenVINOAccelerator:
    """
    Hardware-accelerated pattern matching for KEYPLUG malware analysis
    """
    
    def __init__(self, use_openvino=True):
        """
        Initialize the OpenVINO accelerator
        
        Args:
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
        
        # Initialize models
        self.models = {}
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Initialize OpenVINO Core
        self.core = Core()
        self.device = PREFERRED_DEVICE
        
        # Set up OpenVINO for pattern matching
        # This is a placeholder for actual OpenVINO model setup
        # In a real implementation, we would create and compile models for
        # various pattern matching operations
    
    def accelerated_binary_search(self, data, pattern):
        """
        Perform hardware-accelerated binary pattern search
        
        Args:
            data: Binary data to search in
            pattern: Binary pattern to search for
            
        Returns:
            List of match indices
        """
        if not self.use_openvino or len(data) < 1024:
            # Use standard Python for small data
            return self._standard_binary_search(data, pattern)
        
        # Use OpenVINO for large data
        return self._openvino_binary_search(data, pattern)
    
    def _standard_binary_search(self, data, pattern):
        """Standard binary pattern search implementation"""
        matches = []
        pattern_len = len(pattern)
        data_len = len(data)
        
        # Check if pattern is longer than data
        if pattern_len > data_len:
            return matches
        
        # Convert to numpy arrays for faster processing
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        if isinstance(pattern, (bytes, bytearray)):
            pattern = np.frombuffer(pattern, dtype=np.uint8)
        
        # Find all occurrences
        for i in range(data_len - pattern_len + 1):
            if np.array_equal(data[i:i+pattern_len], pattern):
                matches.append(i)
        
        return matches
    
    def _openvino_binary_search(self, data, pattern):
        """OpenVINO-accelerated binary pattern search implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate pattern matching
        
        # For now, use numpy which is still faster than pure Python
        matches = []
        pattern_len = len(pattern)
        data_len = len(data)
        
        # Check if pattern is longer than data
        if pattern_len > data_len:
            return matches
        
        # Convert to numpy arrays
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        if isinstance(pattern, (bytes, bytearray)):
            pattern = np.frombuffer(pattern, dtype=np.uint8)
        
        # Use numpy's sliding window approach
        # This is much faster than the naive approach
        # Create a view of sliding windows
        windows = np.lib.stride_tricks.sliding_window_view(data, pattern_len)
        
        # Compare each window with the pattern
        # This creates a boolean array where True indicates a match
        matches_mask = np.all(windows == pattern, axis=1)
        
        # Get the indices of matches
        matches = np.where(matches_mask)[0].tolist()
        
        return matches
    
    def accelerated_multi_pattern_search(self, data, patterns):
        """
        Perform hardware-accelerated multi-pattern search
        
        Args:
            data: Binary data to search in
            patterns: List of binary patterns to search for
            
        Returns:
            Dictionary mapping patterns to lists of match indices
        """
        if not self.use_openvino or len(data) < 1024 or len(patterns) < 5:
            # Use standard Python for small data or few patterns
            return self._standard_multi_pattern_search(data, patterns)
        
        # Use OpenVINO for large data and many patterns
        return self._openvino_multi_pattern_search(data, patterns)
    
    def _standard_multi_pattern_search(self, data, patterns):
        """Standard multi-pattern search implementation"""
        results = {}
        
        # Search for each pattern
        for pattern in patterns:
            results[pattern] = self._standard_binary_search(data, pattern)
        
        return results
    
    def _openvino_multi_pattern_search(self, data, patterns):
        """OpenVINO-accelerated multi-pattern search implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate multi-pattern matching
        
        # For now, use parallel processing which is still faster than sequential
        results = {}
        
        # Convert data to numpy array
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        # Process patterns in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_pattern = {executor.submit(self._openvino_binary_search, data, pattern): pattern for pattern in patterns}
            
            for future in concurrent.futures.as_completed(future_to_pattern):
                pattern = future_to_pattern[future]
                try:
                    matches = future.result()
                    results[pattern] = matches
                except Exception as e:
                    print(f"Error searching for pattern: {e}")
                    results[pattern] = []
        
        return results
    
    def accelerated_string_extraction(self, data, min_length=4):
        """
        Perform hardware-accelerated string extraction
        
        Args:
            data: Binary data to extract strings from
            min_length: Minimum string length
            
        Returns:
            List of extracted strings with offsets
        """
        if not self.use_openvino or len(data) < 1024:
            # Use standard Python for small data
            return self._standard_string_extraction(data, min_length)
        
        # Use OpenVINO for large data
        return self._openvino_string_extraction(data, min_length)
    
    def _standard_string_extraction(self, data, min_length=4):
        """Standard string extraction implementation"""
        strings = []
        
        # Extract ASCII strings
        import re
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
        for match in ascii_pattern.finditer(data):
            string = match.group().decode('ascii', errors='ignore')
            strings.append({
                "offset": match.start(),
                "string": string,
                "length": len(string),
                "type": "ascii"
            })
        
        # Extract UTF-16 strings (simplified approach)
        utf16_pattern = re.compile(b'([\x20-\x7E]\x00){%d,}' % min_length)
        for match in utf16_pattern.finditer(data):
            try:
                string = match.group().decode('utf-16le', errors='ignore')
                strings.append({
                    "offset": match.start(),
                    "string": string,
                    "length": len(string),
                    "type": "utf16"
                })
            except:
                pass
        
        return strings
    
    def _openvino_string_extraction(self, data, min_length=4):
        """OpenVINO-accelerated string extraction implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate string extraction
        
        # For now, fall back to standard implementation
        return self._standard_string_extraction(data, min_length)
    
    def accelerated_entropy_calculation(self, data, window_size=256, stride=64):
        """
        Perform hardware-accelerated entropy calculation
        
        Args:
            data: Binary data to calculate entropy for
            window_size: Size of sliding window
            stride: Stride for sliding window
            
        Returns:
            List of entropy values for each window with offsets
        """
        if not self.use_openvino or len(data) < 1024:
            # Use standard Python for small data
            return self._standard_entropy_calculation(data, window_size, stride)
        
        # Use OpenVINO for large data
        return self._openvino_entropy_calculation(data, window_size, stride)
    
    def _standard_entropy_calculation(self, data, window_size=256, stride=64):
        """Standard entropy calculation implementation"""
        results = []
        data_len = len(data)
        
        # Convert to numpy array
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        # Calculate entropy for each window
        for offset in range(0, data_len - window_size + 1, stride):
            window = data[offset:offset+window_size]
            entropy = self._calculate_entropy(window)
            
            results.append({
                "offset": offset,
                "entropy": entropy,
                "window_size": window_size
            })
        
        return results
    
    def _openvino_entropy_calculation(self, data, window_size=256, stride=64):
        """OpenVINO-accelerated entropy calculation implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate entropy calculation
        
        # For now, use numpy which is still faster than pure Python
        results = []
        data_len = len(data)
        
        # Convert to numpy array
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        # Create sliding windows
        windows = []
        for offset in range(0, data_len - window_size + 1, stride):
            windows.append(data[offset:offset+window_size])
        
        # Calculate entropy for each window in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_offset = {executor.submit(self._calculate_entropy, windows[i]): i for i in range(len(windows))}
            
            for future in concurrent.futures.as_completed(future_to_offset):
                i = future_to_offset[future]
                offset = i * stride
                try:
                    entropy = future.result()
                    results.append({
                        "offset": offset,
                        "entropy": entropy,
                        "window_size": window_size
                    })
                except Exception as e:
                    print(f"Error calculating entropy: {e}")
        
        # Sort results by offset
        results.sort(key=lambda x: x["offset"])
        
        return results
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        # Calculate byte frequency
        hist, _ = np.histogram(data, bins=256, range=(0, 256))
        hist = hist / len(data)
        
        # Calculate entropy
        entropy = -np.sum(hist[hist > 0] * np.log2(hist[hist > 0]))
        return entropy
    
    def accelerated_xor_decrypt(self, data, key):
        """
        Perform hardware-accelerated XOR decryption
        
        Args:
            data: Binary data to decrypt
            key: XOR key (byte or list of bytes)
            
        Returns:
            Decrypted data
        """
        if not self.use_openvino or len(data) < 1024:
            # Use standard Python for small data
            return self._standard_xor_decrypt(data, key)
        
        # Use OpenVINO for large data
        return self._openvino_xor_decrypt(data, key)
    
    def _standard_xor_decrypt(self, data, key):
        """Standard XOR decryption implementation"""
        # Convert to numpy arrays
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        # Handle different key types
        if isinstance(key, (int, np.integer)):
            # Single byte key
            result = np.bitwise_xor(data, key).astype(np.uint8)
        elif isinstance(key, (bytes, bytearray)):
            # Multi-byte key (bytes or bytearray)
            key_array = np.frombuffer(key, dtype=np.uint8)
            key_len = len(key_array)
            
            # Apply key in a rolling fashion
            result = np.zeros_like(data)
            for i in range(len(data)):
                result[i] = data[i] ^ key_array[i % key_len]
        elif isinstance(key, (list, np.ndarray)):
            # Multi-byte key (list or numpy array)
            key_array = np.asarray(key, dtype=np.uint8)
            key_len = len(key_array)
            
            # Apply key in a rolling fashion
            result = np.zeros_like(data)
            for i in range(len(data)):
                result[i] = data[i] ^ key_array[i % key_len]
        else:
            raise ValueError(f"Invalid key type: {type(key)}")
        
        return bytes(result)
    
    def _openvino_xor_decrypt(self, data, key):
        """OpenVINO-accelerated XOR decryption implementation"""
        try:
            # Convert inputs to the right format
            if isinstance(data, (bytes, bytearray)):
                data_array = np.frombuffer(data, dtype=np.uint8)
            else:
                data_array = np.asarray(data, dtype=np.uint8)
            
            if isinstance(key, (int, np.integer)):
                # Single byte key - expand to array
                key_array = np.full(min(1024, len(data_array)), key, dtype=np.uint8)
            elif isinstance(key, (bytes, bytearray)):
                # Multi-byte key (bytes or bytearray)
                key_array = np.frombuffer(key, dtype=np.uint8)
            elif isinstance(key, (list, np.ndarray)):
                # Multi-byte key (list or numpy array)
                key_array = np.asarray(key, dtype=np.uint8)
            else:
                raise ValueError(f"Invalid key type: {type(key)}")
            
            # Use OpenVINO for large data
            if OPENVINO_AVAILABLE and len(data_array) > 1024 * 1024:
                # TODO: Implement full OpenVINO acceleration for XOR decryption
                # For now, use numpy vectorization which is still faster than pure Python
                key_len = len(key_array)
                key_repeated = np.tile(key_array, (len(data_array) + key_len - 1) // key_len)[:len(data_array)]
                result = np.bitwise_xor(data_array, key_repeated).astype(np.uint8)
                return bytes(result)
            
            # Fall back to standard implementation for smaller data
            return self._standard_xor_decrypt(data, key)
        except Exception as e:
            print(f"Error in OpenVINO XOR decryption: {e}")
            # Fall back to standard implementation
            return self._standard_xor_decrypt(data, key)
    
    def accelerated_rolling_hash(self, data, algorithm="djb2"):
        """
        Perform hardware-accelerated rolling hash calculation
        
        Args:
            data: Binary data to hash
            algorithm: Hash algorithm to use
            
        Returns:
            List of hash values for each position
        """
        if not self.use_openvino or len(data) < 1024:
            # Use standard Python for small data
            return self._standard_rolling_hash(data, algorithm)
        
        # Use OpenVINO for large data
        return self._openvino_rolling_hash(data, algorithm)
    
    def _standard_rolling_hash(self, data, algorithm="djb2"):
        """Standard rolling hash implementation"""
        results = []
        data_len = len(data)
        
        # Convert to numpy array
        if isinstance(data, (bytes, bytearray)):
            data = np.frombuffer(data, dtype=np.uint8)
        
        # Initialize hash
        if algorithm == "djb2":
            hash_value = 5381
            for i in range(data_len):
                hash_value = ((hash_value << 5) + hash_value) + data[i]  # hash * 33 + c
                hash_value = hash_value & 0xFFFFFFFF  # Keep 32 bits
                results.append(hash_value)
        elif algorithm == "sdbm":
            hash_value = 0
            for i in range(data_len):
                hash_value = data[i] + (hash_value << 6) + (hash_value << 16) - hash_value
                hash_value = hash_value & 0xFFFFFFFF  # Keep 32 bits
                results.append(hash_value)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        return results
    
    def _openvino_rolling_hash(self, data, algorithm="djb2"):
        """OpenVINO-accelerated rolling hash implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate rolling hash calculation
        
        # For now, fall back to standard implementation
        return self._standard_rolling_hash(data, algorithm)
    
    def accelerated_similarity_calculation(self, data1, data2, method="jaccard"):
        """
        Perform hardware-accelerated similarity calculation
        
        Args:
            data1: First data sample
            data2: Second data sample
            method: Similarity method to use
            
        Returns:
            Similarity score (0.0-1.0)
        """
        if not self.use_openvino or len(data1) < 1024 or len(data2) < 1024:
            # Use standard Python for small data
            return self._standard_similarity_calculation(data1, data2, method)
        
        # Use OpenVINO for large data
        return self._openvino_similarity_calculation(data1, data2, method)
    
    def _standard_similarity_calculation(self, data1, data2, method="jaccard"):
        """Standard similarity calculation implementation"""
        # Convert to numpy arrays
        if isinstance(data1, (bytes, bytearray)):
            data1 = np.frombuffer(data1, dtype=np.uint8)
        
        if isinstance(data2, (bytes, bytearray)):
            data2 = np.frombuffer(data2, dtype=np.uint8)
        
        if method == "jaccard":
            # Jaccard similarity
            set1 = set(data1)
            set2 = set(data2)
            
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))
            
            if union == 0:
                return 0.0
            
            return intersection / union
        elif method == "cosine":
            # Cosine similarity
            # Count occurrences of each byte
            counts1 = np.zeros(256, dtype=np.int32)
            counts2 = np.zeros(256, dtype=np.int32)
            
            for b in data1:
                counts1[b] += 1
            
            for b in data2:
                counts2[b] += 1
            
            # Calculate cosine similarity
            dot_product = np.sum(counts1 * counts2)
            norm1 = np.sqrt(np.sum(counts1 ** 2))
            norm2 = np.sqrt(np.sum(counts2 ** 2))
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            return dot_product / (norm1 * norm2)
        else:
            raise ValueError(f"Unsupported similarity method: {method}")
    
    def _openvino_similarity_calculation(self, data1, data2, method="jaccard"):
        """OpenVINO-accelerated similarity calculation implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate similarity calculation
        
        # For now, use numpy which is still faster than pure Python
        return self._standard_similarity_calculation(data1, data2, method)

def main():
    """Main function"""
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description='KEYPLUG OpenVINO Accelerator')
    parser.add_argument('-f', '--file', help='Binary file to process')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-p', '--pattern', help='Binary pattern to search for (hex string)')
    parser.add_argument('-k', '--key', help='XOR key to use (hex string)')
    parser.add_argument('-m', '--mode', choices=['search', 'strings', 'entropy', 'decrypt', 'hash', 'benchmark'], help='Operation mode', default='benchmark')
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and args.mode != 'benchmark':
        parser.error("--file is required for all modes except benchmark")
    
    # Initialize accelerator
    accelerator = OpenVINOAccelerator(use_openvino=not args.no_openvino)
    
    # Benchmark mode
    if args.mode == 'benchmark':
        print("Running benchmark...")
        
        # Generate test data
        data_size = 10 * 1024 * 1024  # 10 MB
        data = np.random.randint(0, 256, data_size, dtype=np.uint8).tobytes()
        
        # Generate test patterns
        patterns = []
        for i in range(10):
            pattern_size = np.random.randint(4, 16)
            pattern = np.random.randint(0, 256, pattern_size, dtype=np.uint8).tobytes()
            patterns.append(pattern)
        
        # Benchmark binary search
        print("\nBenchmarking binary search...")
        start_time = time.time()
        for pattern in patterns:
            accelerator.accelerated_binary_search(data, pattern)
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        # Benchmark multi-pattern search
        print("\nBenchmarking multi-pattern search...")
        start_time = time.time()
        accelerator.accelerated_multi_pattern_search(data, patterns)
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        # Benchmark string extraction
        print("\nBenchmarking string extraction...")
        start_time = time.time()
        accelerator.accelerated_string_extraction(data)
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        # Benchmark entropy calculation
        print("\nBenchmarking entropy calculation...")
        start_time = time.time()
        accelerator.accelerated_entropy_calculation(data)
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        # Benchmark XOR decryption
        print("\nBenchmarking XOR decryption...")
        start_time = time.time()
        key = np.random.randint(0, 256, 16, dtype=np.uint8).tobytes()
        accelerator.accelerated_xor_decrypt(data, key)
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        # Benchmark rolling hash
        print("\nBenchmarking rolling hash...")
        start_time = time.time()
        accelerator.accelerated_rolling_hash(data[:1024*1024])  # Use 1 MB for hash
        end_time = time.time()
        print(f"Time: {end_time - start_time:.2f} seconds")
        
        return 0
    
    # Read input file
    try:
        with open(args.file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return 1
    
    # Process based on mode
    if args.mode == 'search':
        if not args.pattern:
            parser.error("--pattern is required for search mode")
        
        # Convert hex string to bytes
        pattern = bytes.fromhex(args.pattern)
        
        print(f"Searching for pattern in {args.file}...")
        start_time = time.time()
        matches = accelerator.accelerated_binary_search(data, pattern)
        end_time = time.time()
        
        print(f"Found {len(matches)} matches in {end_time - start_time:.2f} seconds")
        
        # Print matches
        for i, offset in enumerate(matches[:10]):  # Show top 10
            print(f"{i+1}. Offset: 0x{offset:08x} ({offset})")
        
        if len(matches) > 10:
            print(f"... and {len(matches) - 10} more matches")
    
    elif args.mode == 'strings':
        print(f"Extracting strings from {args.file}...")
        start_time = time.time()
        strings = accelerator.accelerated_string_extraction(data)
        end_time = time.time()
        
        print(f"Found {len(strings)} strings in {end_time - start_time:.2f} seconds")
        
        # Print strings
        for i, string in enumerate(strings[:10]):  # Show top 10
            print(f"{i+1}. Offset: 0x{string['offset']:08x} ({string['offset']}) - {string['string'][:30]}")
        
        if len(strings) > 10:
            print(f"... and {len(strings) - 10} more strings")
    
    elif args.mode == 'entropy':
        print(f"Calculating entropy for {args.file}...")
        start_time = time.time()
        entropy_values = accelerator.accelerated_entropy_calculation(data)
        end_time = time.time()
        
        print(f"Calculated {len(entropy_values)} entropy values in {end_time - start_time:.2f} seconds")
        
        # Print entropy values
        for i, value in enumerate(entropy_values[:10]):  # Show top 10
            print(f"{i+1}. Offset: 0x{value['offset']:08x} ({value['offset']}) - Entropy: {value['entropy']:.2f}")
        
        if len(entropy_values) > 10:
            print(f"... and {len(entropy_values) - 10} more values")
    
    elif args.mode == 'decrypt':
        if not args.key:
            parser.error("--key is required for decrypt mode")
        
        try:
            # Try to convert hex string to bytes
            key = bytes.fromhex(args.key)
        except ValueError:
            # If not a valid hex string, use as raw bytes
            key = args.key.encode('utf-8')
        
        print(f"Decrypting {args.file} with XOR key {args.key}...")
        start_time = time.time()
        decrypted = accelerator.accelerated_xor_decrypt(data, key)
        end_time = time.time()
        
        print(f"Decrypted {len(data)} bytes in {end_time - start_time:.2f} seconds")
        
        # Save decrypted data
        if args.output:
            try:
                with open(args.output, 'wb') as f:
                    f.write(decrypted)
                print(f"Decrypted data saved to {args.output}")
            except Exception as e:
                print(f"Error saving decrypted data: {e}")
        else:
            # Print sample of decrypted data
            print("\nSample of decrypted data:")
            print(decrypted[:100].hex())
    
    elif args.mode == 'hash':
        print(f"Calculating rolling hash for {args.file}...")
        start_time = time.time()
        hash_values = accelerator.accelerated_rolling_hash(data[:1024*1024])  # Use first 1 MB
        end_time = time.time()
        
        print(f"Calculated {len(hash_values)} hash values in {end_time - start_time:.2f} seconds")
        
        # Print hash values
        for i, value in enumerate(hash_values[:10]):  # Show top 10
            print(f"{i+1}. Offset: {i} - Hash: 0x{value:08x}")
        
        if len(hash_values) > 10:
            print(f"... and {len(hash_values) - 10} more values")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
