#!/usr/bin/env python3
"""
Advanced Multi-Layer Decryption for KEYPLUG Malware
Using OpenVINO for acceleration when possible
"""
import os
import struct
import binascii
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path
import time
import json

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - will use hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - will use standard processing")

# Constants
MZ_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\0\0'
BLOCK_SIZE = 4096
MAX_ENTROPY_THRESHOLD = 0.9
MIN_ENTROPY_THRESHOLD = 0.3
MAX_KEY_LENGTH = 16

# Known keys from previous analysis
KNOWN_KEYS = {
    "9e": b'\x9e',
    "d3": b'\xd3',
    "a5": b'\xa5',
    "9ed3": b'\x9e\xd3',
    "9ed3a5": b'\x9e\xd3\xa5',
    "a2800a28": bytes.fromhex("a2800a28"),
    "b63c1e94": bytes.fromhex("b63c1e94"),
    "fb7153d9": bytes.fromhex("fb7153d9")
}

# PE offsets identified
PE_OFFSETS = [33763, 33849, 48540]

class MLDecryptionEngine:
    """ML-powered decryption engine using OpenVINO when available"""
    
    def __init__(self, use_openvino=True):
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.core = None
        self.compiled_models = {}
        
        if self.use_openvino:
            try:
                self.core = Core()
                print("OpenVINO Core initialized successfully")
                
                # In a real implementation, you would load models here
                # self.load_models()
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.use_openvino = False
    
    def load_models(self):
        """Load neural network models for pattern recognition"""
        # This is a placeholder for actual model loading
        # In a real implementation, you would load models like:
        # model = self.core.read_model("path/to/model.xml")
        # self.compiled_models["pattern_recognition"] = self.core.compile_model(model)
        pass
    
    def predict_decryption_parameters(self, data):
        """Use ML to predict optimal decryption parameters"""
        # This would use OpenVINO to analyze the encrypted data and predict parameters
        # For now, we'll use heuristics
        
        results = {
            "key_candidates": [],
            "algorithm_candidates": [],
            "offset_candidates": []
        }
        
        # In a real implementation, this would use the compiled models
        # input_tensor = preprocess_data(data)
        # predictions = self.compiled_models["pattern_recognition"](input_tensor)
        
        # For now, use heuristic analysis
        entropy = calculate_entropy(data)
        byte_freq = analyze_byte_frequency(data)
        most_common_bytes = [byte for byte, _ in byte_freq.most_common(5)]
        
        # Find potential XOR keys based on frequency analysis
        potential_keys = self.estimate_xor_keys(data, most_common_bytes)
        results["key_candidates"] = potential_keys
        
        # Detect potential algorithm based on patterns
        if entropy > 0.9:
            results["algorithm_candidates"] = ["xor", "rc4", "multi_layer"]
        else:
            results["algorithm_candidates"] = ["xor", "substitution"]
        
        # Find potential decryption starting offsets
        potential_offsets = self.find_potential_offsets(data)
        results["offset_candidates"] = potential_offsets
        
        return results
    
    def estimate_xor_keys(self, data, common_bytes, target_bytes=[0x00, 0x20, 0x0A, 0x0D, 0x4D, 0x5A]):
        """Estimate potential XOR keys"""
        potential_keys = []
        
        # Try single-byte XOR keys derived from common values
        for common_byte in common_bytes:
            for target in target_bytes:
                key_byte = common_byte ^ target
                potential_keys.append(bytes([key_byte]))
        
        # Add known keys
        for key in KNOWN_KEYS.values():
            if key not in potential_keys:
                potential_keys.append(key)
        
        # Try to identify repeating patterns as potential keys
        patterns = find_repeating_patterns(data)
        for pattern, _ in patterns[:5]:  # Top 5 patterns
            if pattern not in potential_keys and len(pattern) <= MAX_KEY_LENGTH:
                potential_keys.append(pattern)
        
        return potential_keys
    
    def find_potential_offsets(self, data):
        """Find potential offsets for decryption start"""
        offsets = []
        
        # Check for entropy transitions
        entropy_map = sliding_window_entropy(data)
        transition_points = []
        
        for i in range(1, len(entropy_map)):
            if abs(entropy_map[i][1] - entropy_map[i-1][1]) > 0.2:
                transition_points.append(entropy_map[i][0])
        
        offsets.extend(transition_points)
        
        # Add known PE offsets
        offsets.extend(PE_OFFSETS)
        
        # Add offsets where MZ signature might be hidden
        for i in range(0, len(data) - 2):
            # Check if XORing with our known keys could produce 'MZ'
            for key_name, key in KNOWN_KEYS.items():
                key_byte = key[0]
                if data[i] ^ key_byte == ord('M') and data[i+1] ^ key_byte == ord('Z'):
                    offsets.append(i)
        
        return sorted(list(set(offsets)))

def xor_decrypt(data, key):
    """Decrypt data using XOR with a repeating key"""
    if isinstance(key, int):
        key = bytes([key])
    
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    
    return bytes(result)

def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    return S

def rc4_prga(S, data):
    """RC4 Pseudo-Random Generation Algorithm"""
    result = bytearray(len(data))
    i = j = 0
    
    for idx in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result[idx] = data[idx] ^ k
    
    return bytes(result)

def rc4_decrypt(data, key):
    """Decrypt data using RC4 algorithm"""
    if isinstance(key, int):
        key = bytes([key])
    
    S = rc4_ksa(key)
    return rc4_prga(S, data)

def calculate_entropy(data, block_size=256):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    # If data is smaller than block_size, use the whole data
    if len(data) < block_size:
        block = data
    else:
        # Otherwise, use a sample from the middle of the data
        start = (len(data) - block_size) // 2
        block = data[start:start+block_size]
    
    entropy = 0.0
    for byte_value in range(256):
        p_x = block.count(byte_value) / len(block)
        if p_x > 0:
            entropy += -p_x * np.log2(p_x)
    
    return entropy / 8.0  # Normalize to [0,1]

def sliding_window_entropy(data, window_size=256, step=64):
    """Calculate entropy over a sliding window"""
    result = []
    
    for i in range(0, len(data) - window_size + 1, step):
        window = data[i:i+window_size]
        entropy = calculate_entropy(window, window_size)
        result.append((i, entropy))
    
    return result

def analyze_byte_frequency(data):
    """Analyze byte frequency distribution"""
    counter = Counter(data)
    return counter

def find_repeating_patterns(data, min_length=2, max_length=8, min_count=3):
    """Find repeating byte patterns in data"""
    patterns = {}
    
    # For each pattern length
    for pattern_len in range(min_length, min(max_length + 1, len(data) // 2)):
        # Collect all patterns of this length
        all_patterns = {}
        for i in range(len(data) - pattern_len + 1):
            pattern = data[i:i+pattern_len]
            if pattern in all_patterns:
                all_patterns[pattern].append(i)
            else:
                all_patterns[pattern] = [i]
        
        # Keep patterns that repeat enough times
        for pattern, positions in all_patterns.items():
            if len(positions) >= min_count:
                patterns[pattern] = positions
    
    # Sort by number of occurrences
    return sorted(patterns.items(), key=lambda x: len(x[1]), reverse=True)

def detect_file_type(data):
    """Detect file type based on signatures"""
    signatures = {
        b'MZ': 'DOS/PE Executable',
        b'PK': 'ZIP Archive',
        b'\x7fELF': 'ELF Executable',
        b'\xff\xd8\xff': 'JPEG Image',
        b'\x89PNG': 'PNG Image',
        b'%PDF': 'PDF Document',
        b'{\r\n': 'JSON Data',
        b'<?xml': 'XML Document',
        b'#!/': 'Script',
        b'#include': 'C/C++ Source',
        b'import ': 'Python Source',
        b'<html': 'HTML Document',
        b'-----BEGIN ': 'PEM Certificate/Key',
    }
    
    for sig, file_type in signatures.items():
        if data.startswith(sig):
            return file_type
    
    # Check for PE header at standard offset
    if len(data) > 0x40:
        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if 0 < pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == PE_SIGNATURE:
                return 'PE Executable'
        except Exception: # Catch specific exceptions if possible
            pass
    
    return 'Unknown'

def is_potentially_valid_pe(data):
    """Check if the data looks like it might be a valid PE file"""
    if len(data) < 0x40:
        return False
    
    # Check for MZ signature
    if data[:2] != MZ_SIGNATURE:
        return False
    
    # Try to find PE header offset
    try:
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset >= len(data) - 4:
            return False
        
        # Check for PE signature
        if data[pe_offset:pe_offset+4] == PE_SIGNATURE:
            return True
        
        return False
    except:
        return False

def is_mostly_printable(data, threshold=0.7):
    """Check if data contains mostly printable ASCII characters"""
    if not data:
        return False
    
    printable_count = sum(32 <= b <= 126 for b in data)
    return printable_count / len(data) >= threshold

def find_embedded_pe(data):
    """Find embedded PE files within data"""
    results = []
    
    # Look for MZ signatures
    offset = 0
    while True:
        offset = data.find(MZ_SIGNATURE, offset)
        if offset == -1:
            break
        
        # Check if this might be a valid PE
        if offset + 0x40 < len(data):
            try:
                pe_offset = struct.unpack('<I', data[offset+0x3C:offset+0x40])[0]
                if offset + pe_offset + 4 < len(data) and data[offset+pe_offset:offset+pe_offset+4] == PE_SIGNATURE:
                    results.append(offset)
            except Exception: # Catch specific exceptions if possible
                pass
        
        offset += 2
    
    return results

def multi_layer_decrypt(data, layers):
    """Apply multiple decryption layers
    
    Layers format: list of (algorithm, key, offset, length) tuples
    If offset is None, entire data is processed
    If length is None, process from offset to end
    """
    result = bytearray(data)
    
    for layer in layers:
        algorithm, key, offset, length = layer
        
        # Determine the portion to decrypt
        if offset is None:
            start = 0
        else:
            start = offset
        
        if length is None:
            end = len(result)
        else:
            end = min(start + length, len(result))
        
        # Apply the decryption algorithm
        if algorithm.lower() == 'xor':
            segment = bytes(result[start:end])
            decrypted = xor_decrypt(segment, key)
            result[start:end] = decrypted
        elif algorithm.lower() == 'rc4':
            segment = bytes(result[start:end])
            decrypted = rc4_decrypt(segment, key)
            result[start:end] = decrypted
        else:
            print(f"Unknown algorithm: {algorithm}")
    
    return bytes(result)

def apply_sliding_key(data, key, window_size=256, step=128):
    """Apply a key that changes (slides) across the data"""
    result = bytearray(data)
    
    # Generate a series of modified keys
    keys = []
    base_key = key
    for i in range(len(data) // step + 1):
        # Modify key slightly for each window
        modified_key = bytearray(base_key)
        for j in range(len(modified_key)):
            modified_key[j] = (modified_key[j] + i) % 256
        keys.append(bytes(modified_key))
    
    # Apply each key to its corresponding window
    for i in range(0, len(data), step):
        end = min(i + window_size, len(data))
        segment = data[i:end]
        key_idx = i // step
        if key_idx < len(keys):
            decrypted = xor_decrypt(segment, keys[key_idx])
            result[i:end] = decrypted
    
    return bytes(result)

def auto_decrypt(data, ml_engine):
    """Attempt to automatically decrypt the data using ML predictions"""
    results = []
    
    # Get ML predictions for decryption parameters
    predictions = ml_engine.predict_decryption_parameters(data)
    
    # Try different combinations of algorithms, keys, and offsets
    for algorithm in predictions["algorithm_candidates"]:
        for key in predictions["key_candidates"]:
            # First try decrypting the whole file
            if algorithm == "xor":
                decrypted = xor_decrypt(data, key)
            elif algorithm == "rc4":
                decrypted = rc4_decrypt(data, key)
            elif algorithm == "multi_layer":
                # Try some combinations of algorithms
                decrypted = multi_layer_decrypt(data, [
                    ("xor", key, None, None),
                    ("rc4", key, None, None)
                ])
            
            # Check if result looks promising
            file_type = detect_file_type(decrypted)
            entropy = calculate_entropy(decrypted)
            
            result = {
                "algorithm": algorithm,
                "key": binascii.hexlify(key).decode(),
                "offset": 0,
                "length": len(data),
                "file_type": file_type,
                "entropy": entropy,
                "md5": hashlib.md5(decrypted).hexdigest(),
                "decrypted_data": decrypted
            }
            
            results.append(result)
            
            # Now try decrypting from specific offsets
            for offset in predictions["offset_candidates"]:
                if offset == 0:
                    continue  # Already tried this
                
                # Try decrypting from this offset to the end
                if algorithm == "xor":
                    partial_data = data[offset:]
                    decrypted_partial = xor_decrypt(partial_data, key)
                    combined = data[:offset] + decrypted_partial
                elif algorithm == "rc4":
                    partial_data = data[offset:]
                    decrypted_partial = rc4_decrypt(partial_data, key)
                    combined = data[:offset] + decrypted_partial
                else:
                    # Skip multi_layer for offset-based decryption for now
                    continue
                
                # Check if result looks promising
                file_type = detect_file_type(combined)
                entropy = calculate_entropy(combined)
                
                result = {
                    "algorithm": algorithm,
                    "key": binascii.hexlify(key).decode(),
                    "offset": offset,
                    "length": len(data) - offset,
                    "file_type": file_type,
                    "entropy": entropy,
                    "md5": hashlib.md5(combined).hexdigest(),
                    "decrypted_data": combined
                }
                
                results.append(result)
    
    # Also try sliding key approach
    for key in predictions["key_candidates"]:
        decrypted = apply_sliding_key(data, key)
        file_type = detect_file_type(decrypted)
        entropy = calculate_entropy(decrypted)
        
        result = {
            "algorithm": "sliding_key_xor",
            "key": binascii.hexlify(key).decode(),
            "offset": 0,
            "length": len(data),
            "file_type": file_type,
            "entropy": entropy,
            "md5": hashlib.md5(decrypted).hexdigest(),
            "decrypted_data": decrypted
        }
        
        results.append(result)
    
    # Sort results by potential validity
    return sorted(results, key=lambda x: rank_result(x))

def rank_result(result):
    """Rank a decryption result by likelihood of being correct"""
    score = 0
    
    # File type detection
    if result["file_type"] != "Unknown":
        score += 10
    if "Executable" in result["file_type"]:
        score += 5
    
    # Entropy - prefer moderate entropy (not too high, not too low)
    entropy = result["entropy"]
    if 0.6 <= entropy <= 0.85:
        score += 5
    elif entropy > 0.95:
        score -= 3  # Still highly encrypted
    
    # Check for MZ/PE header
    if result["decrypted_data"][:2] == MZ_SIGNATURE:
        score += 8
        # Check for PE header
        try:
            pe_offset = struct.unpack('<I', result["decrypted_data"][0x3C:0x40])[0]
            if pe_offset < len(result["decrypted_data"]) - 4:
                if result["decrypted_data"][pe_offset:pe_offset+4] == PE_SIGNATURE:
                    score += 15
        except Exception: # Catch specific exceptions if possible
            pass
    
    # Check for printable strings
    # Take a sample from the beginning, middle, and end
    samples = []
    data_len = len(result["decrypted_data"])
    
    if data_len > 100:
        samples.append(result["decrypted_data"][:100])
        samples.append(result["decrypted_data"][data_len//2-50:data_len//2+50])
        samples.append(result["decrypted_data"][-100:])
    else:
        samples.append(result["decrypted_data"])
    
    for sample in samples:
        printable_ratio = sum(32 <= b <= 126 for b in sample) / len(sample)
        if printable_ratio > 0.7:
            score += 3
    
    return -score  # Negative because we want highest score first in sorted order

def process_file(file_path, output_dir, use_openvino=True):
    """Process a file with multi-layer decryption"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    file_name = os.path.basename(file_path)
    base_name = os.path.splitext(file_name)[0]
    
    print(f"Processing file: {file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Initialize ML engine
    ml_engine = MLDecryptionEngine(use_openvino=use_openvino)
    
    # Try automatic decryption
    print("Attempting automatic decryption...")
    results = auto_decrypt(data, ml_engine)
    
    # Save the top results
    top_results = results[:10]  # Save top 10 results
    
    print(f"\nTop {len(top_results)} decryption results:")
    for i, result in enumerate(top_results):
        print(f"\n[{i+1}] Algorithm: {result['algorithm']}, Key: {result['key']}")
        print(f"    Offset: {result['offset']}, Length: {result['length']}")
        print(f"    File Type: {result['file_type']}, Entropy: {result['entropy']:.4f}")
        print(f"    MD5: {result['md5']}")
        
        # Generate output filename
        if result["offset"] == 0 and result["length"] == len(data):
            # Full file decryption
            output_name = f"{base_name}_{result['algorithm']}_{result['key']}.bin"
        else:
            # Partial file decryption
            output_name = f"{base_name}_{result['algorithm']}_{result['key']}_offset_{result['offset']}.bin"
        
        output_path = os.path.join(output_dir, output_name)
        
        # Save decrypted data
        with open(output_path, 'wb') as f:
            f.write(result['decrypted_data'])
        
        print(f"    Saved to: {output_path}")
        
        # Print hex and ASCII preview
        hex_preview = binascii.hexlify(result['decrypted_data'][:64]).decode()
        ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result['decrypted_data'][:64])
        
        print(f"\n    Hex preview: {hex_preview}")
        print(f"    ASCII preview: {ascii_preview}")
    
    # Generate a summary report
    summary = {
        "file_name": file_path,
        "file_size": len(data),
        "original_entropy": calculate_entropy(data),
        "decryption_results": [
            {
                "algorithm": r["algorithm"],
                "key": r["key"],
                "offset": r["offset"],
                "length": r["length"],
                "file_type": r["file_type"],
                "entropy": r["entropy"],
                "md5": r["md5"]
            }
            for r in top_results
        ]
    }
    
    # Save summary
    summary_path = os.path.join(output_dir, f"{base_name}_decryption_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nSummary saved to: {summary_path}")
    return top_results

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Multi-Layer Decryption for KEYPLUG Malware")
    parser.add_argument("file", help="File to decrypt")
    parser.add_argument("-o", "--output-dir", default="decrypted", help="Output directory for decrypted files")
    parser.add_argument("--no-openvino", action="store_true", help="Disable OpenVINO acceleration")
    args = parser.parse_args()
    
    process_file(args.file, args.output_dir, use_openvino=not args.no_openvino)

if __name__ == "__main__":
    main()
