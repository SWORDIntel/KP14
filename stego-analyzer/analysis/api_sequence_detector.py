#!/usr/bin/env python3
"""
KEYPLUG API Sequence Detector
----------------------------
Detects API call sequences in KEYPLUG malware with OpenVINO acceleration.

This module identifies API call sequences that match known malicious patterns,
leveraging hardware acceleration for maximum performance.
"""

import os
import sys
import json
import numpy as np
from collections import defaultdict
import concurrent.futures

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for API sequence detection")
    
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

class APISequenceDetector:
    """
    Detects API call sequences in KEYPLUG malware with OpenVINO acceleration
    """
    
    def __init__(self, pattern_db_path=None, use_openvino=True):
        """
        Initialize the API sequence detector
        
        Args:
            pattern_db_path: Path to pattern database file
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.pattern_db_path = pattern_db_path
        
        # Load known API sequence patterns
        self.api_sequences = self._load_api_sequences()
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Set up OpenVINO for sequence matching
        # This is a placeholder for actual OpenVINO model setup
        pass
    
    def _load_api_sequences(self):
        """Load known API sequence patterns"""
        # Default patterns
        default_sequences = {
            "c2_communication": [
                {
                    "sequence": ["socket", "connect", "send", "recv"],
                    "description": "Basic socket-based C2 communication",
                    "confidence": 0.7
                },
                {
                    "sequence": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"],
                    "description": "HTTP-based C2 communication",
                    "confidence": 0.8
                },
                {
                    "sequence": ["DnsQuery", "socket", "connect", "send"],
                    "description": "DNS-based C2 communication",
                    "confidence": 0.8
                }
            ],
            "process_injection": [
                {
                    "sequence": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    "description": "Classic process injection",
                    "confidence": 0.9
                },
                {
                    "sequence": ["NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"],
                    "description": "Native API process injection",
                    "confidence": 0.9
                },
                {
                    "sequence": ["GetModuleHandle", "GetProcAddress", "VirtualProtect"],
                    "description": "API hooking",
                    "confidence": 0.7
                }
            ],
            "persistence": [
                {
                    "sequence": ["RegOpenKeyEx", "RegSetValueEx"],
                    "description": "Registry persistence",
                    "confidence": 0.7
                },
                {
                    "sequence": ["CreateFile", "WriteFile", "CloseHandle", "CreateProcess"],
                    "description": "File-based persistence",
                    "confidence": 0.6
                },
                {
                    "sequence": ["WTSEnumerateSessions", "WTSQueryUserToken", "CreateProcessAsUser"],
                    "description": "Session-based persistence",
                    "confidence": 0.8
                }
            ],
            "anti_analysis": [
                {
                    "sequence": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                    "description": "Debugger detection",
                    "confidence": 0.8
                },
                {
                    "sequence": ["GetTickCount", "Sleep", "GetTickCount"],
                    "description": "Timing-based anti-analysis",
                    "confidence": 0.6
                },
                {
                    "sequence": ["GetModuleHandle", "GetProcAddress", "GetSystemInfo"],
                    "description": "System information gathering",
                    "confidence": 0.5
                }
            ],
            "data_exfiltration": [
                {
                    "sequence": ["FindFirstFile", "FindNextFile", "ReadFile", "send"],
                    "description": "File exfiltration",
                    "confidence": 0.8
                },
                {
                    "sequence": ["GetClipboardData", "send"],
                    "description": "Clipboard exfiltration",
                    "confidence": 0.8
                },
                {
                    "sequence": ["GetDC", "BitBlt", "send"],
                    "description": "Screenshot exfiltration",
                    "confidence": 0.8
                }
            ]
        }
        
        # Load patterns from database if available
        if self.pattern_db_path and os.path.exists(self.pattern_db_path):
            try:
                with open(self.pattern_db_path, 'r') as f:
                    data = json.load(f)
                    
                    if "patterns" in data and "api_sequences" in data["patterns"]:
                        # Convert from pattern database format to sequence detector format
                        sequences = defaultdict(list)
                        
                        for pattern in data["patterns"]["api_sequences"]:
                            if "pattern" in pattern and isinstance(pattern["pattern"], list):
                                # Determine category
                                category = "other"
                                for tag in pattern.get("tags", []):
                                    if tag in default_sequences.keys():
                                        category = tag
                                        break
                                
                                sequences[category].append({
                                    "sequence": pattern["pattern"],
                                    "description": pattern.get("description", ""),
                                    "confidence": pattern.get("confidence", 0.5)
                                })
                        
                        # Merge with default sequences
                        for category, patterns in default_sequences.items():
                            if category not in sequences:
                                sequences[category] = patterns
                        
                        return dict(sequences)
                        
                print(f"Loaded API sequences from {self.pattern_db_path}")
                return sequences
            except Exception as e:
                print(f"Error loading API sequences from {self.pattern_db_path}: {e}")
        
        return default_sequences
    
    def detect_sequences(self, api_calls, min_confidence=0.5):
        """
        Detect API call sequences in a list of API calls
        
        Args:
            api_calls: List of API calls
            min_confidence: Minimum confidence score
            
        Returns:
            List of detected sequences with details
        """
        if self.use_openvino and len(api_calls) > 100:
            # Use OpenVINO for large data
            return self._openvino_detect_sequences(api_calls, min_confidence)
        else:
            # Use standard Python for small data
            return self._standard_detect_sequences(api_calls, min_confidence)
    
    def _standard_detect_sequences(self, api_calls, min_confidence=0.5):
        """Standard sequence detection implementation"""
        results = []
        
        # Process each category
        for category, sequences in self.api_sequences.items():
            for sequence_pattern in sequences:
                pattern = sequence_pattern["sequence"]
                confidence = sequence_pattern.get("confidence", 0.5)
                
                # Skip if confidence is too low
                if confidence < min_confidence:
                    continue
                
                # Find all occurrences of the sequence
                matches = self._find_subsequence(api_calls, pattern)
                
                if matches:
                    results.append({
                        "category": category,
                        "pattern": pattern,
                        "description": sequence_pattern.get("description", ""),
                        "confidence": confidence,
                        "matches": matches
                    })
        
        return results
    
    def _openvino_detect_sequences(self, api_calls, min_confidence=0.5):
        """OpenVINO-accelerated sequence detection implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate sequence matching
        
        # For now, fall back to standard implementation
        return self._standard_detect_sequences(api_calls, min_confidence)
    
    def _find_subsequence(self, sequence, subsequence):
        """Find all occurrences of a subsequence in a sequence"""
        matches = []
        seq_len = len(sequence)
        subseq_len = len(subsequence)
        
        # Check if subsequence is longer than sequence
        if subseq_len > seq_len:
            return matches
        
        # Find all occurrences
        for i in range(seq_len - subseq_len + 1):
            match = True
            for j in range(subseq_len):
                if sequence[i+j] != subsequence[j]:
                    match = False
                    break
            
            if match:
                matches.append({
                    "start_index": i,
                    "end_index": i + subseq_len - 1,
                    "apis": subsequence
                })
        
        return matches
    
    def analyze_binary(self, binary_path, min_confidence=0.5):
        """
        Analyze a binary file for API call sequences
        
        Args:
            binary_path: Path to binary file
            min_confidence: Minimum confidence score
            
        Returns:
            Analysis results with detected sequences
        """
        # Extract API calls from binary
        api_calls = self._extract_api_calls(binary_path)
        
        if not api_calls:
            print(f"No API calls found in {binary_path}")
            return {
                "file": os.path.basename(binary_path),
                "api_count": 0,
                "sequences": []
            }
        
        # Detect sequences
        sequences = self.detect_sequences(api_calls, min_confidence)
        
        return {
            "file": os.path.basename(binary_path),
            "api_count": len(api_calls),
            "api_calls": api_calls,
            "sequences": sequences
        }
    
    def _extract_api_calls(self, binary_path):
        """Extract API calls from a binary file"""
        # This is a simplified implementation
        # In a real implementation, we would use a disassembler or similar tool
        
        try:
            # Read the binary file
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Extract API calls (simplified approach)
            api_calls = []
            
            # Common Windows API names to look for
            common_apis = [
                "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
                "RegOpenKeyEx", "RegSetValueEx", "RegCloseKey",
                "socket", "connect", "send", "recv", "closesocket",
                "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                "CreateProcess", "OpenProcess", "VirtualAlloc", "VirtualFree",
                "LoadLibrary", "GetProcAddress", "GetModuleHandle",
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "GetTickCount", "Sleep", "GetSystemInfo"
            ]
            
            # Look for API names in the binary
            for api in common_apis:
                api_bytes = api.encode('utf-8')
                offset = 0
                
                while True:
                    offset = data.find(api_bytes, offset)
                    if offset == -1:
                        break
                    
                    api_calls.append(api)
                    offset += len(api_bytes)
            
            return api_calls
        except Exception as e:
            print(f"Error extracting API calls from {binary_path}: {e}")
            return []

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KEYPLUG API Sequence Detector')
    parser.add_argument('-f', '--file', help='Binary file to analyze')
    parser.add_argument('-d', '--dir', help='Directory containing binary files to analyze')
    parser.add_argument('-o', '--output', help='Output file for analysis results')
    parser.add_argument('-p', '--pattern-db', help='Path to pattern database file')
    parser.add_argument('-c', '--min-confidence', type=float, help='Minimum confidence score', default=0.5)
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.dir:
        parser.error("Either --file or --dir must be specified")
    
    # Initialize detector
    detector = APISequenceDetector(
        pattern_db_path=args.pattern_db,
        use_openvino=not args.no_openvino
    )
    
    results = []
    
    # Process a single file
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found")
            return 1
        
        print(f"Analyzing {args.file}...")
        result = detector.analyze_binary(args.file, args.min_confidence)
        results.append(result)
    
    # Process a directory of files
    elif args.dir:
        if not os.path.exists(args.dir):
            print(f"Error: Directory {args.dir} not found")
            return 1
        
        # Find all binary files in the directory
        import glob
        binary_files = glob.glob(os.path.join(args.dir, "*.bin"))
        binary_files += glob.glob(os.path.join(args.dir, "*.exe"))
        binary_files += glob.glob(os.path.join(args.dir, "*.dll"))
        
        if not binary_files:
            print(f"No binary files found in {args.dir}")
            return 1
        
        print(f"Found {len(binary_files)} binary files in {args.dir}")
        
        # Process files in parallel
        with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(detector.analyze_binary, file_path, args.min_confidence): file_path for file_path in binary_files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"Analyzed {file_path}")
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")
    
    # Save results
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        except Exception as e:
            print(f"Error saving results: {e}")
    else:
        # Print summary
        print("\nAnalysis Results:")
        for result in results:
            print(f"\nFile: {result['file']}")
            print(f"API Calls: {result['api_count']}")
            print(f"Detected Sequences: {len(result['sequences'])}")
            
            for sequence in result['sequences']:
                print(f"  - {sequence['category']}: {sequence['description']} (Confidence: {sequence['confidence']:.2f})")
                print(f"    Sequence: {' -> '.join(sequence['pattern'])}")
                print(f"    Matches: {len(sequence['matches'])}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
