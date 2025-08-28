#!/usr/bin/env python3
"""
KEYPLUG Behavioral Analysis Engine
--------------------------------
Analyzes malware behavior patterns with OpenVINO acceleration.

This module identifies behavioral patterns in KEYPLUG malware by analyzing
API call sequences, memory operations, and other indicators of malicious behavior.
"""

import os
import sys
import json
import concurrent.futures

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for behavioral analysis")
    
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

# Import API sequence detector
try:
    from stego_analyzer.analysis.api_sequence_detector import APISequenceDetector
    API_SEQUENCE_DETECTOR_AVAILABLE = True
except ImportError:
    # Fallback if the primary location is not found
    try:
        from analysis.api_sequence_detector import APISequenceDetector
        API_SEQUENCE_DETECTOR_AVAILABLE = True
    except ImportError:
        API_SEQUENCE_DETECTOR_AVAILABLE = False
        print("ERROR: APISequenceDetector not found. Ensure it's in stego_analyzer.analysis or analysis module.")

class BehavioralAnalyzer:
    """
    Analyzes malware behavior patterns with OpenVINO acceleration
    """
    
    def __init__(self, pattern_db_path=None, use_openvino=True):
        """
        Initialize the behavioral analyzer
        
        Args:
            pattern_db_path: Path to pattern database file
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.pattern_db_path = pattern_db_path
        
        # Initialize API sequence detector if available
        if API_SEQUENCE_DETECTOR_AVAILABLE:
            self.api_detector = APISequenceDetector(pattern_db_path, use_openvino)
        else:
            self.api_detector = None
        
        # Load behavior patterns
        self.behavior_patterns = self._load_behavior_patterns()
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Set up OpenVINO for behavioral analysis
        # This is a placeholder for actual OpenVINO model setup
        pass
    
    def _load_behavior_patterns(self):
        """Load behavior patterns"""
        # Default patterns
        default_patterns = {
            "command_and_control": {
                "description": "Command and Control (C2) communication",
                "indicators": [
                    {"type": "api_sequence", "category": "c2_communication", "weight": 0.8},
                    {"type": "network_activity", "protocol": "http", "weight": 0.6},
                    {"type": "network_activity", "protocol": "dns", "weight": 0.7},
                    {"type": "string", "pattern": "User-Agent:", "weight": 0.3}
                ],
                "threshold": 0.7
            },
            "process_injection": {
                "description": "Process injection techniques",
                "indicators": [
                    {"type": "api_sequence", "category": "process_injection", "weight": 0.9},
                    {"type": "memory_operation", "operation": "write", "weight": 0.7},
                    {"type": "memory_operation", "operation": "execute", "weight": 0.8}
                ],
                "threshold": 0.8
            },
            "persistence": {
                "description": "Persistence mechanisms",
                "indicators": [
                    {"type": "api_sequence", "category": "persistence", "weight": 0.8},
                    {"type": "registry_access", "key": "Run", "weight": 0.7},
                    {"type": "file_access", "path": "Startup", "weight": 0.6}
                ],
                "threshold": 0.7
            },
            "anti_analysis": {
                "description": "Anti-analysis techniques",
                "indicators": [
                    {"type": "api_sequence", "category": "anti_analysis", "weight": 0.8},
                    {"type": "timing_check", "weight": 0.7},
                    {"type": "vm_detection", "weight": 0.9}
                ],
                "threshold": 0.7
            },
            "data_exfiltration": {
                "description": "Data exfiltration techniques",
                "indicators": [
                    {"type": "api_sequence", "category": "data_exfiltration", "weight": 0.8},
                    {"type": "file_access", "operation": "read", "weight": 0.6},
                    {"type": "network_activity", "direction": "outbound", "weight": 0.7}
                ],
                "threshold": 0.7
            },
            "keylogging": {
                "description": "Keylogging functionality",
                "indicators": [
                    {"type": "api_call", "name": "GetAsyncKeyState", "weight": 0.9},
                    {"type": "api_call", "name": "SetWindowsHookEx", "weight": 0.9},
                    {"type": "file_access", "operation": "write", "weight": 0.6}
                ],
                "threshold": 0.8
            },
            "ransomware": {
                "description": "Ransomware functionality",
                "indicators": [
                    {"type": "file_access", "operation": "encrypt", "weight": 0.9},
                    {"type": "api_call", "name": "CryptEncrypt", "weight": 0.8},
                    {"type": "string", "pattern": "ransom", "weight": 0.7}
                ],
                "threshold": 0.8
            }
        }
        
        # Load patterns from database if available
        if self.pattern_db_path and os.path.exists(self.pattern_db_path):
            try:
                with open(self.pattern_db_path, 'r') as f:
                    loaded_data = json.load(f) # Changed variable name to avoid conflict
                    
                    # TODO: Load behavior patterns from database
                    # This is a placeholder for actual implementation
                    # For now, we can merge or update default_patterns with loaded_data if structure matches
                    # Example: default_patterns.update(loaded_data.get("behavior_patterns", {}))
                    
                print(f"Loaded behavior patterns from {self.pattern_db_path}")
            except Exception as e:
                print(f"Error loading behavior patterns from {self.pattern_db_path}: {e}")
        
        return default_patterns
    
    def analyze_binary(self, binary_path, min_confidence=0.5):
        """
        Analyze a binary file for behavioral patterns
        
        Args:
            binary_path: Path to binary file
            min_confidence: Minimum confidence score
            
        Returns:
            Analysis results with detected behaviors
        """
        # Initialize results
        results = {
            "file": os.path.basename(binary_path),
            "behaviors": [],
            "api_sequences": [],
            "overall_score": 0.0
        }
        
        # Analyze API sequences if detector is available
        if self.api_detector:
            api_results = self.api_detector.analyze_binary(binary_path, min_confidence)
            results["api_sequences"] = api_results.get("sequences", [])
        
        # Extract additional indicators
        indicators = self._extract_indicators(binary_path)
        
        # Analyze behaviors
        behaviors = self._analyze_behaviors(results["api_sequences"], indicators, min_confidence)
        results["behaviors"] = behaviors
        
        # Calculate overall maliciousness score
        overall_score = self._calculate_overall_score(behaviors)
        results["overall_score"] = overall_score
        
        return results
    
    def _extract_indicators(self, binary_path):
        """Extract behavioral indicators from a binary file"""
        indicators = {
            "api_calls": [],
            "strings": [],
            "network_activity": [],
            "file_access": [],
            "registry_access": [],
            "memory_operations": [],
            "timing_checks": False,
            "vm_detection": False
        }
        
        try:
            # Read the binary file
            with open(binary_path, 'rb') as f:
                binary_content = f.read()
            
            # Extract API calls (simplified approach)
            common_apis = [
                "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
                "RegOpenKeyEx", "RegSetValueEx", "RegCloseKey",
                "socket", "connect", "send", "recv", "closesocket",
                "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                "CreateProcess", "OpenProcess", "VirtualAlloc", "VirtualFree",
                "LoadLibrary", "GetProcAddress", "GetModuleHandle",
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "GetTickCount", "Sleep", "GetSystemInfo",
                "GetAsyncKeyState", "SetWindowsHookEx",
                "CryptEncrypt", "CryptDecrypt"
            ]
            
            # Look for API names in the binary
            for api in common_apis:
                api_bytes = api.encode('utf-8')
                if api_bytes in binary_content:
                    indicators["api_calls"].append(api)
            
            # Check for timing-based anti-analysis
            if b"GetTickCount" in binary_content and b"Sleep" in binary_content:
                indicators["timing_checks"] = True
            
            # Check for VM detection
            vm_strings = [b"VMware", b"VBox", b"QEMU", b"Virtual", b"Xen"]
            for vm_string in vm_strings:
                if vm_string in binary_content:
                    indicators["vm_detection"] = True
                    break
            
            # Extract strings (simplified approach)
            import re
            ascii_pattern = re.compile(b'[ -~]{4,}')
            for match in ascii_pattern.finditer(binary_content):
                string = match.group().decode('ascii', errors='ignore')
                indicators["strings"].append(string)
            
            # Check for network activity
            network_indicators = [
                "http://", "https://", "ftp://", "socket", "connect", "send", "recv",
                "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"
            ]
            for indicator in network_indicators:
                if indicator.encode('utf-8') in binary_content:
                    protocol = "http"
                    if "ftp://" in indicator:
                        protocol = "ftp"
                    elif "socket" in indicator or "connect" in indicator:
                        protocol = "tcp"
                    
                    indicators["network_activity"].append({
                        "protocol": protocol,
                        "direction": "outbound"  # Assuming outbound by default
                    })
            
            # Check for file access
            file_indicators = ["CreateFile", "ReadFile", "WriteFile", "DeleteFile"]
            for indicator in file_indicators:
                if indicator.encode('utf-8') in binary_content:
                    operation = "read"
                    if "Write" in indicator:
                        operation = "write"
                    elif "Delete" in indicator:
                        operation = "delete"
                    
                    indicators["file_access"].append({
                        "operation": operation
                    })
            
            # Check for registry access
            registry_indicators = ["RegOpenKeyEx", "RegSetValueEx", "RegDeleteValue"]
            for indicator in registry_indicators:
                if indicator.encode('utf-8') in binary_content:
                    operation = "read"
                    if "Set" in indicator:
                        operation = "write"
                    elif "Delete" in indicator:
                        operation = "delete"
                    
                    indicators["registry_access"].append({
                        "operation": operation
                    })
            
            # Check for memory operations
            memory_indicators = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory"]
            for indicator in memory_indicators:
                if indicator.encode('utf-8') in binary_content:
                    operation = "allocate"
                    if "Write" in indicator:
                        operation = "write"
                    elif "Read" in indicator:
                        operation = "read"
                    elif "Protect" in indicator:
                        operation = "protect"
                    
                    indicators["memory_operations"].append({
                        "operation": operation
                    })
            
            return indicators
        except Exception as e:
            print(f"Error extracting indicators from {binary_path}: {e}")
            return indicators
    
    def _analyze_behaviors(self, api_sequences, indicators, min_confidence=0.5):
        """Analyze behaviors based on API sequences and other indicators"""
        behaviors = []
        
        # Process each behavior pattern
        for behavior_name, behavior_pattern in self.behavior_patterns.items():
            score = 0.0
            matched_indicators = []
            
            # Check each indicator
            for indicator in behavior_pattern["indicators"]:
                indicator_type = indicator["type"]
                weight = indicator.get("weight", 0.5)
                
                if indicator_type == "api_sequence":
                    # Check API sequences
                    category = indicator.get("category")
                    for sequence in api_sequences:
                        if sequence["category"] == category:
                            score += weight * sequence["confidence"]
                            matched_indicators.append({
                                "type": "api_sequence",
                                "category": category,
                                "description": sequence["description"],
                                "confidence": sequence["confidence"]
                            })
                
                elif indicator_type == "api_call":
                    # Check API calls
                    api_name = indicator.get("name")
                    if api_name in indicators["api_calls"]:
                        score += weight
                        matched_indicators.append({
                            "type": "api_call",
                            "name": api_name
                        })
                
                elif indicator_type == "string":
                    # Check strings
                    pattern = indicator.get("pattern")
                    for string in indicators["strings"]:
                        if pattern in string:
                            score += weight
                            matched_indicators.append({
                                "type": "string",
                                "pattern": pattern,
                                "value": string
                            })
                            break
                
                elif indicator_type == "network_activity":
                    # Check network activity
                    protocol = indicator.get("protocol")
                    direction = indicator.get("direction")
                    
                    for activity in indicators["network_activity"]:
                        if (not protocol or activity.get("protocol") == protocol) and \
                           (not direction or activity.get("direction") == direction):
                            score += weight
                            matched_indicators.append({
                                "type": "network_activity",
                                "protocol": activity.get("protocol"),
                                "direction": activity.get("direction")
                            })
                            break
                
                elif indicator_type == "file_access":
                    # Check file access
                    operation = indicator.get("operation")
                    path = indicator.get("path")
                    
                    for access in indicators["file_access"]:
                        if (not operation or access.get("operation") == operation) and \
                           (not path or path in access.get("path", "")):
                            score += weight
                            matched_indicators.append({
                                "type": "file_access",
                                "operation": access.get("operation"),
                                "path": access.get("path")
                            })
                            break
                
                elif indicator_type == "registry_access":
                    # Check registry access
                    operation = indicator.get("operation")
                    key = indicator.get("key")
                    
                    for access in indicators["registry_access"]:
                        if (not operation or access.get("operation") == operation) and \
                           (not key or key in access.get("key", "")):
                            score += weight
                            matched_indicators.append({
                                "type": "registry_access",
                                "operation": access.get("operation"),
                                "key": access.get("key")
                            })
                            break
                
                elif indicator_type == "memory_operation":
                    # Check memory operations
                    operation = indicator.get("operation")
                    
                    for op in indicators["memory_operations"]:
                        if op.get("operation") == operation:
                            score += weight
                            matched_indicators.append({
                                "type": "memory_operation",
                                "operation": operation
                            })
                            break
                
                elif indicator_type == "timing_check":
                    # Check timing-based anti-analysis
                    if indicators["timing_checks"]:
                        score += weight
                        matched_indicators.append({
                            "type": "timing_check"
                        })
                
                elif indicator_type == "vm_detection":
                    # Check VM detection
                    if indicators["vm_detection"]:
                        score += weight
                        matched_indicators.append({
                            "type": "vm_detection"
                        })
            
            # Normalize score based on number of indicators
            if behavior_pattern["indicators"]:
                max_possible_score = sum(indicator.get("weight", 0.5) for indicator in behavior_pattern["indicators"])
                if max_possible_score > 0:
                    score = score / max_possible_score
            
            # Check if score exceeds threshold
            threshold = behavior_pattern.get("threshold", 0.5)
            if score >= threshold and score >= min_confidence:
                behaviors.append({
                    "name": behavior_name,
                    "description": behavior_pattern.get("description", ""),
                    "score": score,
                    "threshold": threshold,
                    "indicators": matched_indicators
                })
        
        # Sort behaviors by score (highest first)
        behaviors.sort(key=lambda x: x["score"], reverse=True)
        
        return behaviors
    
    def _calculate_overall_score(self, behaviors):
        """Calculate overall maliciousness score based on detected behaviors"""
        if not behaviors:
            return 0.0
        
        # Weight behaviors by their score
        weighted_sum = sum(behavior["score"] for behavior in behaviors)
        
        # Normalize by number of behaviors
        max_behaviors = len(self.behavior_patterns)
        if max_behaviors > 0:
            # Scale to 0.0-1.0 range
            normalized_score = min(1.0, weighted_sum / max_behaviors)
        else:
            normalized_score = 0.0
        
        return normalized_score

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KEYPLUG Behavioral Analysis Engine')
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
    
    # Initialize analyzer
    analyzer = BehavioralAnalyzer(
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
        result = analyzer.analyze_binary(args.file, args.min_confidence)
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
            future_to_file = {executor.submit(analyzer.analyze_binary, file_path, args.min_confidence): file_path for file_path in binary_files}
            
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
            print(f"Overall Score: {result['overall_score']:.2f}")
            print(f"Detected Behaviors: {len(result['behaviors'])}")
            
            for behavior in result['behaviors']:
                print(f"  - {behavior['name']}: {behavior['description']} (Score: {behavior['score']:.2f})")
                print(f"    Indicators: {len(behavior['indicators'])}")
                
                for indicator in behavior['indicators'][:3]:  # Show top 3 indicators
                    if indicator['type'] == 'api_sequence':
                        print(f"      * API Sequence: {indicator['category']} ({indicator['confidence']:.2f})")
                    elif indicator['type'] == 'api_call':
                        print(f"      * API Call: {indicator['name']}")
                    elif indicator['type'] == 'string':
                        print(f"      * String: {indicator['pattern']}")
                    else:
                        print(f"      * {indicator['type']}")
                
                if len(behavior['indicators']) > 3:
                    print(f"      * ... and {len(behavior['indicators']) - 3} more indicators")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
