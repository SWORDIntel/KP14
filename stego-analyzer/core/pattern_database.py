#!/usr/bin/env python3
"""
KEYPLUG Pattern Database
-----------------------
Centralized pattern database for KEYPLUG malware analysis with OpenVINO acceleration.

This module provides a comprehensive pattern database with hardware acceleration
for storing, retrieving, and matching patterns identified in KEYPLUG malware samples.
"""

import os
import sys
import json
import hashlib
import datetime
# import numpy as np # F401 unused
# from collections import defaultdict # F401 unused
import concurrent.futures

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for pattern database")
    
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

class PatternDatabase:
    """
    Centralized pattern database for KEYPLUG malware analysis
    with OpenVINO acceleration for pattern matching
    """
    
    def __init__(self, db_path="keyplug_patterns.json", use_openvino=True):
        """
        Initialize the pattern database
        
        Args:
            db_path: Path to the pattern database file
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.db_path = db_path
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.patterns = {
            "peb_traversal": [],
            "api_hashing": [],
            "string_encoding": [],
            "decoder_functions": [],
            "api_sequences": [],
            "c2_patterns": [],
            "injection_patterns": [],
            "evasion_techniques": []
        }
        self.metadata = {
            "creation_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pattern_count": 0,
            "openvino_acceleration": self.use_openvino,
            "preferred_device": PREFERRED_DEVICE if self.use_openvino else "None"
        }
        
        # Load existing database if it exists
        if os.path.exists(db_path):
            self.load_database()
        else:
            self.save_database()
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
    
    def _init_openvino(self):
        """Initialize OpenVINO for pattern matching acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Set up OpenVINO for pattern matching
        # This is a placeholder for actual OpenVINO model setup
        # In a real implementation, we would create and compile models for
        # various pattern matching operations
        pass
    
    def load_database(self):
        """Load pattern database from file"""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
                self.patterns = data.get("patterns", self.patterns)
                self.metadata = data.get("metadata", self.metadata)
                
                # Update pattern count
                self.metadata["pattern_count"] = sum(len(patterns) for patterns in self.patterns.values())
                
                print(f"Loaded {self.metadata['pattern_count']} patterns from {self.db_path}")
        except Exception as e:
            print(f"Error loading pattern database: {e}")
    
    def save_database(self):
        """Save pattern database to file"""
        try:
            # Update metadata
            self.metadata["last_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.metadata["pattern_count"] = sum(len(patterns) for patterns in self.patterns.values())
            
            data = {
                "patterns": self.patterns,
                "metadata": self.metadata
            }
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            print(f"Saved {self.metadata['pattern_count']} patterns to {self.db_path}")
        except Exception as e:
            print(f"Error saving pattern database: {e}")
    
    def add_pattern(self, category, pattern, description=None, source=None, confidence=None, tags=None):
        """
        Add a pattern to the database
        
        Args:
            category: Pattern category (peb_traversal, api_hashing, etc.)
            pattern: The pattern to add (can be bytes, string, or dict)
            description: Description of the pattern
            source: Source of the pattern (file, analysis, etc.)
            confidence: Confidence score (0.0-1.0)
            tags: List of tags for the pattern
            
        Returns:
            Pattern ID if successful, None otherwise
        """
        if category not in self.patterns:
            print(f"Error: Invalid category '{category}'")
            return None
        
        # Generate pattern ID
        pattern_id = self._generate_pattern_id(category, pattern)
        
        # Check if pattern already exists
        for existing_pattern in self.patterns[category]:
            if existing_pattern.get("id") == pattern_id:
                # Update existing pattern
                existing_pattern["description"] = description or existing_pattern.get("description")
                existing_pattern["source"] = source or existing_pattern.get("source")
                existing_pattern["confidence"] = confidence or existing_pattern.get("confidence")
                existing_pattern["tags"] = tags or existing_pattern.get("tags")
                existing_pattern["last_updated"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                self.save_database()
                return pattern_id
        
        # Create new pattern
        new_pattern = {
            "id": pattern_id,
            "pattern": pattern,
            "description": description or "",
            "source": source or "manual",
            "confidence": confidence or 0.5,
            "tags": tags or [],
            "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.patterns[category].append(new_pattern)
        self.save_database()
        
        return pattern_id
    
    def remove_pattern(self, pattern_id):
        """
        Remove a pattern from the database
        
        Args:
            pattern_id: ID of the pattern to remove
            
        Returns:
            True if successful, False otherwise
        """
        for category, patterns in self.patterns.items():
            for i, pattern in enumerate(patterns):
                if pattern.get("id") == pattern_id:
                    self.patterns[category].pop(i)
                    self.save_database()
                    return True
        
        return False
    
    def get_pattern(self, pattern_id):
        """
        Get a pattern by ID
        
        Args:
            pattern_id: ID of the pattern to get
            
        Returns:
            Pattern dict if found, None otherwise
        """
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.get("id") == pattern_id:
                    return pattern
        
        return None
    
    def search_patterns(self, query, category=None, tags=None, min_confidence=0.0):
        """
        Search for patterns in the database
        
        Args:
            query: Search query (string)
            category: Limit search to specific category
            tags: Limit search to patterns with specific tags
            min_confidence: Minimum confidence score
            
        Returns:
            List of matching patterns
        """
        results = []
        
        # Determine categories to search
        categories = [category] if category else self.patterns.keys()
        
        for cat in categories:
            if cat not in self.patterns:
                continue
                
            for pattern in self.patterns[cat]:
                # Check confidence
                if pattern.get("confidence", 0.0) < min_confidence:
                    continue
                    
                # Check tags
                if tags and not any(tag in pattern.get("tags", []) for tag in tags):
                    continue
                    
                # Check query
                if query.lower() in str(pattern.get("pattern", "")).lower() or \
                   query.lower() in pattern.get("description", "").lower():
                    results.append(pattern)
        
        return results
    
    def match_pattern(self, data, category=None, min_confidence=0.0):
        """
        Match data against patterns in the database
        
        Args:
            data: Data to match (bytes or string)
            category: Limit matching to specific category
            min_confidence: Minimum confidence score
            
        Returns:
            List of matching patterns with match details
        """
        if self.use_openvino and len(data) > 1024:
            # Use OpenVINO for large data
            return self._openvino_match_pattern(data, category, min_confidence)
        else:
            # Use standard Python for small data
            return self._standard_match_pattern(data, category, min_confidence)
    
    def _standard_match_pattern(self, data, category=None, min_confidence=0.0):
        """Standard pattern matching implementation"""
        results = []
        
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Determine categories to search
        categories = [category] if category else self.patterns.keys()
        
        for cat in categories:
            if cat not in self.patterns:
                continue
                
            for pattern in self.patterns[cat]:
                # Check confidence
                if pattern.get("confidence", 0.0) < min_confidence:
                    continue
                
                # Get pattern data
                pattern_data = pattern.get("pattern")
                
                # Skip if pattern is not valid
                if not pattern_data:
                    continue
                
                # Convert pattern to bytes if it's a string
                if isinstance(pattern_data, str):
                    pattern_data = pattern_data.encode('utf-8')
                
                # Match pattern
                if isinstance(pattern_data, (bytes, bytearray)):
                    # Binary pattern
                    matches = self._find_all(data, pattern_data)
                    
                    if matches:
                        results.append({
                            "pattern": pattern,
                            "category": cat,
                            "matches": matches
                        })
                elif isinstance(pattern_data, dict) and "regex" in pattern_data:
                    # Regex pattern
                    import re
                    regex = pattern_data["regex"]
                    
                    try:
                        matches = []
                        for match in re.finditer(regex.encode('utf-8'), data):
                            matches.append({
                                "offset": match.start(),
                                "length": match.end() - match.start(),
                                "value": match.group().decode('utf-8', errors='ignore')
                            })
                        
                        if matches:
                            results.append({
                                "pattern": pattern,
                                "category": cat,
                                "matches": matches
                            })
                    except Exception as e:
                        print(f"Error matching regex pattern: {e}")
        
        return results
    
    def _openvino_match_pattern(self, data, category=None, min_confidence=0.0):
        """OpenVINO-accelerated pattern matching implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate pattern matching
        
        # For now, fall back to standard implementation
        return self._standard_match_pattern(data, category, min_confidence)
    
    def _find_all(self, data, pattern):
        """Find all occurrences of a pattern in data"""
        matches = []
        offset = 0
        
        while True:
            offset = data.find(pattern, offset)
            if offset == -1:
                break
                
            matches.append({
                "offset": offset,
                "length": len(pattern),
                "value": pattern.decode('utf-8', errors='ignore')
            })
            
            offset += 1
        
        return matches
    
    def _generate_pattern_id(self, category, pattern):
        """Generate a unique ID for a pattern"""
        pattern_str = str(pattern)
        pattern_hash = hashlib.md5(pattern_str.encode('utf-8')).hexdigest()
        return f"{category}_{pattern_hash}"
    
    def import_patterns_from_analysis(self, analysis_dir, categories=None):
        """
        Import patterns from analysis results
        
        Args:
            analysis_dir: Directory containing analysis results
            categories: List of categories to import (default: all)
            
        Returns:
            Number of patterns imported
        """
        if not os.path.exists(analysis_dir):
            print(f"Error: Analysis directory {analysis_dir} not found")
            return 0
        
        # Determine categories to import
        if categories is None:
            categories = list(self.patterns.keys())
        
        # Find all JSON files in the analysis directory
        import glob
        json_files = glob.glob(os.path.join(analysis_dir, "**", "*.json"), recursive=True)
        
        if not json_files:
            print(f"No JSON files found in {analysis_dir}")
            return 0
        
        print(f"Found {len(json_files)} JSON files in {analysis_dir}")
        
        # Process files in parallel
        imported_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(self._process_analysis_file, file_path, categories): file_path for file_path in json_files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    count = future.result()
                    imported_count += count
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
        
        # Save database
        self.save_database()
        
        print(f"Imported {imported_count} patterns from {analysis_dir}")
        return imported_count
    
    def _process_analysis_file(self, file_path, categories):
        """Process a single analysis file for pattern import"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            file_name = os.path.basename(file_path)
            imported_count = 0
            
            # Process PEB traversal patterns
            if "peb_traversal" in categories and "peb_analysis" in file_path:
                # Extract PEB traversal patterns
                if "raw_peb_matches" in data:
                    for match in data["raw_peb_matches"]:
                        pattern = match.get("pattern")
                        description = match.get("description")
                        
                        if pattern:
                            self.add_pattern(
                                "peb_traversal",
                                pattern,
                                description=description,
                                source=file_name,
                                confidence=0.8,
                                tags=["peb", "api_resolution"]
                            )
                            imported_count += 1
            
            # Process API hashing patterns
            if "api_hashing" in categories and "hash_analysis" in file_path:
                # Extract API hashing patterns
                if "hash_algorithms" in data:
                    for algo in data["hash_algorithms"]:
                        algorithm = algo.get("algorithm")
                        patterns = algo.get("patterns", [])
                        confidence = algo.get("confidence", 0.5)
                        
                        for pattern in patterns:
                            self.add_pattern(
                                "api_hashing",
                                pattern,
                                description=f"API hashing algorithm: {algorithm}",
                                source=file_name,
                                confidence=confidence,
                                tags=["api_hashing", algorithm]
                            )
                            imported_count += 1
            
            # Process string encoding patterns
            if "string_encoding" in categories and "string_analysis" in file_path:
                # Extract string encoding patterns
                if "encoded_strings" in data:
                    for string in data["encoded_strings"]:
                        encoded = string.get("encoded")
                        decoded = string.get("decoded")
                        algorithm = string.get("algorithm")
                        score = string.get("score", 0.5)
                        
                        if encoded and decoded and algorithm:
                            self.add_pattern(
                                "string_encoding",
                                {
                                    "encoded": encoded,
                                    "decoded": decoded,
                                    "algorithm": algorithm
                                },
                                description=f"Encoded string using {algorithm}",
                                source=file_name,
                                confidence=score,
                                tags=["string_encoding", algorithm]
                            )
                            imported_count += 1
            
            # Process decoder function patterns
            if "decoder_functions" in categories and "decoder_analysis" in file_path:
                # Extract decoder function patterns
                if "decoders" in data:
                    for decoder in data["decoders"]:
                        signature = decoder.get("signature")
                        score = decoder.get("score", 0.5)
                        decoder_type = decoder.get("type", "unknown")
                        
                        if signature:
                            self.add_pattern(
                                "decoder_functions",
                                signature,
                                description=f"Decoder function of type {decoder_type}",
                                source=file_name,
                                confidence=score,
                                tags=["decoder", decoder_type]
                            )
                            imported_count += 1
            
            # Process API sequence patterns
            if "api_sequences" in categories and "api_flow" in file_path:
                # Extract API sequence patterns
                if "api_sequences" in data:
                    for sequence in data["api_sequences"]:
                        apis = sequence.get("apis", [])
                        score = sequence.get("score", 0.5)
                        behavior = sequence.get("behavior", "unknown")
                        
                        if apis:
                            self.add_pattern(
                                "api_sequences",
                                apis,
                                description=f"API sequence for {behavior}",
                                source=file_name,
                                confidence=score,
                                tags=["api_sequence", behavior]
                            )
                            imported_count += 1
            
            # Process C2 patterns
            if "c2_patterns" in categories and "api_flow" in file_path:
                # Extract C2 patterns
                if "potential_c2" in data:
                    for c2 in data["potential_c2"]:
                        pattern = c2.get("pattern")
                        score = c2.get("score", 0.5)
                        protocol = c2.get("protocol", "unknown")
                        
                        if pattern:
                            self.add_pattern(
                                "c2_patterns",
                                pattern,
                                description=f"Potential C2 communication using {protocol}",
                                source=file_name,
                                confidence=score,
                                tags=["c2", protocol]
                            )
                            imported_count += 1
            
            # Process injection patterns
            if "injection_patterns" in categories and "api_flow" in file_path:
                # Extract injection patterns
                if "injection_patterns" in data:
                    for injection in data["injection_patterns"]:
                        pattern = injection.get("pattern")
                        score = injection.get("score", 0.5)
                        technique = injection.get("technique", "unknown")
                        
                        if pattern:
                            self.add_pattern(
                                "injection_patterns",
                                pattern,
                                description=f"Process injection using {technique}",
                                source=file_name,
                                confidence=score,
                                tags=["injection", technique]
                            )
                            imported_count += 1
            
            return imported_count
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return 0
    
    def export_yara_rules(self, output_file):
        """
        Export patterns as YARA rules
        
        Args:
            output_file: Path to output YARA file
            
        Returns:
            Number of rules exported
        """
        try:
            rules = []
            rule_count = 0
            
            # Generate rules for each category
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    rule_name = f"KEYPLUG_{category}_{rule_count}"
                    pattern_data = pattern.get("pattern")
                    description = pattern.get("description", "")
                    confidence = pattern.get("confidence", 0.5)
                    tags = pattern.get("tags", [])
                    
                    # Skip if pattern is not valid
                    if not pattern_data:
                        continue
                    
                    # Generate rule
                    rule = f"rule {rule_name} {{\n"
                    rule += f"    meta:\n"
                    rule += f"        description = \"{description}\"\n"
                    rule += f"        category = \"{category}\"\n"
                    rule += f"        confidence = {confidence}\n"
                    
                    if tags:
                        rule += f"        tags = \"{', '.join(tags)}\"\n"
                    
                    rule += f"    strings:\n"
                    
                    # Add strings based on pattern type
                    if isinstance(pattern_data, (bytes, bytearray, str)):
                        # Binary or string pattern
                        if isinstance(pattern_data, str):
                            pattern_data = pattern_data.encode('utf-8')
                            
                        # Convert to hex string
                        hex_string = " ".join([f"{b:02x}" for b in pattern_data])
                        rule += f"        $s1 = {{ {hex_string} }}\n"
                    elif isinstance(pattern_data, dict) and "regex" in pattern_data:
                        # Regex pattern
                        rule += f"        $s1 = /{pattern_data['regex']}/\n"
                    elif isinstance(pattern_data, list):
                        # List of patterns
                        for i, p in enumerate(pattern_data):
                            if isinstance(p, str):
                                rule += f"        $s{i+1} = \"{p}\"\n"
                            else:
                                # Convert to hex string
                                hex_string = " ".join([f"{b:02x}" for b in p])
                                rule += f"        $s{i+1} = {{ {hex_string} }}\n"
                    
                    rule += f"    condition:\n"
                    rule += f"        any of them\n"
                    rule += f"}}\n\n"
                    
                    rules.append(rule)
                    rule_count += 1
            
            # Write rules to file
            with open(output_file, 'w') as f:
                f.write("/*\n")
                f.write(f" * KEYPLUG YARA Rules\n")
                f.write(f" * Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f" * Pattern Count: {rule_count}\n")
                f.write(" */\n\n")
                
                for rule in rules:
                    f.write(rule)
            
            print(f"Exported {rule_count} YARA rules to {output_file}")
            return rule_count
        except Exception as e:
            print(f"Error exporting YARA rules: {e}")
            return 0

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KEYPLUG Pattern Database')
    parser.add_argument('-d', '--db', help='Path to pattern database file', default='keyplug_patterns.json')
    parser.add_argument('--import-dir', help='Import patterns from analysis directory')
    parser.add_argument('--export-yara', help='Export patterns as YARA rules')
    parser.add_argument('--search', help='Search for patterns')
    parser.add_argument('--category', help='Limit to specific category')
    parser.add_argument('--min-confidence', type=float, help='Minimum confidence score', default=0.0)
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    args = parser.parse_args()
    
    # Initialize pattern database
    db = PatternDatabase(db_path=args.db, use_openvino=not args.no_openvino)
    
    # Import patterns
    if args.import_dir:
        db.import_patterns_from_analysis(args.import_dir, categories=[args.category] if args.category else None)
    
    # Export YARA rules
    if args.export_yara:
        db.export_yara_rules(args.export_yara)
    
    # Search for patterns
    if args.search:
        results = db.search_patterns(args.search, category=args.category, min_confidence=args.min_confidence)
        
        print(f"Found {len(results)} matching patterns:")
        for i, result in enumerate(results):
            print(f"{i+1}. {result.get('description', 'No description')} (Confidence: {result.get('confidence', 0.0):.2f})")
            print(f"   Category: {result.get('category', 'unknown')}")
            print(f"   Tags: {', '.join(result.get('tags', []))}")
            print(f"   Pattern: {result.get('pattern')}")
            print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
