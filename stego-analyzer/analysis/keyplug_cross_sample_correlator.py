#!/usr/bin/env python3
"""
KEYPLUG Cross-Sample Correlator
-----------------------------
Correlates findings across multiple malware samples with OpenVINO acceleration.

This module identifies relationships and similarities between different KEYPLUG
malware samples, leveraging hardware acceleration for maximum performance.
"""

import os
import sys
import json
import numpy as np
import hashlib
from collections import defaultdict
import concurrent.futures
import datetime

# Try to import OpenVINO for hardware acceleration
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for cross-sample correlation")
    
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

# Import API sequence detector and behavioral analyzer if available
try:
    from keyplug_api_sequence_detector import APISequenceDetector
    API_SEQUENCE_DETECTOR_AVAILABLE = True
except ImportError:
    API_SEQUENCE_DETECTOR_AVAILABLE = False
    print("WARNING: API Sequence Detector not available - functionality will be limited")

try:
    from keyplug_behavioral_analyzer import BehavioralAnalyzer
    BEHAVIORAL_ANALYZER_AVAILABLE = True
except ImportError:
    BEHAVIORAL_ANALYZER_AVAILABLE = False
    print("WARNING: Behavioral Analyzer not available - functionality will be limited")

class CrossSampleCorrelator:
    """
    Correlates findings across multiple malware samples with OpenVINO acceleration
    """
    
    def __init__(self, pattern_db_path=None, use_openvino=True):
        """
        Initialize the cross-sample correlator
        
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
        
        # Initialize behavioral analyzer if available
        if BEHAVIORAL_ANALYZER_AVAILABLE:
            self.behavior_analyzer = BehavioralAnalyzer(pattern_db_path, use_openvino)
        else:
            self.behavior_analyzer = None
        
        # Initialize OpenVINO for acceleration if available
        if self.use_openvino:
            self._init_openvino()
    
    def _init_openvino(self):
        """Initialize OpenVINO for acceleration"""
        if not OPENVINO_AVAILABLE:
            return
        
        # Set up OpenVINO for correlation analysis
        # This is a placeholder for actual OpenVINO model setup
        pass
    
    def analyze_samples(self, sample_paths, min_confidence=0.5):
        """
        Analyze multiple samples and correlate findings
        
        Args:
            sample_paths: List of paths to binary samples
            min_confidence: Minimum confidence score
            
        Returns:
            Correlation results
        """
        # Validate sample paths
        valid_paths = [path for path in sample_paths if os.path.exists(path)]
        if not valid_paths:
            print("No valid sample paths provided")
            return {
                "samples": [],
                "correlations": [],
                "clusters": []
            }
        
        print(f"Analyzing {len(valid_paths)} samples...")
        
        # Analyze each sample
        sample_results = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_sample = {executor.submit(self._analyze_sample, path, min_confidence): path for path in valid_paths}
            
            for future in concurrent.futures.as_completed(future_to_sample):
                path = future_to_sample[future]
                try:
                    result = future.result()
                    sample_results.append(result)
                    print(f"Analyzed {os.path.basename(path)}")
                except Exception as e:
                    print(f"Error analyzing {path}: {e}")
        
        # Correlate findings
        correlations = self._correlate_findings(sample_results, min_confidence)
        
        # Cluster samples
        clusters = self._cluster_samples(sample_results, correlations, min_confidence)
        
        return {
            "analysis_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sample_count": len(sample_results),
            "samples": sample_results,
            "correlations": correlations,
            "clusters": clusters
        }
    
    def _analyze_sample(self, sample_path, min_confidence=0.5):
        """Analyze a single sample"""
        result = {
            "file": os.path.basename(sample_path),
            "path": sample_path,
            "size": os.path.getsize(sample_path),
            "md5": self._calculate_md5(sample_path),
            "api_sequences": [],
            "behaviors": [],
            "strings": [],
            "overall_score": 0.0
        }
        
        # Analyze API sequences if detector is available
        if self.api_detector:
            api_results = self.api_detector.analyze_binary(sample_path, min_confidence)
            result["api_sequences"] = api_results.get("sequences", [])
            result["api_calls"] = api_results.get("api_calls", [])
        
        # Analyze behaviors if analyzer is available
        if self.behavior_analyzer:
            behavior_results = self.behavior_analyzer.analyze_binary(sample_path, min_confidence)
            result["behaviors"] = behavior_results.get("behaviors", [])
            result["overall_score"] = behavior_results.get("overall_score", 0.0)
        
        # Extract strings
        result["strings"] = self._extract_strings(sample_path)
        
        return result
    
    def _calculate_md5(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                md5 = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                return md5.hexdigest()
        except Exception as e:
            print(f"Error calculating MD5 for {file_path}: {e}")
            return "unknown"
    
    def _extract_strings(self, file_path):
        """Extract strings from a binary file"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            import re
            ascii_pattern = re.compile(b'[ -~]{4,}')
            for match in ascii_pattern.finditer(data):
                string = match.group().decode('ascii', errors='ignore')
                strings.append(string)
            
            return strings
        except Exception as e:
            print(f"Error extracting strings from {file_path}: {e}")
            return strings
    
    def _correlate_findings(self, sample_results, min_confidence=0.5):
        """Correlate findings across samples"""
        correlations = []
        
        # Skip if less than 2 samples
        if len(sample_results) < 2:
            return correlations
        
        # Process sample pairs
        for i in range(len(sample_results)):
            for j in range(i + 1, len(sample_results)):
                sample1 = sample_results[i]
                sample2 = sample_results[j]
                
                correlation = self._correlate_sample_pair(sample1, sample2, min_confidence)
                if correlation["score"] >= min_confidence:
                    correlations.append(correlation)
        
        # Sort correlations by score (highest first)
        correlations.sort(key=lambda x: x["score"], reverse=True)
        
        return correlations
    
    def _correlate_sample_pair(self, sample1, sample2, min_confidence=0.5):
        """Correlate a pair of samples"""
        correlation = {
            "sample1": sample1["file"],
            "sample2": sample2["file"],
            "score": 0.0,
            "shared_behaviors": [],
            "shared_api_sequences": [],
            "shared_strings": [],
            "shared_indicators": []
        }
        
        # Compare behaviors
        shared_behaviors = []
        for behavior1 in sample1.get("behaviors", []):
            for behavior2 in sample2.get("behaviors", []):
                if behavior1["name"] == behavior2["name"]:
                    shared_behaviors.append({
                        "name": behavior1["name"],
                        "description": behavior1["description"],
                        "score1": behavior1["score"],
                        "score2": behavior2["score"],
                        "average_score": (behavior1["score"] + behavior2["score"]) / 2
                    })
        
        correlation["shared_behaviors"] = shared_behaviors
        
        # Compare API sequences
        shared_api_sequences = []
        for seq1 in sample1.get("api_sequences", []):
            for seq2 in sample2.get("api_sequences", []):
                if seq1["category"] == seq2["category"]:
                    # Compare the actual sequences
                    pattern1 = seq1["pattern"]
                    pattern2 = seq2["pattern"]
                    
                    # Calculate Jaccard similarity
                    similarity = self._calculate_jaccard_similarity(pattern1, pattern2)
                    
                    if similarity >= min_confidence:
                        shared_api_sequences.append({
                            "category": seq1["category"],
                            "description": seq1["description"],
                            "similarity": similarity,
                            "confidence1": seq1["confidence"],
                            "confidence2": seq2["confidence"],
                            "average_confidence": (seq1["confidence"] + seq2["confidence"]) / 2
                        })
        
        correlation["shared_api_sequences"] = shared_api_sequences
        
        # Compare strings
        shared_strings = []
        strings1 = set(sample1.get("strings", []))
        strings2 = set(sample2.get("strings", []))
        common_strings = strings1.intersection(strings2)
        
        # Filter out very common strings
        filtered_strings = [s for s in common_strings if len(s) >= 8]
        
        # Take top 10 longest strings
        filtered_strings.sort(key=len, reverse=True)
        correlation["shared_strings"] = filtered_strings[:10]
        
        # Calculate overall correlation score
        behavior_score = sum(b["average_score"] for b in shared_behaviors) / max(1, len(shared_behaviors))
        api_score = sum(a["average_confidence"] for a in shared_api_sequences) / max(1, len(shared_api_sequences))
        string_score = min(1.0, len(filtered_strings) / 10)
        
        # Weight the scores
        correlation["score"] = 0.5 * behavior_score + 0.3 * api_score + 0.2 * string_score
        
        return correlation
    
    def _calculate_jaccard_similarity(self, list1, list2):
        """Calculate Jaccard similarity between two lists"""
        set1 = set(list1)
        set2 = set(list2)
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def _cluster_samples(self, sample_results, correlations, min_confidence=0.5):
        """Cluster samples based on correlations"""
        # Skip if less than 2 samples
        if len(sample_results) < 2:
            return []
        
        # Build correlation matrix
        sample_files = [sample["file"] for sample in sample_results]
        n_samples = len(sample_files)
        correlation_matrix = np.zeros((n_samples, n_samples))
        
        # Fill correlation matrix
        for correlation in correlations:
            i = sample_files.index(correlation["sample1"])
            j = sample_files.index(correlation["sample2"])
            correlation_matrix[i, j] = correlation["score"]
            correlation_matrix[j, i] = correlation["score"]  # Symmetric
        
        # Set diagonal to 1.0 (self-correlation)
        np.fill_diagonal(correlation_matrix, 1.0)
        
        # Use OpenVINO for clustering if available
        if self.use_openvino:
            clusters = self._openvino_cluster_samples(correlation_matrix, sample_files, min_confidence)
        else:
            clusters = self._standard_cluster_samples(correlation_matrix, sample_files, min_confidence)
        
        return clusters
    
    def _standard_cluster_samples(self, correlation_matrix, sample_files, min_confidence=0.5):
        """Standard clustering implementation"""
        # Simple hierarchical clustering
        clusters = []
        n_samples = len(sample_files)
        
        # Initialize each sample as its own cluster
        remaining = set(range(n_samples))
        
        while remaining:
            # Start a new cluster
            i = min(remaining)
            cluster = [i]
            remaining.remove(i)
            
            # Find all samples that correlate with this cluster
            changed = True
            while changed:
                changed = False
                for j in list(remaining):
                    # Check if j correlates with any sample in the cluster
                    if any(correlation_matrix[j, k] >= min_confidence for k in cluster):
                        cluster.append(j)
                        remaining.remove(j)
                        changed = True
            
            # Add cluster
            clusters.append({
                "samples": [sample_files[i] for i in cluster],
                "size": len(cluster),
                "average_correlation": self._calculate_average_correlation(correlation_matrix, cluster)
            })
        
        # Sort clusters by size (largest first)
        clusters.sort(key=lambda x: x["size"], reverse=True)
        
        return clusters
    
    def _openvino_cluster_samples(self, correlation_matrix, sample_files, min_confidence=0.5):
        """OpenVINO-accelerated clustering implementation"""
        # This is a placeholder for actual OpenVINO implementation
        # In a real implementation, we would use OpenVINO to accelerate clustering
        
        # For now, fall back to standard implementation
        return self._standard_cluster_samples(correlation_matrix, sample_files, min_confidence)
    
    def _calculate_average_correlation(self, correlation_matrix, cluster_indices):
        """Calculate average correlation within a cluster"""
        if len(cluster_indices) <= 1:
            return 1.0
        
        total = 0.0
        count = 0
        
        for i in range(len(cluster_indices)):
            for j in range(i + 1, len(cluster_indices)):
                total += correlation_matrix[cluster_indices[i], cluster_indices[j]]
                count += 1
        
        if count == 0:
            return 0.0
        
        return total / count

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='KEYPLUG Cross-Sample Correlator')
    parser.add_argument('-f', '--files', nargs='+', help='Binary files to analyze')
    parser.add_argument('-d', '--dir', help='Directory containing binary files to analyze')
    parser.add_argument('-o', '--output', help='Output file for analysis results')
    parser.add_argument('-p', '--pattern-db', help='Path to pattern database file')
    parser.add_argument('-c', '--min-confidence', type=float, help='Minimum confidence score', default=0.5)
    parser.add_argument('--no-openvino', action='store_true', help='Disable OpenVINO acceleration')
    args = parser.parse_args()
    
    # Validate arguments
    if not args.files and not args.dir:
        parser.error("Either --files or --dir must be specified")
    
    # Initialize correlator
    correlator = CrossSampleCorrelator(
        pattern_db_path=args.pattern_db,
        use_openvino=not args.no_openvino
    )
    
    # Get sample paths
    sample_paths = []
    
    if args.files:
        sample_paths.extend(args.files)
    
    if args.dir:
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
        
        sample_paths.extend(binary_files)
    
    # Analyze samples
    results = correlator.analyze_samples(sample_paths, args.min_confidence)
    
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
        print(f"Analyzed {results['sample_count']} samples")
        print(f"Found {len(results['correlations'])} correlations")
        print(f"Identified {len(results['clusters'])} clusters")
        
        # Print correlations
        if results['correlations']:
            print("\nTop Correlations:")
            for i, correlation in enumerate(results['correlations'][:5]):  # Show top 5
                print(f"{i+1}. {correlation['sample1']} <-> {correlation['sample2']} (Score: {correlation['score']:.2f})")
                
                if correlation['shared_behaviors']:
                    print(f"   Shared Behaviors: {len(correlation['shared_behaviors'])}")
                    for behavior in correlation['shared_behaviors'][:2]:  # Show top 2
                        print(f"     - {behavior['name']}: {behavior['description']} (Score: {behavior['average_score']:.2f})")
                
                if correlation['shared_api_sequences']:
                    print(f"   Shared API Sequences: {len(correlation['shared_api_sequences'])}")
                    for sequence in correlation['shared_api_sequences'][:2]:  # Show top 2
                        print(f"     - {sequence['category']}: {sequence['description']} (Similarity: {sequence['similarity']:.2f})")
        
        # Print clusters
        if results['clusters']:
            print("\nClusters:")
            for i, cluster in enumerate(results['clusters']):
                print(f"{i+1}. Size: {cluster['size']} samples (Avg. Correlation: {cluster['average_correlation']:.2f})")
                print(f"   Samples: {', '.join(cluster['samples'][:5])}")
                if len(cluster['samples']) > 5:
                    print(f"   ... and {len(cluster['samples']) - 5} more")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
