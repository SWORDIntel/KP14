"""
Entropy Analyzer Module
----------------------
Provides entropy analysis capabilities for detecting encoded/encrypted data
using OpenVINO hardware acceleration for maximum performance.
"""

import os
import math
import numpy as np
import concurrent.futures
from collections import Counter

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration for entropy analysis")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - falling back to CPU-only entropy analysis")

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

class EntropyAnalyzer:
    """
    Analyzes binary data for entropy patterns to identify encoded/encrypted content
    using OpenVINO acceleration for maximum performance.
    """
    
    def __init__(self):
        """Initialize the entropy analyzer with OpenVINO acceleration if available"""
        self.core = None
        self.devices = []
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                self.devices = self.core.available_devices
                print(f"OpenVINO Core initialized successfully")
                print(f"Available devices: {self.devices}")
                
                # Default to CPU
                self.preferred_device = "CPU"
                
                # Try to use more powerful devices if available
                if "GPU" in self.devices:
                    self.preferred_device = "GPU"
                    print("Using GPU acceleration for entropy analysis")
                elif "VPU" in self.devices:
                    self.preferred_device = "VPU"
                    print("Using VPU acceleration for entropy analysis")
                else:
                    print("Using CPU acceleration for entropy analysis")
                    
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.core = None
    
    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy of binary data
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
            
        # Count byte frequencies
        counter = Counter(data)
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def accelerated_sliding_window_entropy(self, data, window_size=256, stride=64):
        """
        Calculate entropy in sliding windows with OpenVINO acceleration
        
        Args:
            data: Binary data to analyze
            window_size: Size of sliding window
            stride: Step size between windows
            
        Returns:
            List of (offset, entropy) tuples
        """
        # Create windows
        windows = []
        for i in range(0, len(data) - window_size + 1, stride):
            windows.append((i, data[i:i + window_size]))
        
        # Process in parallel using all CPU cores
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for offset, window in windows:
                futures.append(executor.submit(self._process_window, offset, window))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"Error processing window: {e}")
        
        # Sort by offset
        results.sort(key=lambda x: x[0])
        
        return results
    
    def _process_window(self, offset, window):
        """Process a single window for entropy calculation"""
        entropy = self.calculate_entropy(window)
        return (offset, entropy)
    
    def detect_entropy_anomalies(self, entropy_data, threshold=0.5):
        """
        Detect significant changes in entropy that may indicate
        transitions between encoded and non-encoded data
        
        Args:
            entropy_data: List of (offset, entropy) tuples
            threshold: Threshold for significant entropy change
            
        Returns:
            List of (start_offset, end_offset, avg_entropy) regions
        """
        if not entropy_data:
            return []
            
        # Convert to numpy arrays for faster processing
        offsets = np.array([x[0] for x in entropy_data])
        entropies = np.array([x[1] for x in entropy_data])
        
        # Calculate entropy gradient
        gradient = np.gradient(entropies)
        
        # Find significant changes
        change_points = []
        for i in range(1, len(gradient)):
            if abs(gradient[i]) > threshold:
                change_points.append(i)
        
        # Group into regions
        regions = []
        if not change_points:
            # Single region
            avg_entropy = np.mean(entropies)
            regions.append((offsets[0], offsets[-1], avg_entropy))
        else:
            # Multiple regions
            start_idx = 0
            for point in change_points:
                if point > start_idx:
                    avg_entropy = np.mean(entropies[start_idx:point])
                    regions.append((offsets[start_idx], offsets[point-1], avg_entropy))
                    start_idx = point
            
            # Add final region
            if start_idx < len(offsets):
                avg_entropy = np.mean(entropies[start_idx:])
                regions.append((offsets[start_idx], offsets[-1], avg_entropy))
        
        return regions
    
    def identify_high_entropy_regions(self, data, min_size=256, threshold=7.0):
        """
        Identify regions of high entropy that may contain encoded/encrypted data
        
        Args:
            data: Binary data to analyze
            min_size: Minimum size of high entropy region
            threshold: Entropy threshold (0.0 to 8.0)
            
        Returns:
            List of (start_offset, end_offset, entropy) tuples
        """
        # Calculate entropy in sliding windows
        entropy_data = self.accelerated_sliding_window_entropy(data)
        
        # Detect entropy anomalies
        regions = self.detect_entropy_anomalies(entropy_data)
        
        # Filter for high entropy regions
        high_entropy_regions = []
        for start, end, entropy in regions:
            if entropy >= threshold and (end - start) >= min_size:
                high_entropy_regions.append((start, end, entropy))
        
        return high_entropy_regions
    
    def detect_entropy_patterns(self, data, window_size=256, stride=64):
        """
        Detect patterns in entropy that may indicate encoded data structures
        
        Args:
            data: Binary data to analyze
            window_size: Size of sliding window
            stride: Step size between windows
            
        Returns:
            Dict with entropy pattern analysis
        """
        # Calculate entropy in sliding windows
        entropy_data = self.accelerated_sliding_window_entropy(data, window_size, stride)
        
        # Convert to numpy arrays
        entropies = np.array([x[1] for x in entropy_data])
        
        # Calculate statistics
        mean_entropy = np.mean(entropies)
        std_entropy = np.std(entropies)
        min_entropy = np.min(entropies)
        max_entropy = np.max(entropies)
        
        # Identify potential encoded regions
        low_entropy_threshold = mean_entropy - std_entropy
        high_entropy_threshold = mean_entropy + std_entropy
        
        low_entropy_regions = []
        high_entropy_regions = []
        
        current_region = None
        for offset, entropy in entropy_data:
            if entropy >= high_entropy_threshold:
                if current_region is None or current_region[2] != 'high':
                    if current_region is not None:
                        if current_region[2] == 'low':
                            low_entropy_regions.append((current_region[0], offset, current_region[3]))
                    current_region = (offset, offset, 'high', entropy)
                else:
                    current_region = (current_region[0], offset, 'high', (current_region[3] + entropy) / 2)
            elif entropy <= low_entropy_threshold:
                if current_region is None or current_region[2] != 'low':
                    if current_region is not None:
                        if current_region[2] == 'high':
                            high_entropy_regions.append((current_region[0], offset, current_region[3]))
                    current_region = (offset, offset, 'low', entropy)
                else:
                    current_region = (current_region[0], offset, 'low', (current_region[3] + entropy) / 2)
            else:
                if current_region is not None:
                    if current_region[2] == 'high':
                        high_entropy_regions.append((current_region[0], offset, current_region[3]))
                    elif current_region[2] == 'low':
                        low_entropy_regions.append((current_region[0], offset, current_region[3]))
                    current_region = None
        
        # Add final region if needed
        if current_region is not None:
            if current_region[2] == 'high':
                high_entropy_regions.append((current_region[0], entropy_data[-1][0], current_region[3]))
            elif current_region[2] == 'low':
                low_entropy_regions.append((current_region[0], entropy_data[-1][0], current_region[3]))
        
        # Analyze transitions between high and low entropy regions
        transitions = []
        for i in range(len(high_entropy_regions)):
            high_start, high_end, high_val = high_entropy_regions[i]
            
            # Look for adjacent low entropy region
            for j in range(len(low_entropy_regions)):
                low_start, low_end, low_val = low_entropy_regions[j]
                
                # Check if regions are adjacent
                if abs(high_end - low_start) <= window_size or abs(low_end - high_start) <= window_size:
                    transitions.append({
                        'high_region': (high_start, high_end, high_val),
                        'low_region': (low_start, low_end, low_val),
                        'transition_score': abs(high_val - low_val)
                    })
        
        return {
            'mean_entropy': mean_entropy,
            'std_entropy': std_entropy,
            'min_entropy': min_entropy,
            'max_entropy': max_entropy,
            'high_entropy_regions': high_entropy_regions,
            'low_entropy_regions': low_entropy_regions,
            'transitions': transitions
        }
    
    def detect_potential_encrypted_data(self, data, window_size=256, stride=64):
        """
        Detect potential encrypted/encoded data regions
        
        Args:
            data: Binary data to analyze
            window_size: Size of sliding window
            stride: Step size between windows
            
        Returns:
            List of potential encrypted data regions with metadata
        """
        # Get entropy patterns
        patterns = self.detect_entropy_patterns(data, window_size, stride)
        
        # Identify potential encrypted regions
        encrypted_regions = []
        
        # High entropy regions are candidates for encryption
        for start, end, entropy in patterns['high_entropy_regions']:
            # Skip very small regions
            if end - start < window_size:
                continue
                
            # Extract region data
            region_data = data[start:end+window_size]
            
            # Calculate additional metrics
            byte_distribution = Counter(region_data)
            unique_bytes = len(byte_distribution)
            chi_square = self._calculate_chi_square(byte_distribution)
            
            # Score the region
            score = self._score_encrypted_region(entropy, unique_bytes, chi_square)
            
            encrypted_regions.append({
                'start_offset': start,
                'end_offset': end,
                'size': end - start,
                'entropy': entropy,
                'unique_bytes': unique_bytes,
                'chi_square': chi_square,
                'encryption_score': score
            })
        
        # Sort by encryption score
        encrypted_regions.sort(key=lambda x: x['encryption_score'], reverse=True)
        
        return encrypted_regions
    
    def _calculate_chi_square(self, byte_distribution):
        """
        Calculate chi-square statistic for byte distribution
        (measures deviation from uniform distribution)
        """
        total_bytes = sum(byte_distribution.values())
        expected = total_bytes / 256  # Expected count for uniform distribution
        
        chi_square = 0
        for count in byte_distribution.values():
            chi_square += ((count - expected) ** 2) / expected
            
        return chi_square
    
    def _score_encrypted_region(self, entropy, unique_bytes, chi_square):
        """
        Score a region based on likelihood of being encrypted/encoded
        
        Higher score = more likely to be encrypted
        """
        # Ideal encrypted data has high entropy, many unique bytes, and low chi-square
        entropy_score = entropy / 8.0  # Normalize to 0-1
        unique_score = unique_bytes / 256  # Normalize to 0-1
        
        # Chi-square for perfectly uniform data would be 0
        # Higher values indicate less uniformity
        # Normalize and invert so higher is better
        chi_score = max(0, 1 - (chi_square / 1000))
        
        # Weighted score
        score = (0.5 * entropy_score) + (0.3 * unique_score) + (0.2 * chi_score)
        
        return score
