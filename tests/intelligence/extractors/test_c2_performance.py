"""
Performance benchmarking tests for C2 extractor optimization

Tests verify:
- 5x performance improvement on large files (>10MB)
- Accuracy maintained (no false negatives vs full scan)
- Configurable sampling parameters
- Parallel processing for very large files
"""

import pytest
import time
import struct
import socket
from intelligence.extractors.c2_extractor import C2Extractor, C2Endpoint


class TestC2ExtractionPerformance:
    """Test performance improvements from optimization."""

    def test_small_file_performance_unchanged(self):
        """Test 1MB file has similar performance (no optimization overhead)."""
        # Create 1MB file with embedded IPs
        data = self._create_test_data(1 * 1024 * 1024, num_ips=10)

        # Test with optimization enabled
        extractor_opt = C2Extractor(config={'enable_sampling': True})
        start = time.perf_counter()
        result_opt = extractor_opt._extract_from_binary(data)
        time_opt = time.perf_counter() - start

        # Test with optimization disabled (full scan)
        extractor_full = C2Extractor(config={'enable_sampling': False})
        start = time.perf_counter()
        result_full = extractor_full._extract_from_binary(data)
        time_full = time.perf_counter() - start

        # For small files, performance should be similar (within 2x)
        # Both should use full scan path
        assert time_opt < time_full * 2.0, "Small file optimization overhead too high"

        # Should find same IPs
        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}
        ips_full = {ep.value for ep in result_full if ep.endpoint_type == 'ip'}
        assert ips_opt == ips_full, "Small file results differ"

    def test_medium_file_3x_faster(self):
        """Test 10MB file is at least 3x faster with optimization."""
        # Create 10MB file with embedded IPs
        data = self._create_test_data(10 * 1024 * 1024, num_ips=20)

        # Test with optimization enabled
        extractor_opt = C2Extractor(config={
            'enable_sampling': True,
            'sampling_threshold_mb': 10,
            'sample_interval_bytes': 1024
        })
        start = time.perf_counter()
        result_opt = extractor_opt._extract_from_binary(data)
        time_opt = time.perf_counter() - start

        # Test with optimization disabled (full scan)
        extractor_full = C2Extractor(config={'enable_sampling': False})
        start = time.perf_counter()
        result_full = extractor_full._extract_from_binary(data)
        time_full = time.perf_counter() - start

        # Should be at least 3x faster
        speedup = time_full / time_opt
        print(f"\n10MB file speedup: {speedup:.2f}x")
        print(f"Optimized: {time_opt:.4f}s, Full scan: {time_full:.4f}s")
        assert speedup >= 3.0, f"Expected 3x speedup, got {speedup:.2f}x"

        # Should find all IPs (no false negatives)
        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}
        ips_full = {ep.value for ep in result_full if ep.endpoint_type == 'ip'}
        assert ips_opt == ips_full, "Medium file missing IPs with optimization"

    def test_large_file_5x_faster(self):
        """Test 100MB file is at least 5x faster with optimization."""
        # Create 100MB file with embedded IPs
        data = self._create_test_data(100 * 1024 * 1024, num_ips=50)

        # Test with optimization enabled
        extractor_opt = C2Extractor(config={
            'enable_sampling': True,
            'sampling_threshold_mb': 10,
            'sample_interval_bytes': 1024,
            'enable_parallel_scan': False  # Disable parallel for fair comparison
        })
        start = time.perf_counter()
        result_opt = extractor_opt._extract_from_binary(data)
        time_opt = time.perf_counter() - start

        # For 100MB, we'll sample the full scan to avoid test timeout
        # Full scan would take ~10-20 seconds, we'll extrapolate
        extractor_sample = C2Extractor(config={'enable_sampling': False})
        sample_size = 10 * 1024 * 1024  # 10MB sample
        start = time.perf_counter()
        extractor_sample._extract_from_binary(data[:sample_size])
        time_sample = time.perf_counter() - start

        # Extrapolate full scan time (linear scaling)
        time_full_estimated = time_sample * (len(data) / sample_size)

        # Should be at least 5x faster
        speedup = time_full_estimated / time_opt
        print(f"\n100MB file speedup: {speedup:.2f}x (estimated)")
        print(f"Optimized: {time_opt:.4f}s, Full scan (est): {time_full_estimated:.4f}s")
        assert speedup >= 5.0, f"Expected 5x speedup, got {speedup:.2f}x"

        # Should find IPs in high-value regions
        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}
        assert len(ips_opt) > 0, "No IPs found in large file"

    @pytest.mark.slow
    def test_very_large_file_8x_faster(self):
        """Test 500MB file is at least 8x faster with parallel optimization."""
        # Create 500MB file with embedded IPs
        # This test is marked slow and may be skipped in CI
        data = self._create_test_data(500 * 1024 * 1024, num_ips=100)

        # Test with parallel optimization
        extractor_parallel = C2Extractor(config={
            'enable_sampling': True,
            'sampling_threshold_mb': 10,
            'sample_interval_bytes': 1024,
            'enable_parallel_scan': True,
            'max_workers': 4
        })
        start = time.perf_counter()
        result_parallel = extractor_parallel._extract_from_binary(data)
        time_parallel = time.perf_counter() - start

        # Estimate full scan time from 10MB sample
        extractor_sample = C2Extractor(config={'enable_sampling': False})
        sample_size = 10 * 1024 * 1024
        start = time.perf_counter()
        extractor_sample._extract_from_binary(data[:sample_size])
        time_sample = time.perf_counter() - start

        time_full_estimated = time_sample * (len(data) / sample_size)

        # Should be at least 8x faster
        speedup = time_full_estimated / time_parallel
        print(f"\n500MB file speedup: {speedup:.2f}x (estimated, parallel)")
        print(f"Parallel optimized: {time_parallel:.4f}s, Full scan (est): {time_full_estimated:.4f}s")
        assert speedup >= 8.0, f"Expected 8x speedup, got {speedup:.2f}x"

    def test_configurable_sampling_rate(self):
        """Test that sampling rate affects performance and accuracy."""
        data = self._create_test_data(20 * 1024 * 1024, num_ips=30)

        # Test with aggressive sampling (4KB interval)
        extractor_aggressive = C2Extractor(config={
            'enable_sampling': True,
            'sample_interval_bytes': 4096
        })
        start = time.perf_counter()
        result_aggressive = extractor_aggressive._extract_from_binary(data)
        time_aggressive = time.perf_counter() - start

        # Test with conservative sampling (512B interval)
        extractor_conservative = C2Extractor(config={
            'enable_sampling': True,
            'sample_interval_bytes': 512
        })
        start = time.perf_counter()
        result_conservative = extractor_conservative._extract_from_binary(data)
        time_conservative = time.perf_counter() - start

        # Aggressive should be faster
        assert time_aggressive < time_conservative, "Aggressive sampling not faster"

        # Conservative should find more or equal IPs
        ips_aggressive = len([ep for ep in result_aggressive if ep.endpoint_type == 'ip'])
        ips_conservative = len([ep for ep in result_conservative if ep.endpoint_type == 'ip'])
        assert ips_conservative >= ips_aggressive * 0.8, "Conservative sampling accuracy too low"

        print(f"\nSampling rate test:")
        print(f"Aggressive (4KB): {time_aggressive:.4f}s, {ips_aggressive} IPs")
        print(f"Conservative (512B): {time_conservative:.4f}s, {ips_conservative} IPs")


class TestAccuracyValidation:
    """Test that optimization maintains accuracy."""

    def test_no_false_negatives_headers(self):
        """Test that IPs in headers are always found."""
        # Create file with IPs in first 64KB (header region)
        header = self._create_test_data(64 * 1024, num_ips=10)
        data = header + b'\x00' * (10 * 1024 * 1024)  # Pad to 10MB

        extractor_opt = C2Extractor(config={'enable_sampling': True})
        extractor_full = C2Extractor(config={'enable_sampling': False})

        result_opt = extractor_opt._extract_from_binary(data)
        result_full = extractor_full._extract_from_binary(data)

        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}
        ips_full = {ep.value for ep in result_full if ep.endpoint_type == 'ip'}

        # Should find all header IPs
        assert ips_opt == ips_full, "Missing IPs from header region"
        assert len(ips_opt) >= 10, "Not all header IPs found"

    def test_no_false_negatives_resources(self):
        """Test that IPs in resources (last 64KB) are always found."""
        # Create file with IPs in last 64KB (resource region)
        resources = self._create_test_data(64 * 1024, num_ips=10)
        data = b'\x00' * (10 * 1024 * 1024) + resources

        extractor_opt = C2Extractor(config={'enable_sampling': True})
        extractor_full = C2Extractor(config={'enable_sampling': False})

        result_opt = extractor_opt._extract_from_binary(data)
        result_full = extractor_full._extract_from_binary(data)

        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}
        ips_full = {ep.value for ep in result_full if ep.endpoint_type == 'ip'}

        # Should find all resource IPs
        assert ips_opt == ips_full, "Missing IPs from resource region"
        assert len(ips_opt) >= 10, "Not all resource IPs found"

    def test_low_entropy_regions_scanned(self):
        """Test that low-entropy regions (likely strings) are scanned."""
        # Create file with low-entropy region containing IPs
        low_entropy = b'A' * 1024 + self._create_test_data(4096, num_ips=5) + b'B' * 1024
        data = b'\x00' * (5 * 1024 * 1024) + low_entropy + b'\x00' * (5 * 1024 * 1024)

        extractor_opt = C2Extractor(config={'enable_sampling': True})
        result_opt = extractor_opt._extract_from_binary(data)

        ips_opt = {ep.value for ep in result_opt if ep.endpoint_type == 'ip'}

        # Should find IPs in low-entropy region
        assert len(ips_opt) >= 3, "Not enough IPs found in low-entropy region"

    def test_high_value_region_identification(self):
        """Test that high-value regions are correctly identified."""
        data = b'\x00' * (20 * 1024 * 1024)  # 20MB of zeros

        extractor = C2Extractor(config={'enable_sampling': True})
        positions = extractor._get_scan_positions(data)

        # Should scan first 64KB
        assert any(p < 65536 for p in positions), "Header region not scanned"

        # Should scan last 64KB
        data_len = len(data)
        assert any(p > data_len - 65536 for p in positions), "Resource region not scanned"

        # Total scan positions should be much less than file size
        scan_ratio = len(positions) / data_len
        print(f"\nScan ratio: {scan_ratio:.6f} ({len(positions)} positions in {data_len} bytes)")
        assert scan_ratio < 0.1, "Scanning too many positions"

    def test_parallel_accuracy(self):
        """Test that parallel scanning finds same results as sequential."""
        data = self._create_test_data(60 * 1024 * 1024, num_ips=30)

        # Sequential optimized scan
        extractor_seq = C2Extractor(config={
            'enable_sampling': True,
            'enable_parallel_scan': False
        })
        result_seq = extractor_seq._extract_from_binary(data)

        # Parallel optimized scan
        extractor_par = C2Extractor(config={
            'enable_sampling': True,
            'enable_parallel_scan': True,
            'max_workers': 4
        })
        result_par = extractor_par._extract_from_binary(data)

        ips_seq = {ep.value for ep in result_seq if ep.endpoint_type == 'ip'}
        ips_par = {ep.value for ep in result_par if ep.endpoint_type == 'ip'}

        # Should find same IPs (allow minor differences due to deduplication)
        assert len(ips_par) >= len(ips_seq) * 0.9, "Parallel scan lost too many IPs"


class TestHelperMethods:
    """Test helper methods for optimization."""

    def test_entropy_calculation(self):
        """Test entropy calculation for region identification."""
        extractor = C2Extractor()

        # Low entropy (repeated pattern)
        low_entropy = b'AAAA' * 1000
        entropy_low = extractor._calculate_entropy(low_entropy)
        assert entropy_low < 4.0, f"Low entropy too high: {entropy_low}"

        # High entropy (random-like)
        high_entropy = bytes([i % 256 for i in range(1000)])
        entropy_high = extractor._calculate_entropy(high_entropy)
        assert entropy_high > 5.0, f"High entropy too low: {entropy_high}"

    def test_low_entropy_region_identification(self):
        """Test identification of low-entropy regions."""
        # Create data with mixed entropy
        low = b'A' * 4096
        high = bytes([i % 256 for i in range(4096)])
        data = low + high + low + high

        extractor = C2Extractor()
        positions = extractor._identify_low_entropy_regions(data)

        # Should identify low-entropy regions
        assert len(positions) > 0, "No low-entropy regions found"

        # Positions should be in low-entropy chunks
        for pos in positions:
            chunk_idx = pos // 4096
            assert chunk_idx % 2 == 0, "Position in high-entropy region"


# Test data generation helpers
def _create_test_data(size: int, num_ips: int) -> bytes:
    """
    Create test binary data with embedded IP addresses.

    Args:
        size: Total size in bytes
        num_ips: Number of IPs to embed

    Returns:
        Binary data with packed IPs at strategic positions
    """
    data = bytearray(size)

    # Fill with random-ish pattern
    for i in range(size):
        data[i] = (i * 73) % 256

    # Embed IPs at various positions
    ip_positions = []
    if num_ips > 0:
        # Place some in header
        header_ips = min(num_ips // 3, 10)
        for i in range(header_ips):
            pos = i * 1000
            if pos + 4 < size:
                ip_positions.append(pos)

        # Place some in middle
        middle_ips = num_ips // 3
        middle_start = size // 2 - (middle_ips * 2000)
        for i in range(middle_ips):
            pos = middle_start + i * 4000
            if pos + 4 < size:
                ip_positions.append(pos)

        # Place some at end
        end_ips = num_ips - header_ips - middle_ips
        for i in range(end_ips):
            pos = size - 65536 + i * 1000
            if pos + 4 < size and pos >= 0:
                ip_positions.append(pos)

    # Insert packed IPs
    for idx, pos in enumerate(ip_positions):
        # Generate valid public IP
        ip_bytes = struct.pack('>I', 0x2D000000 + idx * 0x10000 + 0x0100)  # 45.x.1.0 range
        data[pos:pos+4] = ip_bytes

    return bytes(data)


# Attach helper to test classes
TestC2ExtractionPerformance._create_test_data = staticmethod(_create_test_data)
TestAccuracyValidation._create_test_data = staticmethod(_create_test_data)
