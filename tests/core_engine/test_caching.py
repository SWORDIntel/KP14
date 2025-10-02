"""
Comprehensive tests for KP14 caching functionality.

Tests cache_manager, file_hasher, and integration with pipeline_manager.
"""

import os
import pytest
import tempfile
import time
import hashlib
from pathlib import Path

from core_engine.cache_manager import (
    LRUCache,
    FileHashCache,
    PEHeaderCache,
    MLInferenceCache,
    PatternMatchCache,
    PersistentCache,
    CacheManager,
    cached,
    get_cache_manager,
)
from core_engine.file_hasher import FileHasher, get_file_hasher, quick_hash


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def temp_cache_dir():
    """Create temporary cache directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_test_file():
    """Create temporary test file."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'Test file content for caching tests\n' * 100)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.remove(temp_path)


@pytest.fixture
def cache_manager(temp_cache_dir):
    """Create cache manager with temp directory."""
    return CacheManager(cache_dir=temp_cache_dir, enable_persistent=True)


@pytest.fixture
def file_hasher(cache_manager):
    """Create file hasher with cache manager."""
    return FileHasher(cache_manager=cache_manager)


# ============================================================================
# LRU Cache Tests
# ============================================================================


class TestLRUCache:
    """Test LRU cache functionality."""

    def test_basic_get_put(self):
        """Test basic cache get/put operations."""
        cache = LRUCache(max_size=10, ttl=60)

        # Put and get
        cache.put('key1', 'value1')
        assert cache.get('key1') == 'value1'

        # Miss
        assert cache.get('nonexistent') is None

    def test_lru_eviction(self):
        """Test LRU eviction policy."""
        cache = LRUCache(max_size=3, ttl=60)

        # Fill cache
        cache.put('key1', 'value1')
        cache.put('key2', 'value2')
        cache.put('key3', 'value3')

        # Add one more (should evict key1)
        cache.put('key4', 'value4')

        assert cache.get('key1') is None  # Evicted
        assert cache.get('key2') == 'value2'
        assert cache.get('key3') == 'value3'
        assert cache.get('key4') == 'value4'

    def test_ttl_expiration(self):
        """Test TTL expiration."""
        cache = LRUCache(max_size=10, ttl=1)  # 1 second TTL

        cache.put('key1', 'value1')
        assert cache.get('key1') == 'value1'

        # Wait for expiration
        time.sleep(1.5)

        assert cache.get('key1') is None  # Expired

    def test_statistics(self):
        """Test cache statistics."""
        cache = LRUCache(max_size=10, ttl=60)

        # Generate hits and misses
        cache.put('key1', 'value1')
        cache.get('key1')  # Hit
        cache.get('key1')  # Hit
        cache.get('key2')  # Miss
        cache.get('key3')  # Miss

        stats = cache.get_stats()
        assert stats['hits'] == 2
        assert stats['misses'] == 2
        assert stats['hit_rate'] == 0.5
        assert stats['size'] == 1

    def test_invalidate(self):
        """Test cache invalidation."""
        cache = LRUCache(max_size=10, ttl=60)

        cache.put('key1', 'value1')
        assert cache.get('key1') == 'value1'

        cache.invalidate('key1')
        assert cache.get('key1') is None

    def test_clear(self):
        """Test cache clearing."""
        cache = LRUCache(max_size=10, ttl=60)

        cache.put('key1', 'value1')
        cache.put('key2', 'value2')

        cache.clear()

        assert cache.get('key1') is None
        assert cache.get('key2') is None
        assert cache.get_stats()['size'] == 0


# ============================================================================
# File Hash Cache Tests
# ============================================================================


class TestFileHashCache:
    """Test file hash caching."""

    def test_file_hash_caching(self, temp_test_file):
        """Test file hash calculation with caching."""
        cache = FileHashCache(max_size=10, ttl=60)

        # First call (cache miss)
        hash1 = cache.get_file_hash(temp_test_file, 'sha256')
        assert hash1 is not None
        assert len(hash1) == 64  # SHA256 hex digest length

        # Second call (cache hit)
        hash2 = cache.get_file_hash(temp_test_file, 'sha256')
        assert hash2 == hash1

        # Check statistics
        stats = cache.get_stats()
        assert stats['hits'] >= 1
        assert stats['hit_rate'] > 0

    def test_file_modification_detection(self, temp_test_file):
        """Test cache invalidation on file modification."""
        cache = FileHashCache(max_size=10, ttl=60)

        # Get initial hash
        hash1 = cache.get_file_hash(temp_test_file, 'sha256')

        # Modify file
        with open(temp_test_file, 'ab') as f:
            f.write(b'Modified content')

        # Get hash again (should recalculate due to mtime change)
        hash2 = cache.get_file_hash(temp_test_file, 'sha256')
        assert hash2 != hash1

    def test_multiple_algorithms(self, temp_test_file):
        """Test caching with different hash algorithms."""
        cache = FileHashCache(max_size=10, ttl=60)

        hash_md5 = cache.get_file_hash(temp_test_file, 'md5')
        hash_sha1 = cache.get_file_hash(temp_test_file, 'sha1')
        hash_sha256 = cache.get_file_hash(temp_test_file, 'sha256')

        assert len(hash_md5) == 32
        assert len(hash_sha1) == 40
        assert len(hash_sha256) == 64


# ============================================================================
# File Hasher Tests
# ============================================================================


class TestFileHasher:
    """Test FileHasher class."""

    def test_get_file_hash(self, file_hasher, temp_test_file):
        """Test basic file hashing."""
        hash1 = file_hasher.get_file_hash(temp_test_file, 'sha256')
        assert hash1 is not None
        assert len(hash1) == 64

    def test_caching_speedup(self, file_hasher, temp_test_file):
        """Test caching provides speedup."""
        # First call (cold cache)
        start = time.time()
        hash1 = file_hasher.get_file_hash(temp_test_file, 'sha256', use_cache=True)
        time1 = time.time() - start

        # Second call (warm cache)
        start = time.time()
        hash2 = file_hasher.get_file_hash(temp_test_file, 'sha256', use_cache=True)
        time2 = time.time() - start

        assert hash1 == hash2
        # Cache should be at least 2x faster (usually much more)
        assert time2 < time1 / 2

    def test_multiple_hashes(self, file_hasher, temp_test_file):
        """Test calculating multiple hashes."""
        hashes = file_hasher.get_multiple_hashes(
            temp_test_file,
            algorithms=['md5', 'sha1', 'sha256']
        )

        assert 'md5' in hashes
        assert 'sha1' in hashes
        assert 'sha256' in hashes
        assert len(hashes['md5']) == 32
        assert len(hashes['sha1']) == 40
        assert len(hashes['sha256']) == 64

    def test_file_info(self, file_hasher, temp_test_file):
        """Test getting comprehensive file info."""
        info = file_hasher.get_file_info(temp_test_file)

        assert 'path' in info
        assert 'size' in info
        assert 'mtime' in info
        assert 'md5' in info
        assert 'sha1' in info
        assert 'sha256' in info

        assert info['path'] == temp_test_file
        assert info['size'] > 0

    def test_verify_integrity(self, file_hasher, temp_test_file):
        """Test file integrity verification."""
        # Get actual hash
        actual_hash = file_hasher.get_file_hash(temp_test_file, 'sha256')

        # Verify with correct hash
        is_valid, returned_hash = file_hasher.verify_file_integrity(
            temp_test_file, actual_hash, 'sha256'
        )
        assert is_valid is True
        assert returned_hash == actual_hash

        # Verify with wrong hash
        is_valid, returned_hash = file_hasher.verify_file_integrity(
            temp_test_file, 'wrong_hash', 'sha256'
        )
        assert is_valid is False

    def test_unsupported_algorithm(self, file_hasher, temp_test_file):
        """Test error handling for unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            file_hasher.get_file_hash(temp_test_file, 'unsupported_algo')

    def test_nonexistent_file(self, file_hasher):
        """Test error handling for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            file_hasher.get_file_hash('/nonexistent/file.txt', 'sha256')


# ============================================================================
# Persistent Cache Tests
# ============================================================================


class TestPersistentCache:
    """Test persistent disk-backed caching."""

    def test_basic_persistence(self, temp_cache_dir):
        """Test basic put/get with persistence."""
        cache = PersistentCache(cache_dir=temp_cache_dir, max_size_mb=10)

        # Put value
        cache.put('test_key', {'data': 'test_value'})

        # Get value
        result = cache.get('test_key')
        assert result == {'data': 'test_value'}

    def test_persistence_across_instances(self, temp_cache_dir):
        """Test data persists across cache instances."""
        # First instance
        cache1 = PersistentCache(cache_dir=temp_cache_dir, max_size_mb=10)
        cache1.put('persist_key', {'important': 'data'})

        # Second instance (simulates restart)
        cache2 = PersistentCache(cache_dir=temp_cache_dir, max_size_mb=10)
        result = cache2.get('persist_key')
        assert result == {'important': 'data'}

    def test_clear(self, temp_cache_dir):
        """Test clearing persistent cache."""
        cache = PersistentCache(cache_dir=temp_cache_dir, max_size_mb=10)

        cache.put('key1', 'value1')
        cache.put('key2', 'value2')

        cache.clear()

        assert cache.get('key1') is None
        assert cache.get('key2') is None


# ============================================================================
# Cache Manager Tests
# ============================================================================


class TestCacheManager:
    """Test unified cache manager."""

    def test_initialization(self, temp_cache_dir):
        """Test cache manager initialization."""
        mgr = CacheManager(cache_dir=temp_cache_dir, enable_persistent=True)

        assert mgr.file_hash_cache is not None
        assert mgr.pe_header_cache is not None
        assert mgr.ml_inference_cache is not None
        assert mgr.pattern_match_cache is not None
        assert mgr.persistent_cache is not None

    def test_file_hash_caching(self, cache_manager, temp_test_file):
        """Test file hash caching through manager."""
        hash1 = cache_manager.get_file_hash(temp_test_file, 'sha256')
        hash2 = cache_manager.get_file_hash(temp_test_file, 'sha256')

        assert hash1 == hash2

        stats = cache_manager.get_stats()
        assert stats['file_hash']['hits'] >= 1

    def test_aggregate_statistics(self, cache_manager, temp_test_file):
        """Test aggregate statistics."""
        # Generate some cache activity
        cache_manager.get_file_hash(temp_test_file, 'sha256')
        cache_manager.get_file_hash(temp_test_file, 'sha256')  # Hit
        cache_manager.get_file_hash(temp_test_file, 'md5')

        agg_stats = cache_manager.get_aggregate_stats()

        assert 'total_requests' in agg_stats
        assert 'total_hits' in agg_stats
        assert 'total_misses' in agg_stats
        assert 'overall_hit_rate' in agg_stats
        assert agg_stats['total_requests'] > 0

    def test_clear_all(self, cache_manager, temp_test_file):
        """Test clearing all caches."""
        # Add some data to caches
        cache_manager.get_file_hash(temp_test_file, 'sha256')

        # Clear all
        cache_manager.clear_all()

        # Verify caches are empty
        stats = cache_manager.get_stats()
        for cache_stats in stats.values():
            assert cache_stats['size'] == 0
            assert cache_stats['hits'] == 0
            assert cache_stats['misses'] == 0


# ============================================================================
# Cached Decorator Tests
# ============================================================================


class TestCachedDecorator:
    """Test @cached decorator."""

    def test_basic_caching(self):
        """Test basic function caching."""
        call_count = [0]

        @cached(ttl=60)
        def expensive_function(x):
            call_count[0] += 1
            return x * x

        # First call
        result1 = expensive_function(5)
        assert result1 == 25
        assert call_count[0] == 1

        # Second call (should use cache)
        result2 = expensive_function(5)
        assert result2 == 25
        assert call_count[0] == 1  # Not called again

        # Different argument (cache miss)
        result3 = expensive_function(6)
        assert result3 == 36
        assert call_count[0] == 2

    def test_custom_key_pattern(self):
        """Test decorator with custom key pattern."""
        call_count = [0]

        @cached(ttl=60, key_pattern='custom:{0}')
        def custom_key_function(value):
            call_count[0] += 1
            return value * 2

        # First call
        result1 = custom_key_function(10)
        assert result1 == 20
        assert call_count[0] == 1

        # Second call (cached)
        result2 = custom_key_function(10)
        assert result2 == 20
        assert call_count[0] == 1

    def test_cache_statistics(self):
        """Test accessing cache statistics."""
        @cached(ttl=60)
        def cached_function(x):
            return x + 1

        # Generate some cache activity
        cached_function(1)
        cached_function(1)  # Hit
        cached_function(2)

        # Access cache stats
        stats = cached_function._cache_stats()
        assert stats['hits'] >= 1
        assert stats['misses'] >= 1

    def test_cache_clear(self):
        """Test clearing decorator cache."""
        @cached(ttl=60)
        def cached_function(x):
            return x * 3

        # Add to cache
        cached_function(5)
        assert cached_function._cache.get_stats()['size'] == 1

        # Clear cache
        cached_function._cache_clear()
        assert cached_function._cache.get_stats()['size'] == 0


# ============================================================================
# Integration Tests
# ============================================================================


class TestCachingIntegration:
    """Test caching integration scenarios."""

    def test_pipeline_caching_scenario(self, cache_manager, temp_test_file):
        """Test realistic pipeline caching scenario."""
        # Simulate pipeline operations
        file_hash = cache_manager.get_file_hash(temp_test_file, 'sha256')

        # Simulate PE header caching
        def parse_pe_mock(path):
            return {'pe_type': 'PE32', 'sections': 3}

        pe_info = cache_manager.get_pe_info(temp_test_file, parse_pe_mock)
        assert pe_info is not None

        # Get again (should be cached)
        pe_info2 = cache_manager.get_pe_info(temp_test_file, parse_pe_mock)
        assert pe_info2 == pe_info

        # Check statistics
        stats = cache_manager.get_aggregate_stats()
        assert stats['overall_hit_rate'] > 0

    def test_high_cache_hit_rate(self, cache_manager, temp_test_file):
        """Test achieving high cache hit rate."""
        # Perform repeated operations
        for _ in range(10):
            cache_manager.get_file_hash(temp_test_file, 'sha256')

        stats = cache_manager.get_aggregate_stats()

        # Should achieve >80% hit rate
        assert stats['overall_hit_rate'] >= 0.8


# ============================================================================
# Performance Benchmarks
# ============================================================================


class TestCachingPerformance:
    """Performance benchmarks for caching."""

    def test_cache_speedup_benchmark(self, file_hasher, temp_test_file):
        """Benchmark cache speedup (target: 10×)."""
        # Cold cache (first run)
        start = time.time()
        hash1 = file_hasher.get_file_hash(temp_test_file, 'sha256', use_cache=False)
        cold_time = time.time() - start

        # Warm up cache
        file_hasher.get_file_hash(temp_test_file, 'sha256', use_cache=True)

        # Warm cache (second run)
        start = time.time()
        hash2 = file_hasher.get_file_hash(temp_test_file, 'sha256', use_cache=True)
        warm_time = time.time() - start

        assert hash1 == hash2

        speedup = cold_time / warm_time if warm_time > 0 else 0
        print(f"\nCache speedup: {speedup:.1f}×")
        print(f"Cold: {cold_time:.4f}s, Warm: {warm_time:.4f}s")

        # Should be at least 10× faster (typically much more)
        assert speedup >= 10.0

    def test_cache_memory_efficiency(self, temp_cache_dir):
        """Test cache memory efficiency."""
        cache = LRUCache(max_size=100, ttl=60)

        # Fill cache
        for i in range(100):
            cache.put(f'key{i}', f'value{i}')

        stats = cache.get_stats()
        assert stats['size'] == 100

        # Add more (should evict old entries)
        for i in range(100, 120):
            cache.put(f'key{i}', f'value{i}')

        stats = cache.get_stats()
        assert stats['size'] == 100  # Still at max size


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
