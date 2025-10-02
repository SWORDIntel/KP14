"""
Cache Manager for KP14 Analysis Framework
==========================================

Provides comprehensive caching for:
- File hash calculations
- Parsed PE headers
- ML model inferences
- Pattern matches
- Analysis results

Features:
- LRU caching with configurable size limits
- TTL (time-to-live) for cache entries
- Cache invalidation
- Memory-efficient storage
- Thread-safe operations
- Cache statistics and monitoring

Author: KP14 Development Team
Version: 1.0.0
"""

import hashlib
import json
import logging
import os
import pickle
import threading
import time
import weakref
from collections import OrderedDict
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Union


# ============================================================================
# LRU Cache Implementation
# ============================================================================


class LRUCache:
    """Thread-safe LRU cache with TTL support."""

    def __init__(self, max_size: int = 1000, ttl: Optional[int] = 3600):
        """
        Initialize LRU cache.

        Args:
            max_size: Maximum number of entries
            ttl: Time-to-live in seconds (None for no expiration)
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found or expired
        """
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None

            # Check if expired
            if self.ttl is not None:
                age = time.time() - self.timestamps[key]
                if age > self.ttl:
                    self._remove(key)
                    self.misses += 1
                    return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.hits += 1
            return self.cache[key]

    def put(self, key: str, value: Any):
        """
        Put value into cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self.lock:
            # Remove oldest if at capacity
            if key not in self.cache and len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                self._remove(oldest_key)

            # Add or update
            self.cache[key] = value
            self.timestamps[key] = time.time()
            self.cache.move_to_end(key)

    def _remove(self, key: str):
        """Remove entry from cache."""
        if key in self.cache:
            del self.cache[key]
            del self.timestamps[key]

    def invalidate(self, key: str):
        """
        Invalidate cache entry.

        Args:
            key: Cache key to invalidate
        """
        with self.lock:
            self._remove(key)

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
            self.hits = 0
            self.misses = 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = self.hits / total_requests if total_requests > 0 else 0.0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate,
                "ttl": self.ttl,
            }


# ============================================================================
# Specialized Cache Types
# ============================================================================


class FileHashCache(LRUCache):
    """Cache for file hash calculations."""

    def __init__(self, max_size: int = 500, ttl: int = 3600):
        super().__init__(max_size, ttl)
        self.logger = logging.getLogger(__name__ + ".FileHashCache")

    def get_file_hash(
        self, file_path: str, algorithm: str = "sha256", chunk_size: int = 8192
    ) -> str:
        """
        Get file hash with caching.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, etc.)
            chunk_size: Size of chunks to read

        Returns:
            Hex digest of file hash
        """
        # Create cache key from file path, mtime, and size
        try:
            stat = os.stat(file_path)
            cache_key = f"{file_path}:{algorithm}:{stat.st_mtime}:{stat.st_size}"
        except OSError as e:
            self.logger.warning(f"Could not stat file {file_path}: {e}")
            cache_key = f"{file_path}:{algorithm}"

        # Check cache
        cached_hash = self.get(cache_key)
        if cached_hash:
            return cached_hash

        # Calculate hash
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()

            # Cache result
            self.put(cache_key, file_hash)
            return file_hash

        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            raise


class PEHeaderCache(LRUCache):
    """Cache for parsed PE headers."""

    def __init__(self, max_size: int = 200, ttl: int = 3600):
        super().__init__(max_size, ttl)
        self.logger = logging.getLogger(__name__ + ".PEHeaderCache")

    def get_pe_info(
        self, file_path: str, parse_func: Optional[Callable] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get parsed PE information with caching.

        Args:
            file_path: Path to PE file
            parse_func: Function to parse PE if not cached

        Returns:
            Parsed PE information dictionary
        """
        # Create cache key from file path and mtime
        try:
            stat = os.stat(file_path)
            cache_key = f"{file_path}:pe:{stat.st_mtime}:{stat.st_size}"
        except OSError:
            cache_key = f"{file_path}:pe"

        # Check cache
        cached_info = self.get(cache_key)
        if cached_info:
            return cached_info

        # Parse PE if function provided
        if parse_func:
            try:
                pe_info = parse_func(file_path)
                self.put(cache_key, pe_info)
                return pe_info
            except Exception as e:
                self.logger.error(f"Error parsing PE {file_path}: {e}")
                return None

        return None


class MLInferenceCache(LRUCache):
    """Cache for ML model inferences."""

    def __init__(self, max_size: int = 1000, ttl: int = 7200):
        super().__init__(max_size, ttl)
        self.logger = logging.getLogger(__name__ + ".MLInferenceCache")

    def get_inference(
        self,
        model_name: str,
        input_hash: str,
        inference_func: Optional[Callable] = None,
        *args,
        **kwargs,
    ) -> Optional[Any]:
        """
        Get ML inference result with caching.

        Args:
            model_name: Name of model
            input_hash: Hash of input data
            inference_func: Function to run inference if not cached
            *args: Arguments for inference function
            **kwargs: Keyword arguments for inference function

        Returns:
            Inference result
        """
        cache_key = f"{model_name}:{input_hash}"

        # Check cache
        cached_result = self.get(cache_key)
        if cached_result is not None:
            return cached_result

        # Run inference if function provided
        if inference_func:
            try:
                result = inference_func(*args, **kwargs)
                self.put(cache_key, result)
                return result
            except Exception as e:
                self.logger.error(f"Error running inference for {model_name}: {e}")
                return None

        return None


class PatternMatchCache(LRUCache):
    """Cache for pattern matching results."""

    def __init__(self, max_size: int = 2000, ttl: int = 3600):
        super().__init__(max_size, ttl)
        self.logger = logging.getLogger(__name__ + ".PatternMatchCache")

    def get_matches(
        self, data_hash: str, pattern_id: str, match_func: Optional[Callable] = None, *args, **kwargs
    ) -> Optional[Any]:
        """
        Get pattern matches with caching.

        Args:
            data_hash: Hash of data to search
            pattern_id: Identifier for pattern
            match_func: Function to run matching if not cached
            *args: Arguments for matching function
            **kwargs: Keyword arguments for matching function

        Returns:
            Pattern matching results
        """
        cache_key = f"{pattern_id}:{data_hash}"

        # Check cache
        cached_matches = self.get(cache_key)
        if cached_matches is not None:
            return cached_matches

        # Run matching if function provided
        if match_func:
            try:
                matches = match_func(*args, **kwargs)
                self.put(cache_key, matches)
                return matches
            except Exception as e:
                self.logger.error(f"Error matching pattern {pattern_id}: {e}")
                return None

        return None


# ============================================================================
# Persistent Cache
# ============================================================================


class PersistentCache:
    """Disk-backed cache for persistent storage."""

    def __init__(self, cache_dir: str = ".cache", max_size_mb: int = 500):
        """
        Initialize persistent cache.

        Args:
            cache_dir: Directory for cache files
            max_size_mb: Maximum cache size in megabytes
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__ + ".PersistentCache")

    def _get_cache_path(self, key: str) -> Path:
        """Get path for cache file."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.cache_dir / f"{key_hash}.cache"

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from persistent cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        cache_path = self._get_cache_path(key)

        with self.lock:
            if not cache_path.exists():
                return None

            try:
                with open(cache_path, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                self.logger.warning(f"Error loading cache for {key}: {e}")
                return None

    def put(self, key: str, value: Any):
        """
        Put value into persistent cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        cache_path = self._get_cache_path(key)

        with self.lock:
            try:
                # Write to cache
                with open(cache_path, "wb") as f:
                    pickle.dump(value, f, protocol=pickle.HIGHEST_PROTOCOL)

                # Check cache size and cleanup if needed
                self._cleanup_if_needed()

            except Exception as e:
                self.logger.error(f"Error saving cache for {key}: {e}")

    def _cleanup_if_needed(self):
        """Clean up old cache files if size limit exceeded."""
        # Get all cache files sorted by access time
        cache_files = []
        total_size = 0

        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                stat = cache_file.stat()
                cache_files.append((cache_file, stat.st_atime, stat.st_size))
                total_size += stat.st_size
            except OSError:
                continue

        # Remove oldest files if over limit
        if total_size > self.max_size_bytes:
            cache_files.sort(key=lambda x: x[1])  # Sort by access time

            for cache_file, _, size in cache_files:
                if total_size <= self.max_size_bytes * 0.8:  # Leave 20% buffer
                    break

                try:
                    cache_file.unlink()
                    total_size -= size
                except OSError:
                    pass

    def clear(self):
        """Clear all cached files."""
        with self.lock:
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    cache_file.unlink()
                except OSError:
                    pass


# ============================================================================
# Unified Cache Manager
# ============================================================================


class CacheManager:
    """Unified cache manager for all caching needs."""

    def __init__(
        self,
        cache_dir: str = ".cache",
        enable_persistent: bool = True,
        file_hash_size: int = 500,
        pe_header_size: int = 200,
        ml_inference_size: int = 1000,
        pattern_match_size: int = 2000,
    ):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory for persistent caches
            enable_persistent: Enable disk-backed caching
            file_hash_size: Max size of file hash cache
            pe_header_size: Max size of PE header cache
            ml_inference_size: Max size of ML inference cache
            pattern_match_size: Max size of pattern match cache
        """
        self.logger = logging.getLogger(__name__)

        # Initialize specialized caches
        self.file_hash_cache = FileHashCache(max_size=file_hash_size)
        self.pe_header_cache = PEHeaderCache(max_size=pe_header_size)
        self.ml_inference_cache = MLInferenceCache(max_size=ml_inference_size)
        self.pattern_match_cache = PatternMatchCache(max_size=pattern_match_size)

        # Initialize persistent cache
        self.persistent_cache = None
        if enable_persistent:
            self.persistent_cache = PersistentCache(cache_dir=cache_dir)

        self.logger.info("Cache manager initialized")

    def get_file_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Get file hash with caching."""
        return self.file_hash_cache.get_file_hash(file_path, algorithm)

    def get_pe_info(
        self, file_path: str, parse_func: Optional[Callable] = None
    ) -> Optional[Dict[str, Any]]:
        """Get PE information with caching."""
        return self.pe_header_cache.get_pe_info(file_path, parse_func)

    def get_ml_inference(
        self, model_name: str, input_hash: str, inference_func: Optional[Callable] = None, *args, **kwargs
    ) -> Optional[Any]:
        """Get ML inference with caching."""
        return self.ml_inference_cache.get_inference(
            model_name, input_hash, inference_func, *args, **kwargs
        )

    def get_pattern_matches(
        self, data_hash: str, pattern_id: str, match_func: Optional[Callable] = None, *args, **kwargs
    ) -> Optional[Any]:
        """Get pattern matches with caching."""
        return self.pattern_match_cache.get_matches(
            data_hash, pattern_id, match_func, *args, **kwargs
        )

    def invalidate_file(self, file_path: str):
        """
        Invalidate all caches for a file.

        Args:
            file_path: Path to file
        """
        # Invalidate based on file path prefix
        for cache in [self.file_hash_cache, self.pe_header_cache]:
            keys_to_remove = [k for k in cache.cache.keys() if k.startswith(file_path)]
            for key in keys_to_remove:
                cache.invalidate(key)

    def clear_all(self):
        """Clear all caches."""
        self.file_hash_cache.clear()
        self.pe_header_cache.clear()
        self.ml_inference_cache.clear()
        self.pattern_match_cache.clear()

        if self.persistent_cache:
            self.persistent_cache.clear()

        self.logger.info("All caches cleared")

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get statistics for all caches.

        Returns:
            Dictionary with statistics for each cache
        """
        return {
            "file_hash": self.file_hash_cache.get_stats(),
            "pe_header": self.pe_header_cache.get_stats(),
            "ml_inference": self.ml_inference_cache.get_stats(),
            "pattern_match": self.pattern_match_cache.get_stats(),
        }

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """
        Get aggregated statistics across all caches.

        Returns:
            Dictionary with aggregate statistics
        """
        all_stats = self.get_stats()

        total_hits = 0
        total_misses = 0
        total_size = 0
        total_max_size = 0

        for cache_stats in all_stats.values():
            total_hits += cache_stats.get('hits', 0)
            total_misses += cache_stats.get('misses', 0)
            total_size += cache_stats.get('size', 0)
            total_max_size += cache_stats.get('max_size', 0)

        total_requests = total_hits + total_misses
        overall_hit_rate = total_hits / total_requests if total_requests > 0 else 0.0

        return {
            "total_requests": total_requests,
            "total_hits": total_hits,
            "total_misses": total_misses,
            "overall_hit_rate": overall_hit_rate,
            "total_cached_items": total_size,
            "total_capacity": total_max_size,
            "utilization": total_size / total_max_size if total_max_size > 0 else 0.0,
            "individual_caches": all_stats,
        }

    def print_stats(self):
        """Print cache statistics."""
        stats = self.get_stats()
        print("\n=== Cache Statistics ===")
        for cache_name, cache_stats in stats.items():
            print(f"\n{cache_name}:")
            for key, value in cache_stats.items():
                if key == "hit_rate":
                    print(f"  {key}: {value:.2%}")
                else:
                    print(f"  {key}: {value}")

    def print_aggregate_stats(self):
        """Print aggregate cache statistics."""
        stats = self.get_aggregate_stats()
        print("\n=== Aggregate Cache Statistics ===")
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Total Hits: {stats['total_hits']}")
        print(f"Total Misses: {stats['total_misses']}")
        print(f"Overall Hit Rate: {stats['overall_hit_rate']:.2%}")
        print(f"Total Cached Items: {stats['total_cached_items']}")
        print(f"Total Capacity: {stats['total_capacity']}")
        print(f"Cache Utilization: {stats['utilization']:.2%}")

    def log_stats(self, logger: Optional[logging.Logger] = None):
        """
        Log cache statistics.

        Args:
            logger: Logger instance (uses internal logger if None)
        """
        log = logger or self.logger
        stats = self.get_aggregate_stats()

        log.info("=" * 60)
        log.info("CACHE PERFORMANCE STATISTICS")
        log.info("=" * 60)
        log.info(f"Overall Hit Rate: {stats['overall_hit_rate']:.1%}")
        log.info(f"Total Requests: {stats['total_requests']} "
                f"(Hits: {stats['total_hits']}, Misses: {stats['total_misses']})")
        log.info(f"Cache Utilization: {stats['utilization']:.1%} "
                f"({stats['total_cached_items']}/{stats['total_capacity']} items)")

        # Log individual cache performance
        for cache_name, cache_stats in stats['individual_caches'].items():
            hit_rate = cache_stats.get('hit_rate', 0)
            hits = cache_stats.get('hits', 0)
            misses = cache_stats.get('misses', 0)
            size = cache_stats.get('size', 0)

            if hits + misses > 0:  # Only log caches that have been used
                log.info(f"  {cache_name}: {hit_rate:.1%} hit rate "
                        f"({hits} hits, {misses} misses, {size} items)")

        log.info("=" * 60)


# ============================================================================
# Cache Decorator
# ============================================================================


def cached(cache_manager: CacheManager = None, cache_type: str = "general", ttl: int = 3600, key_pattern: str = None):
    """
    Decorator for caching function results.

    Args:
        cache_manager: CacheManager instance (uses global if None)
        cache_type: Type of cache to use
        ttl: Time-to-live in seconds
        key_pattern: Custom key pattern (e.g., 'analysis:{0}:{1}')

    Returns:
        Decorated function

    Example:
        @cached(ttl=3600, key_pattern='pe_analysis:{file_hash}')
        def analyze_pe(file_path, options):
            # Analysis code
            pass
    """

    def decorator(func: Callable) -> Callable:
        # Use global cache manager if none provided
        if cache_manager is None:
            mgr = get_cache_manager()
        else:
            mgr = cache_manager

        func_cache = LRUCache(max_size=1000, ttl=ttl)

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key
            if key_pattern:
                # Use custom key pattern
                try:
                    # Try to format with kwargs first
                    cache_key = key_pattern.format(**kwargs)
                except (KeyError, IndexError):
                    # Fallback to positional args
                    cache_key = key_pattern.format(*args)
            else:
                # Create default cache key from function name and arguments
                key_parts = [func.__name__]
                key_parts.extend(str(arg)[:100] for arg in args)  # Limit arg length
                key_parts.extend(f"{k}={str(v)[:50]}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(key_parts)

            # Check cache
            result = func_cache.get(cache_key)
            if result is not None:
                return result

            # Call function and cache result
            result = func(*args, **kwargs)
            func_cache.put(cache_key, result)
            return result

        # Add cache access methods
        wrapper._cache = func_cache
        wrapper._cache_clear = func_cache.clear
        wrapper._cache_stats = func_cache.get_stats

        return wrapper

    return decorator


# ============================================================================
# Global Cache Manager Instance
# ============================================================================

_global_cache_manager: Optional[CacheManager] = None
_cache_manager_lock = threading.Lock()


def get_cache_manager(**kwargs) -> CacheManager:
    """
    Get global cache manager instance (singleton pattern).

    Args:
        **kwargs: Arguments for CacheManager initialization

    Returns:
        Global CacheManager instance
    """
    global _global_cache_manager

    with _cache_manager_lock:
        if _global_cache_manager is None:
            _global_cache_manager = CacheManager(**kwargs)

    return _global_cache_manager


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    # Create cache manager
    cache_mgr = get_cache_manager(cache_dir=".test_cache")

    # Test file hash caching
    print("\n=== Testing File Hash Cache ===")
    test_file = __file__
    hash1 = cache_mgr.get_file_hash(test_file)
    print(f"Hash 1: {hash1}")
    hash2 = cache_mgr.get_file_hash(test_file)  # Should be cached
    print(f"Hash 2: {hash2}")
    print(f"Hashes match: {hash1 == hash2}")

    # Test cached decorator
    print("\n=== Testing Cached Decorator ===")

    @cached(cache_mgr, ttl=60)
    def expensive_function(x: int) -> int:
        print(f"Computing for x={x}...")
        time.sleep(1)
        return x * x

    result1 = expensive_function(5)
    print(f"Result 1: {result1}")
    result2 = expensive_function(5)  # Should be instant from cache
    print(f"Result 2: {result2}")

    # Print statistics
    cache_mgr.print_stats()

    # Cleanup
    cache_mgr.clear_all()
    print("\n=== Caches cleared ===")
