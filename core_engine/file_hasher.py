"""
File Hasher with Caching for KP14 Analysis Framework
====================================================

Provides cached file hash calculation with multiple algorithms,
file modification tracking, and memory-efficient chunked reading.

Features:
- Multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
- Automatic cache invalidation based on file mtime
- Memory-efficient chunked file reading
- Thread-safe operations
- Integration with CacheManager

Author: KP14 Development Team
Version: 1.0.0
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from core_engine.cache_manager import get_cache_manager


class FileHasher:
    """
    File hasher with intelligent caching and multiple algorithm support.

    This class provides efficient file hashing with automatic caching
    and invalidation based on file modification times.
    """

    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

    # Default chunk size for reading files (8 KB)
    DEFAULT_CHUNK_SIZE = 8192

    def __init__(self, cache_manager=None):
        """
        Initialize file hasher.

        Args:
            cache_manager: CacheManager instance (uses global if None)
        """
        self.logger = logging.getLogger(__name__)
        self.cache_manager = cache_manager or get_cache_manager()

    def get_file_hash(
        self,
        file_path: str,
        algorithm: str = 'sha256',
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        use_cache: bool = True
    ) -> str:
        """
        Calculate file hash with caching.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
            chunk_size: Size of chunks to read in bytes
            use_cache: Whether to use caching

        Returns:
            Hex digest of file hash

        Raises:
            ValueError: If algorithm not supported
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        # Validate algorithm
        if algorithm.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Supported: {', '.join(self.SUPPORTED_ALGORITHMS)}"
            )

        # Check file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Use cache if enabled
        if use_cache:
            return self.cache_manager.get_file_hash(file_path, algorithm)

        # Calculate hash without cache
        return self._calculate_hash(file_path, algorithm, chunk_size)

    def _calculate_hash(
        self,
        file_path: str,
        algorithm: str,
        chunk_size: int
    ) -> str:
        """
        Calculate file hash without caching.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm
            chunk_size: Size of chunks to read

        Returns:
            Hex digest of file hash
        """
        try:
            hasher = hashlib.new(algorithm)

            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except IOError as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            raise

    def get_multiple_hashes(
        self,
        file_path: str,
        algorithms: list = None,
        use_cache: bool = True
    ) -> Dict[str, str]:
        """
        Calculate multiple hashes for a file efficiently.

        Args:
            file_path: Path to file
            algorithms: List of algorithms (default: ['md5', 'sha1', 'sha256'])
            use_cache: Whether to use caching

        Returns:
            Dictionary mapping algorithm names to hash values
        """
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']

        # Validate algorithms
        for algo in algorithms:
            if algo.lower() not in self.SUPPORTED_ALGORITHMS:
                raise ValueError(f"Unsupported algorithm: {algo}")

        # Check file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # If using cache, check each algorithm separately
        if use_cache:
            results = {}
            for algo in algorithms:
                try:
                    results[algo] = self.cache_manager.get_file_hash(file_path, algo)
                except Exception as e:
                    self.logger.warning(f"Error getting {algo} hash: {e}")
            return results

        # Calculate all hashes in one pass (more efficient)
        return self._calculate_multiple_hashes(file_path, algorithms)

    def _calculate_multiple_hashes(
        self,
        file_path: str,
        algorithms: list
    ) -> Dict[str, str]:
        """
        Calculate multiple hashes in a single file pass.

        Args:
            file_path: Path to file
            algorithms: List of algorithm names

        Returns:
            Dictionary mapping algorithm names to hash values
        """
        try:
            # Create hashers for each algorithm
            hashers = {algo: hashlib.new(algo) for algo in algorithms}

            # Read file once and update all hashers
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.DEFAULT_CHUNK_SIZE):
                    for hasher in hashers.values():
                        hasher.update(chunk)

            # Return results
            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}

        except IOError as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {file_path}: {e}")
            raise

    def get_file_info(self, file_path: str) -> Dict:
        """
        Get comprehensive file information including hashes.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with file information
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        stat = os.stat(file_path)

        return {
            'path': file_path,
            'size': stat.st_size,
            'mtime': stat.st_mtime,
            'md5': self.get_file_hash(file_path, 'md5'),
            'sha1': self.get_file_hash(file_path, 'sha1'),
            'sha256': self.get_file_hash(file_path, 'sha256'),
        }

    def verify_file_integrity(
        self,
        file_path: str,
        expected_hash: str,
        algorithm: str = 'sha256'
    ) -> Tuple[bool, str]:
        """
        Verify file integrity against expected hash.

        Args:
            file_path: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm to use

        Returns:
            Tuple of (is_valid, actual_hash)
        """
        try:
            actual_hash = self.get_file_hash(file_path, algorithm)
            is_valid = actual_hash.lower() == expected_hash.lower()
            return is_valid, actual_hash
        except Exception as e:
            self.logger.error(f"Error verifying file integrity: {e}")
            return False, ""

    def invalidate_cache(self, file_path: str):
        """
        Invalidate cached hashes for a file.

        Args:
            file_path: Path to file
        """
        self.cache_manager.invalidate_file(file_path)
        self.logger.debug(f"Invalidated cache for {file_path}")


# ============================================================================
# Convenience Functions
# ============================================================================

# Global file hasher instance
_global_file_hasher: Optional[FileHasher] = None


def get_file_hasher() -> FileHasher:
    """
    Get global file hasher instance (singleton pattern).

    Returns:
        Global FileHasher instance
    """
    global _global_file_hasher

    if _global_file_hasher is None:
        _global_file_hasher = FileHasher()

    return _global_file_hasher


def quick_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Quick convenience function to hash a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (default: sha256)

    Returns:
        Hex digest of file hash
    """
    hasher = get_file_hasher()
    return hasher.get_file_hash(file_path, algorithm)


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    import time

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create file hasher
    hasher = FileHasher()

    # Test with this file
    test_file = __file__

    print("\n=== Testing File Hasher ===")
    print(f"Test file: {test_file}")

    # Test single hash with cache
    print("\n--- First hash (cold cache) ---")
    start = time.time()
    hash1 = hasher.get_file_hash(test_file, 'sha256')
    time1 = time.time() - start
    print(f"SHA256: {hash1}")
    print(f"Time: {time1:.4f}s")

    # Test cached hash
    print("\n--- Second hash (warm cache) ---")
    start = time.time()
    hash2 = hasher.get_file_hash(test_file, 'sha256')
    time2 = time.time() - start
    print(f"SHA256: {hash2}")
    print(f"Time: {time2:.4f}s")
    print(f"Speedup: {time1/time2:.1f}x")
    print(f"Cache hit: {hash1 == hash2}")

    # Test multiple hashes
    print("\n--- Multiple hashes ---")
    hashes = hasher.get_multiple_hashes(test_file, ['md5', 'sha1', 'sha256'])
    for algo, hash_value in hashes.items():
        print(f"{algo.upper()}: {hash_value}")

    # Test file info
    print("\n--- File info ---")
    info = hasher.get_file_info(test_file)
    for key, value in info.items():
        if key in ['md5', 'sha1', 'sha256']:
            print(f"{key.upper()}: {value}")
        else:
            print(f"{key}: {value}")

    # Test integrity verification
    print("\n--- Integrity verification ---")
    is_valid, actual = hasher.verify_file_integrity(test_file, hash1, 'sha256')
    print(f"Integrity check: {'PASS' if is_valid else 'FAIL'}")

    # Print cache statistics
    print("\n--- Cache Statistics ---")
    cache_mgr = get_cache_manager()
    cache_mgr.print_stats()
