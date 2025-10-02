"""
Common Utility Functions for KP14 Analysis Framework
====================================================

This module consolidates frequently used utility functions to eliminate
code duplication across the codebase.

Features:
- Hash calculation utilities
- File validation helpers
- Entropy calculation functions
- Common file operations
- Data structure utilities

Author: KP14 Development Team
Version: 1.0.0
"""

import hashlib
import math
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Union, Any


# ============================================================================
# Hash Calculation Utilities
# ============================================================================

# Default chunk size for file reading (8KB)
DEFAULT_CHUNK_SIZE = 8192


def calculate_file_hash(
    file_path: Union[str, Path],
    algorithm: str = 'sha256',
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Calculate hash of a file using specified algorithm.

    This is a consolidated hash calculation function used across the codebase.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        chunk_size: Size of chunks to read in bytes

    Returns:
        Hex digest of file hash

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If algorithm is not supported
        IOError: If file cannot be read

    Example:
        >>> hash_value = calculate_file_hash('/path/to/file.exe', 'sha256')
        >>> print(hash_value)
        'a1b2c3d4...'
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError as e:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from e

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e


def calculate_multiple_hashes(
    file_path: Union[str, Path],
    algorithms: Optional[List[str]] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file in a single pass.

    More efficient than calling calculate_file_hash multiple times
    as it only reads the file once.

    Args:
        file_path: Path to file
        algorithms: List of hash algorithms (default: ['md5', 'sha1', 'sha256'])
        chunk_size: Size of chunks to read in bytes

    Returns:
        Dictionary mapping algorithm names to hash values

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If any algorithm is not supported
        IOError: If file cannot be read

    Example:
        >>> hashes = calculate_multiple_hashes('/path/to/file.exe')
        >>> print(hashes['sha256'])
        'a1b2c3d4...'
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Create hash objects
    hashers = {}
    for algo in algorithms:
        try:
            hashers[algo] = hashlib.new(algo)
        except ValueError as e:
            raise ValueError(f"Unsupported hash algorithm: {algo}") from e

    # Read file once and update all hashers
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                for hasher in hashers.values():
                    hasher.update(chunk)

        # Return results
        return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}

    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e


def calculate_data_hash(
    data: bytes,
    algorithm: str = 'sha256'
) -> str:
    """
    Calculate hash of data bytes.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of data hash

    Raises:
        ValueError: If algorithm is not supported

    Example:
        >>> hash_value = calculate_data_hash(b'Hello, World!', 'sha256')
        >>> print(hash_value)
        'dffd6021...'
    """
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()
    except ValueError as e:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from e


# ============================================================================
# Entropy Calculation Utilities
# ============================================================================

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Entropy measures randomness/complexity of data:
    - 0.0: All same byte (no randomness)
    - 8.0: Maximum randomness (encrypted/compressed data)
    - 4.0-6.0: Normal text/code
    - 7.0+: Likely encrypted or compressed

    Args:
        data: Bytes to calculate entropy for

    Returns:
        Entropy value (0.0 to 8.0)

    Example:
        >>> entropy = calculate_shannon_entropy(b'AAAA')
        >>> print(f'{entropy:.2f}')
        '0.00'
        >>> entropy = calculate_shannon_entropy(os.urandom(100))
        >>> print(f'{entropy:.2f}')
        '7.95'
    """
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)

    # Calculate Shannon entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: Optional[int] = None
) -> float:
    """
    Calculate Shannon entropy of a file.

    Args:
        file_path: Path to file
        chunk_size: Size of chunks to read
        max_bytes: Maximum number of bytes to read (None = entire file)

    Returns:
        Entropy value (0.0 to 8.0)

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read

    Example:
        >>> entropy = calculate_file_entropy('/path/to/encrypted.bin')
        >>> if entropy > 7.5:
        ...     print('File appears to be encrypted or compressed')
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    byte_counts = Counter()
    total_bytes = 0

    try:
        with open(file_path, 'rb') as f:
            while True:
                # Check max_bytes limit
                if max_bytes and total_bytes >= max_bytes:
                    break

                # Read chunk
                read_size = chunk_size
                if max_bytes:
                    read_size = min(chunk_size, max_bytes - total_bytes)

                chunk = f.read(read_size)
                if not chunk:
                    break

                # Update counts
                byte_counts.update(chunk)
                total_bytes += len(chunk)

    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e

    if total_bytes == 0:
        return 0.0

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)

    return entropy


# ============================================================================
# File Validation Utilities
# ============================================================================

def validate_file_exists(file_path: Union[str, Path]) -> Path:
    """
    Validate that a file exists and is readable.

    Args:
        file_path: Path to file

    Returns:
        Path object for the file

    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file is not readable

    Example:
        >>> path = validate_file_exists('/path/to/file.exe')
        >>> print(path.name)
        'file.exe'
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    if not os.access(path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")

    return path


def get_file_size(file_path: Union[str, Path]) -> int:
    """
    Get size of a file in bytes.

    Args:
        file_path: Path to file

    Returns:
        File size in bytes

    Raises:
        FileNotFoundError: If file doesn't exist

    Example:
        >>> size = get_file_size('/path/to/file.exe')
        >>> print(f'{size:,} bytes')
        '1,234,567 bytes'
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    return os.path.getsize(file_path)


def validate_file_size(
    file_path: Union[str, Path],
    max_size: Optional[int] = None,
    min_size: Optional[int] = None
) -> int:
    """
    Validate file size is within acceptable limits.

    Args:
        file_path: Path to file
        max_size: Maximum allowed size in bytes (None = no limit)
        min_size: Minimum allowed size in bytes (None = no limit)

    Returns:
        Actual file size in bytes

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file size is out of bounds

    Example:
        >>> size = validate_file_size('/path/to/file.exe', max_size=100*1024*1024)
        >>> print(f'File size: {size:,} bytes')
    """
    file_size = get_file_size(file_path)

    if max_size is not None and file_size > max_size:
        raise ValueError(
            f"File size ({file_size:,} bytes) exceeds maximum "
            f"allowed size ({max_size:,} bytes)"
        )

    if min_size is not None and file_size < min_size:
        raise ValueError(
            f"File size ({file_size:,} bytes) is smaller than minimum "
            f"required size ({min_size:,} bytes)"
        )

    return file_size


# ============================================================================
# File Reading Utilities
# ============================================================================

def read_file_chunks(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: Optional[int] = None
):
    """
    Generator that yields file contents in chunks.

    Args:
        file_path: Path to file
        chunk_size: Size of chunks to yield
        max_bytes: Maximum number of bytes to read (None = entire file)

    Yields:
        Chunks of file data as bytes

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read

    Example:
        >>> for chunk in read_file_chunks('/path/to/file.exe', chunk_size=4096):
        ...     process_chunk(chunk)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    total_read = 0

    try:
        with open(file_path, 'rb') as f:
            while True:
                # Check max_bytes limit
                if max_bytes and total_read >= max_bytes:
                    break

                # Calculate read size
                read_size = chunk_size
                if max_bytes:
                    read_size = min(chunk_size, max_bytes - total_read)

                # Read chunk
                chunk = f.read(read_size)
                if not chunk:
                    break

                total_read += len(chunk)
                yield chunk

    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e


def read_file_header(
    file_path: Union[str, Path],
    num_bytes: int = 16
) -> bytes:
    """
    Read the first N bytes of a file (header).

    Useful for magic byte detection and file type identification.

    Args:
        file_path: Path to file
        num_bytes: Number of bytes to read from start

    Returns:
        First N bytes of file

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read

    Example:
        >>> header = read_file_header('/path/to/file.exe', 2)
        >>> if header == b'MZ':
        ...     print('PE executable detected')
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, 'rb') as f:
            return f.read(num_bytes)
    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e


# ============================================================================
# Data Structure Utilities
# ============================================================================

def safe_get_nested(
    data: Dict[str, Any],
    *keys: str,
    default: Any = None
) -> Any:
    """
    Safely get nested dictionary values.

    Args:
        data: Dictionary to search
        *keys: Sequence of keys to traverse
        default: Default value if key path doesn't exist

    Returns:
        Value at key path or default

    Example:
        >>> data = {'a': {'b': {'c': 123}}}
        >>> value = safe_get_nested(data, 'a', 'b', 'c')
        >>> print(value)
        123
        >>> value = safe_get_nested(data, 'a', 'x', 'y', default=0)
        >>> print(value)
        0
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def format_bytes(num_bytes: int) -> str:
    """
    Format byte count as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Formatted string (e.g., '1.5 MB')

    Example:
        >>> print(format_bytes(1536))
        '1.5 KB'
        >>> print(format_bytes(1048576))
        '1.0 MB'
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Format bytes as hex dump.

    Args:
        data: Bytes to format
        bytes_per_line: Number of bytes per line

    Returns:
        Hex dump string

    Example:
        >>> data = b'Hello, World!'
        >>> print(format_hex(data, bytes_per_line=8))
        '48 65 6C 6C 6F 2C 20 57
         6F 72 6C 64 21'
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        lines.append(hex_str)
    return '\n'.join(lines)


# ============================================================================
# Path Utilities
# ============================================================================

def ensure_directory(dir_path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        dir_path: Path to directory

    Returns:
        Path object for the directory

    Raises:
        PermissionError: If directory cannot be created

    Example:
        >>> output_dir = ensure_directory('/path/to/output')
        >>> print(output_dir)
        /path/to/output
    """
    path = Path(dir_path)
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except PermissionError as e:
        raise PermissionError(f"Cannot create directory {dir_path}: {e}") from e


def get_safe_filename(filename: str, max_length: int = 255) -> str:
    """
    Create a safe filename by removing/replacing invalid characters.

    Args:
        filename: Original filename
        max_length: Maximum length for filename

    Returns:
        Safe filename

    Example:
        >>> safe_name = get_safe_filename('file:name?.exe')
        >>> print(safe_name)
        'file_name_.exe'
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    safe_name = filename
    for char in invalid_chars:
        safe_name = safe_name.replace(char, '_')

    # Truncate to max length
    if len(safe_name) > max_length:
        name, ext = os.path.splitext(safe_name)
        max_name_len = max_length - len(ext)
        safe_name = name[:max_name_len] + ext

    return safe_name


# ============================================================================
# Main (for testing)
# ============================================================================

if __name__ == "__main__":
    import tempfile

    print("=== KP14 Common Utilities - Testing ===\n")

    # Test hash calculation
    print("Test 1: Hash Calculation")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        test_file = f.name
        f.write(b"Test data for hashing")

    try:
        hash_value = calculate_file_hash(test_file, 'sha256')
        print(f"SHA256: {hash_value}")

        hashes = calculate_multiple_hashes(test_file)
        for algo, value in hashes.items():
            print(f"{algo.upper()}: {value}")
    finally:
        os.unlink(test_file)

    # Test entropy calculation
    print("\nTest 2: Entropy Calculation")
    low_entropy = calculate_shannon_entropy(b'AAAA' * 100)
    high_entropy = calculate_shannon_entropy(os.urandom(400))
    print(f"Low entropy: {low_entropy:.2f}")
    print(f"High entropy: {high_entropy:.2f}")

    # Test data structure utilities
    print("\nTest 3: Data Structure Utilities")
    data = {'a': {'b': {'c': 123}}}
    value = safe_get_nested(data, 'a', 'b', 'c')
    print(f"Nested value: {value}")

    # Test formatting
    print("\nTest 4: Formatting Utilities")
    print(f"Formatted bytes: {format_bytes(1536000)}")
    print(f"Hex dump:\n{format_hex(b'Hello, World!', 8)}")

    print("\n=== All tests completed ===")
