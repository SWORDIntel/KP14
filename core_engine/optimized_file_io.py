"""
Optimized File I/O Module for KP14 Analysis Framework
=====================================================

Provides high-performance file I/O operations:
- Memory-mapped file access
- Read-ahead buffering
- Batch file operations
- Streaming results
- Zero-copy operations where possible

Features:
- Automatic optimization based on file size
- Efficient large file handling
- Memory-efficient streaming
- Thread-safe operations

Author: KP14 Development Team
Version: 1.0.0
"""

import io
import logging
import mmap
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Generator, Iterator, Optional, Union


# ============================================================================
# Constants
# ============================================================================

# File size thresholds for optimization strategies
SMALL_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB - load into memory
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100 MB - use memory mapping
STREAMING_THRESHOLD = 500 * 1024 * 1024  # 500 MB - use streaming

# Buffer sizes
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB
MMAP_BUFFER_SIZE = 1 * 1024 * 1024  # 1 MB


# ============================================================================
# Memory-Mapped File Reader
# ============================================================================


class MemoryMappedFile:
    """Memory-mapped file reader for efficient large file access."""

    def __init__(self, file_path: str, access: int = mmap.ACCESS_READ):
        """
        Initialize memory-mapped file.

        Args:
            file_path: Path to file
            access: Access mode (mmap.ACCESS_READ, mmap.ACCESS_WRITE, mmap.ACCESS_COPY)
        """
        self.file_path = file_path
        self.access = access
        self.file_handle: Optional[BinaryIO] = None
        self.mmap_obj: Optional[mmap.mmap] = None
        self.logger = logging.getLogger(__name__ + ".MemoryMappedFile")

    def __enter__(self):
        """Enter context manager."""
        try:
            self.file_handle = open(self.file_path, "rb")
            self.mmap_obj = mmap.mmap(self.file_handle.fileno(), 0, access=self.access)
            return self.mmap_obj
        except Exception as e:
            self.logger.error(f"Error creating memory map for {self.file_path}: {e}")
            self.close()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.close()

    def close(self):
        """Close memory-mapped file."""
        if self.mmap_obj:
            try:
                self.mmap_obj.close()
            except Exception:
                pass
            self.mmap_obj = None

        if self.file_handle:
            try:
                self.file_handle.close()
            except Exception:
                pass
            self.file_handle = None

    def read_chunk(self, offset: int, size: int) -> bytes:
        """
        Read chunk from memory-mapped file.

        Args:
            offset: Offset to start reading
            size: Number of bytes to read

        Returns:
            Bytes read from file
        """
        if not self.mmap_obj:
            raise RuntimeError("Memory-mapped file not open")

        return self.mmap_obj[offset : offset + size]

    def search(self, pattern: bytes, start: int = 0) -> int:
        """
        Search for pattern in memory-mapped file.

        Args:
            pattern: Pattern to search for
            start: Start offset

        Returns:
            Offset of pattern or -1 if not found
        """
        if not self.mmap_obj:
            raise RuntimeError("Memory-mapped file not open")

        return self.mmap_obj.find(pattern, start)


# ============================================================================
# Buffered File Reader
# ============================================================================


class BufferedFileReader:
    """Buffered file reader with read-ahead support."""

    def __init__(self, file_path: str, buffer_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize buffered file reader.

        Args:
            file_path: Path to file
            buffer_size: Size of read buffer
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.file_handle: Optional[BinaryIO] = None
        self.buffer: bytes = b""
        self.buffer_offset: int = 0
        self.file_offset: int = 0
        self.file_size: int = 0
        self.logger = logging.getLogger(__name__ + ".BufferedFileReader")

    def __enter__(self):
        """Enter context manager."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.close()

    def open(self):
        """Open file for buffered reading."""
        try:
            self.file_handle = open(self.file_path, "rb")
            self.file_size = os.path.getsize(self.file_path)
            self._fill_buffer()
        except Exception as e:
            self.logger.error(f"Error opening file {self.file_path}: {e}")
            self.close()
            raise

    def close(self):
        """Close file."""
        if self.file_handle:
            try:
                self.file_handle.close()
            except Exception:
                pass
            self.file_handle = None

        self.buffer = b""
        self.buffer_offset = 0
        self.file_offset = 0

    def _fill_buffer(self):
        """Fill read buffer."""
        if not self.file_handle:
            return

        try:
            self.buffer = self.file_handle.read(self.buffer_size)
            self.buffer_offset = 0
        except Exception as e:
            self.logger.error(f"Error filling buffer: {e}")
            self.buffer = b""

    def read(self, size: int) -> bytes:
        """
        Read bytes from file.

        Args:
            size: Number of bytes to read

        Returns:
            Bytes read from file
        """
        if not self.file_handle:
            raise RuntimeError("File not open")

        result = b""

        while size > 0:
            # Check if buffer needs refilling
            if self.buffer_offset >= len(self.buffer):
                self._fill_buffer()
                if not self.buffer:
                    break

            # Read from buffer
            available = len(self.buffer) - self.buffer_offset
            to_read = min(size, available)
            result += self.buffer[self.buffer_offset : self.buffer_offset + to_read]
            self.buffer_offset += to_read
            self.file_offset += to_read
            size -= to_read

        return result

    def read_all(self) -> bytes:
        """Read entire file."""
        chunks = []
        while True:
            chunk = self.read(self.buffer_size)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def seek(self, offset: int, whence: int = 0):
        """
        Seek to position in file.

        Args:
            offset: Offset to seek to
            whence: Reference point (0=start, 1=current, 2=end)
        """
        if not self.file_handle:
            raise RuntimeError("File not open")

        self.file_handle.seek(offset, whence)
        self.file_offset = self.file_handle.tell()
        self._fill_buffer()


# ============================================================================
# Streaming File Reader
# ============================================================================


def stream_file(
    file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Generator[bytes, None, None]:
    """
    Stream file in chunks.

    Args:
        file_path: Path to file
        chunk_size: Size of chunks to yield

    Yields:
        Chunks of file data
    """
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def stream_lines(file_path: str, encoding: str = "utf-8") -> Generator[str, None, None]:
    """
    Stream file lines.

    Args:
        file_path: Path to file
        encoding: Text encoding

    Yields:
        Lines from file
    """
    with open(file_path, "r", encoding=encoding, errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n\r")


# ============================================================================
# Batch File Operations
# ============================================================================


class BatchFileReader:
    """Read multiple files efficiently."""

    def __init__(self, file_paths: list[str], chunk_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize batch file reader.

        Args:
            file_paths: List of file paths to read
            chunk_size: Chunk size for reading
        """
        self.file_paths = file_paths
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__ + ".BatchFileReader")

    def read_all(self) -> dict[str, bytes]:
        """
        Read all files into memory.

        Returns:
            Dictionary mapping file paths to file contents
        """
        results = {}

        for file_path in self.file_paths:
            try:
                with open(file_path, "rb") as f:
                    results[file_path] = f.read()
            except Exception as e:
                self.logger.error(f"Error reading {file_path}: {e}")
                results[file_path] = None

        return results

    def stream_all(self) -> Generator[tuple[str, bytes], None, None]:
        """
        Stream all files.

        Yields:
            Tuples of (file_path, chunk)
        """
        for file_path in self.file_paths:
            try:
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(self.chunk_size)
                        if not chunk:
                            break
                        yield (file_path, chunk)
            except Exception as e:
                self.logger.error(f"Error streaming {file_path}: {e}")


# ============================================================================
# Optimized File Reader (Adaptive Strategy)
# ============================================================================


class OptimizedFileReader:
    """
    Adaptive file reader that selects optimal strategy based on file size.
    """

    def __init__(self, file_path: str):
        """
        Initialize optimized file reader.

        Args:
            file_path: Path to file
        """
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.logger = logging.getLogger(__name__ + ".OptimizedFileReader")

    def read(self) -> bytes:
        """
        Read file using optimal strategy.

        Returns:
            File contents
        """
        if self.file_size < SMALL_FILE_THRESHOLD:
            # Small file - read directly into memory
            return self._read_small_file()

        elif self.file_size < LARGE_FILE_THRESHOLD:
            # Medium file - use buffered reading
            return self._read_buffered()

        else:
            # Large file - use memory mapping
            return self._read_memory_mapped()

    def _read_small_file(self) -> bytes:
        """Read small file directly."""
        with open(self.file_path, "rb") as f:
            return f.read()

    def _read_buffered(self) -> bytes:
        """Read file with buffering."""
        with BufferedFileReader(self.file_path) as reader:
            return reader.read_all()

    def _read_memory_mapped(self) -> bytes:
        """Read file using memory mapping."""
        with MemoryMappedFile(self.file_path) as mmap_obj:
            return bytes(mmap_obj)

    def stream(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Generator[bytes, None, None]:
        """
        Stream file in chunks.

        Args:
            chunk_size: Size of chunks to yield

        Yields:
            Chunks of file data
        """
        if self.file_size > STREAMING_THRESHOLD:
            # Very large file - use memory mapping with chunked access
            with MemoryMappedFile(self.file_path) as mmap_obj:
                offset = 0
                while offset < len(mmap_obj):
                    chunk = mmap_obj[offset : offset + chunk_size]
                    yield bytes(chunk)
                    offset += chunk_size
        else:
            # Use regular streaming
            yield from stream_file(self.file_path, chunk_size)

    def read_chunk(self, offset: int, size: int) -> bytes:
        """
        Read specific chunk from file.

        Args:
            offset: Offset to start reading
            size: Number of bytes to read

        Returns:
            Bytes read from file
        """
        if self.file_size > LARGE_FILE_THRESHOLD:
            # Use memory mapping for large files
            with MemoryMappedFile(self.file_path) as mmap_obj:
                return mmap_obj[offset : offset + size]
        else:
            # Use regular file seeking
            with open(self.file_path, "rb") as f:
                f.seek(offset)
                return f.read(size)


# ============================================================================
# File Analysis Utilities
# ============================================================================


def analyze_file_efficiently(
    file_path: str, analyzer_func, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> any:
    """
    Analyze file efficiently using streaming.

    Args:
        file_path: Path to file
        analyzer_func: Function to analyze each chunk
        chunk_size: Size of chunks to process

    Returns:
        Analysis results
    """
    reader = OptimizedFileReader(file_path)

    # For small files, analyze all at once
    if reader.file_size < SMALL_FILE_THRESHOLD:
        data = reader.read()
        return analyzer_func(data)

    # For larger files, stream and aggregate results
    results = []
    for chunk in reader.stream(chunk_size):
        result = analyzer_func(chunk)
        if result:
            results.append(result)

    return results


def compute_file_hash_optimized(file_path: str, algorithm: str = "sha256") -> str:
    """
    Compute file hash using optimized I/O.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm

    Returns:
        Hex digest of file hash
    """
    import hashlib

    hasher = hashlib.new(algorithm)
    reader = OptimizedFileReader(file_path)

    for chunk in reader.stream(chunk_size=1024 * 1024):  # 1MB chunks
        hasher.update(chunk)

    return hasher.hexdigest()


# ============================================================================
# Zero-Copy File Operations
# ============================================================================


def zero_copy_search(file_path: str, pattern: bytes, max_matches: int = None) -> list[int]:
    """
    Search for pattern in file using zero-copy operations.

    Args:
        file_path: Path to file
        pattern: Pattern to search for
        max_matches: Maximum number of matches to find

    Returns:
        List of offsets where pattern was found
    """
    matches = []

    with MemoryMappedFile(file_path) as mmap_obj:
        offset = 0
        while True:
            pos = mmap_obj.find(pattern, offset)
            if pos == -1:
                break

            matches.append(pos)
            if max_matches and len(matches) >= max_matches:
                break

            offset = pos + 1

    return matches


# ============================================================================
# Thread-Safe File Reader Pool
# ============================================================================


class FileReaderPool:
    """Thread-safe pool of file readers for concurrent access."""

    def __init__(self, max_readers: int = 10):
        """
        Initialize file reader pool.

        Args:
            max_readers: Maximum number of concurrent readers
        """
        self.max_readers = max_readers
        self.active_readers = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__ + ".FileReaderPool")

    @contextmanager
    def get_reader(self, file_path: str):
        """
        Get file reader from pool.

        Args:
            file_path: Path to file

        Yields:
            OptimizedFileReader instance
        """
        reader_id = threading.get_ident()

        with self.lock:
            if len(self.active_readers) >= self.max_readers:
                self.logger.warning(f"File reader pool at capacity ({self.max_readers})")

            reader = OptimizedFileReader(file_path)
            self.active_readers[reader_id] = reader

        try:
            yield reader
        finally:
            with self.lock:
                self.active_readers.pop(reader_id, None)


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    test_file = __file__

    print(f"=== Testing Optimized File I/O ===")
    print(f"Test file: {test_file}")
    print(f"File size: {os.path.getsize(test_file)} bytes")

    # Test optimized reader
    print("\n1. Testing OptimizedFileReader...")
    reader = OptimizedFileReader(test_file)
    data = reader.read()
    print(f"   Read {len(data)} bytes")

    # Test streaming
    print("\n2. Testing streaming...")
    chunk_count = 0
    total_bytes = 0
    for chunk in reader.stream(chunk_size=1024):
        chunk_count += 1
        total_bytes += len(chunk)
    print(f"   Streamed {chunk_count} chunks, {total_bytes} bytes total")

    # Test hash computation
    print("\n3. Testing optimized hash computation...")
    file_hash = compute_file_hash_optimized(test_file)
    print(f"   SHA256: {file_hash}")

    # Test pattern search
    print("\n4. Testing zero-copy pattern search...")
    pattern = b"def "
    matches = zero_copy_search(test_file, pattern, max_matches=5)
    print(f"   Found {len(matches)} matches for pattern '{pattern.decode()}'")
    print(f"   First match at offset: {matches[0] if matches else 'N/A'}")

    print("\n=== Tests Complete ===")
