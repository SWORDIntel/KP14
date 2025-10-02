"""
ChunkedFileReader - Memory-efficient file processing module for KP14.

This module provides streaming and memory-mapped file access to prevent
OOM crashes when processing large files (up to 500MB) with minimal memory usage.

Features:
- Configurable chunk-based streaming (default 8MB chunks)
- Memory-mapped file support for large files (>100MB)
- Context manager for safe resource handling
- Random access support for PE section reading
- Memory usage monitoring and optimization

Security: All file operations validate paths and handle errors safely.
Performance: Designed to keep memory usage <2GB even with 500MB files.
"""

import os
import mmap
import logging
from typing import Generator, Optional, BinaryIO
from pathlib import Path


class ChunkedFileReader:
    """
    Memory-efficient file reader with support for streaming and memory-mapped access.

    This class provides two modes of operation:
    1. Streaming mode: Reads file in configurable chunks (default: 8MB)
    2. Memory-mapped mode: Uses mmap for files >100MB threshold

    Usage:
        # Streaming mode for sequential access
        with ChunkedFileReader('/path/to/file.exe') as reader:
            for chunk in reader.read_chunks():
                process(chunk)

        # Random access mode for PE sections
        with ChunkedFileReader('/path/to/file.exe') as reader:
            header = reader.read_range(0, 4096)
            section_data = reader.read_range(offset, size)
    """

    DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks
    MMAP_THRESHOLD = 100 * 1024 * 1024     # Use mmap for files >100MB

    def __init__(
        self,
        file_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        use_mmap_threshold: int = MMAP_THRESHOLD
    ):
        """
        Initialize chunked file reader.

        Args:
            file_path: Path to file to read
            chunk_size: Size of chunks for streaming (default: 8MB)
            use_mmap_threshold: File size threshold for using mmap (default: 100MB)

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If chunk_size or use_mmap_threshold are invalid
        """
        self.file_path = Path(file_path)
        self.chunk_size = chunk_size
        self.use_mmap_threshold = use_mmap_threshold
        self.logger = logging.getLogger(__name__)

        # Validate inputs
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not self.file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        if chunk_size <= 0:
            raise ValueError(f"Invalid chunk_size: {chunk_size}, must be > 0")

        if use_mmap_threshold < 0:
            raise ValueError(f"Invalid use_mmap_threshold: {use_mmap_threshold}")

        # Runtime state
        self._file_handle: Optional[BinaryIO] = None
        self._mmap_handle: Optional[mmap.mmap] = None
        self._file_size: Optional[int] = None
        self._use_mmap: bool = False

    def __enter__(self):
        """Context manager entry - opens file and sets up access mode."""
        self._open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures proper cleanup."""
        self._close()
        return False

    def _open(self):
        """Open file and determine access mode (streaming vs mmap)."""
        try:
            # Get file size
            self._file_size = self.file_path.stat().st_size

            # Determine if we should use mmap
            self._use_mmap = self._file_size > self.use_mmap_threshold

            # Open file handle
            self._file_handle = open(self.file_path, 'rb')

            # Set up mmap if needed
            if self._use_mmap:
                try:
                    self._mmap_handle = mmap.mmap(
                        self._file_handle.fileno(),
                        0,
                        access=mmap.ACCESS_READ
                    )
                    self.logger.debug(
                        f"Using memory-mapped mode for {self.file_path.name} "
                        f"({self._file_size / 1024 / 1024:.1f} MB)"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to create mmap for {self.file_path.name}, "
                        f"falling back to streaming: {e}"
                    )
                    self._use_mmap = False
                    self._mmap_handle = None
            else:
                self.logger.debug(
                    f"Using streaming mode for {self.file_path.name} "
                    f"({self._file_size / 1024 / 1024:.1f} MB)"
                )

        except Exception as e:
            self._close()
            raise IOError(f"Failed to open file {self.file_path}: {e}") from e

    def _close(self):
        """Close file handles and clean up resources."""
        try:
            if self._mmap_handle is not None:
                self._mmap_handle.close()
                self._mmap_handle = None

            if self._file_handle is not None:
                self._file_handle.close()
                self._file_handle = None

        except Exception as e:
            self.logger.error(f"Error closing file {self.file_path}: {e}")

    def get_file_size(self) -> int:
        """
        Get total file size in bytes.

        Returns:
            File size in bytes

        Raises:
            RuntimeError: If file hasn't been opened yet
        """
        if self._file_size is None:
            raise RuntimeError("File not opened - use context manager or call _open()")
        return self._file_size

    def read_chunks(self) -> Generator[bytes, None, None]:
        """
        Generator that yields file data in chunks.

        This is the preferred method for sequential file processing as it
        minimizes memory usage by only keeping one chunk in memory at a time.

        Yields:
            bytes: Chunk of file data (up to chunk_size bytes)

        Raises:
            RuntimeError: If file hasn't been opened yet
            IOError: If read operation fails
        """
        if self._file_handle is None:
            raise RuntimeError("File not opened - use context manager")

        try:
            if self._use_mmap and self._mmap_handle is not None:
                # Read from memory-mapped file in chunks
                offset = 0
                while offset < self._file_size:
                    chunk_end = min(offset + self.chunk_size, self._file_size)
                    yield self._mmap_handle[offset:chunk_end]
                    offset = chunk_end
            else:
                # Read from regular file handle in chunks
                self._file_handle.seek(0)
                while True:
                    chunk = self._file_handle.read(self.chunk_size)
                    if not chunk:
                        break
                    yield chunk

        except Exception as e:
            raise IOError(f"Error reading chunks from {self.file_path}: {e}") from e

    def read_range(self, offset: int, size: int) -> bytes:
        """
        Read specific range of bytes from file.

        This method is optimized for random access patterns common in PE analysis,
        such as reading headers or specific sections.

        Args:
            offset: Byte offset to start reading from
            size: Number of bytes to read

        Returns:
            bytes: Requested data range

        Raises:
            RuntimeError: If file hasn't been opened yet
            ValueError: If offset or size are invalid
            IOError: If read operation fails
        """
        if self._file_handle is None:
            raise RuntimeError("File not opened - use context manager")

        if offset < 0:
            raise ValueError(f"Invalid offset: {offset}, must be >= 0")

        if size < 0:
            raise ValueError(f"Invalid size: {size}, must be >= 0")

        if offset + size > self._file_size:
            raise ValueError(
                f"Range [{offset}:{offset+size}] exceeds file size {self._file_size}"
            )

        try:
            if self._use_mmap and self._mmap_handle is not None:
                # Read from memory-mapped file (O(1) operation)
                return self._mmap_handle[offset:offset + size]
            else:
                # Read from regular file handle
                self._file_handle.seek(offset)
                data = self._file_handle.read(size)
                if len(data) != size:
                    raise IOError(
                        f"Expected {size} bytes, got {len(data)} bytes at offset {offset}"
                    )
                return data

        except Exception as e:
            raise IOError(
                f"Error reading range [{offset}:{offset+size}] from {self.file_path}: {e}"
            ) from e

    def read_all(self) -> bytes:
        """
        Read entire file into memory.

        WARNING: Use this method only for small files or when absolutely necessary.
        For large files, prefer read_chunks() or read_range() to avoid OOM.

        Returns:
            bytes: Complete file contents

        Raises:
            RuntimeError: If file hasn't been opened yet
            IOError: If read operation fails
            MemoryError: If file is too large to fit in memory
        """
        if self._file_handle is None:
            raise RuntimeError("File not opened - use context manager")

        # Warn if reading large file into memory
        if self._file_size > 100 * 1024 * 1024:  # >100MB
            self.logger.warning(
                f"Reading large file ({self._file_size / 1024 / 1024:.1f} MB) "
                f"into memory - consider using read_chunks() instead"
            )

        try:
            if self._use_mmap and self._mmap_handle is not None:
                return self._mmap_handle[:]
            else:
                self._file_handle.seek(0)
                return self._file_handle.read()

        except MemoryError as e:
            raise MemoryError(
                f"Not enough memory to read {self._file_size / 1024 / 1024:.1f} MB file"
            ) from e
        except Exception as e:
            raise IOError(f"Error reading file {self.file_path}: {e}") from e

    def is_using_mmap(self) -> bool:
        """Check if reader is using memory-mapped mode."""
        return self._use_mmap and self._mmap_handle is not None


def log_memory_usage(label: str, logger: Optional[logging.Logger] = None):
    """
    Log current process memory usage.

    Args:
        label: Description label for the log entry
        logger: Logger instance to use (creates one if None)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        import psutil
        process = psutil.Process()
        mem_info = process.memory_info()
        mem_mb = mem_info.rss / 1024 / 1024

        logger.debug(f"{label}: Memory usage = {mem_mb:.1f} MB")

        # Warn if memory usage is high
        if mem_mb > 1536:  # >1.5GB
            logger.warning(
                f"{label}: High memory usage detected: {mem_mb:.1f} MB"
            )

    except ImportError:
        logger.debug(f"{label}: psutil not available, cannot log memory usage")
    except Exception as e:
        logger.debug(f"{label}: Error getting memory usage: {e}")


# Convenience function for simple use cases
def read_file_chunked(
    file_path: str,
    chunk_size: int = ChunkedFileReader.DEFAULT_CHUNK_SIZE
) -> Generator[bytes, None, None]:
    """
    Convenience function to read file in chunks without explicit context manager.

    Args:
        file_path: Path to file to read
        chunk_size: Size of chunks (default: 8MB)

    Yields:
        bytes: Chunk of file data
    """
    with ChunkedFileReader(file_path, chunk_size=chunk_size) as reader:
        yield from reader.read_chunks()


if __name__ == '__main__':
    # Simple test/demonstration
    import sys

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        print("Usage: python chunked_file_reader.py <file_path>")
        sys.exit(1)

    test_file = sys.argv[1]

    logger.info(f"Testing ChunkedFileReader with: {test_file}")

    try:
        # Test file opening and size detection
        with ChunkedFileReader(test_file) as reader:
            file_size = reader.get_file_size()
            logger.info(f"File size: {file_size / 1024 / 1024:.2f} MB")
            logger.info(f"Using mmap: {reader.is_using_mmap()}")

            # Test chunked reading
            log_memory_usage("Before reading chunks", logger)
            chunk_count = 0
            total_bytes = 0

            for chunk in reader.read_chunks():
                chunk_count += 1
                total_bytes += len(chunk)

            log_memory_usage("After reading chunks", logger)
            logger.info(f"Read {chunk_count} chunks, {total_bytes} total bytes")

            # Test range reading (read first 16 bytes)
            if file_size >= 16:
                header = reader.read_range(0, 16)
                logger.info(f"First 16 bytes: {header.hex()}")

        logger.info("Test completed successfully")

    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)
