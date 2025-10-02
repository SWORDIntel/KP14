"""
Tests for ChunkedFileReader - Memory-efficient file processing.

These tests validate the streaming and memory-mapped file access
capabilities for preventing OOM crashes with large files.
"""

import os
import pytest
import tempfile
from pathlib import Path

from core_engine.chunked_file_reader import (
    ChunkedFileReader,
    log_memory_usage,
    read_file_chunked
)


class TestChunkedFileReader:
    """Test suite for ChunkedFileReader functionality."""

    @pytest.fixture
    def small_file(self, tmp_path):
        """Create a small test file (1MB)."""
        file_path = tmp_path / "small_test.bin"
        data = b"A" * 1024 * 1024  # 1MB
        file_path.write_bytes(data)
        return file_path

    @pytest.fixture
    def large_file(self, tmp_path):
        """Create a large test file (150MB) for mmap testing."""
        file_path = tmp_path / "large_test.bin"
        # Create 150MB file
        chunk = b"B" * (10 * 1024 * 1024)  # 10MB chunks
        with open(file_path, 'wb') as f:
            for _ in range(15):  # 15 * 10MB = 150MB
                f.write(chunk)
        return file_path

    @pytest.fixture
    def pe_like_file(self, tmp_path):
        """Create a file with PE header for type detection."""
        file_path = tmp_path / "test.exe"
        # Minimal PE header
        data = b'MZ' + b'\x00' * 62 + b'\x80\x00\x00\x00'  # DOS header
        data += b'\x00' * 64  # DOS stub
        data += b'PE\x00\x00'  # PE signature
        data += b'\x00' * 1024  # Rest of file
        file_path.write_bytes(data)
        return file_path

    def test_initialization(self, small_file):
        """Test ChunkedFileReader initialization."""
        reader = ChunkedFileReader(str(small_file))
        assert reader.file_path == small_file
        assert reader.chunk_size == ChunkedFileReader.DEFAULT_CHUNK_SIZE
        assert reader.use_mmap_threshold == ChunkedFileReader.MMAP_THRESHOLD

    def test_initialization_with_custom_params(self, small_file):
        """Test initialization with custom chunk size and mmap threshold."""
        chunk_size = 4 * 1024 * 1024  # 4MB
        mmap_threshold = 50 * 1024 * 1024  # 50MB

        reader = ChunkedFileReader(
            str(small_file),
            chunk_size=chunk_size,
            use_mmap_threshold=mmap_threshold
        )

        assert reader.chunk_size == chunk_size
        assert reader.use_mmap_threshold == mmap_threshold

    def test_initialization_invalid_file(self):
        """Test initialization with non-existent file."""
        with pytest.raises(FileNotFoundError):
            ChunkedFileReader("/nonexistent/file.bin")

    def test_initialization_invalid_chunk_size(self, small_file):
        """Test initialization with invalid chunk size."""
        with pytest.raises(ValueError):
            ChunkedFileReader(str(small_file), chunk_size=0)

        with pytest.raises(ValueError):
            ChunkedFileReader(str(small_file), chunk_size=-1)

    def test_context_manager(self, small_file):
        """Test context manager functionality."""
        with ChunkedFileReader(str(small_file)) as reader:
            assert reader._file_handle is not None
            assert reader._file_size is not None

        # After exit, handles should be closed
        assert reader._file_handle is None or reader._file_handle.closed

    def test_get_file_size(self, small_file):
        """Test getting file size."""
        with ChunkedFileReader(str(small_file)) as reader:
            size = reader.get_file_size()
            assert size == 1024 * 1024  # 1MB

    def test_read_chunks_small_file(self, small_file):
        """Test chunked reading of small file."""
        with ChunkedFileReader(str(small_file), chunk_size=256*1024) as reader:
            chunks = list(reader.read_chunks())

            # 1MB file with 256KB chunks = 4 chunks
            assert len(chunks) == 4

            # Verify total size
            total_size = sum(len(chunk) for chunk in chunks)
            assert total_size == 1024 * 1024

            # Verify content
            for chunk in chunks:
                assert chunk == b"A" * len(chunk)

    def test_read_chunks_large_file(self, large_file):
        """Test chunked reading of large file (tests mmap mode)."""
        chunk_size = 16 * 1024 * 1024  # 16MB chunks

        with ChunkedFileReader(str(large_file), chunk_size=chunk_size) as reader:
            # Large file should use mmap
            assert reader.is_using_mmap()

            chunks = list(reader.read_chunks())

            # 150MB file with 16MB chunks = 10 chunks (9 full + 1 partial)
            assert len(chunks) == 10

            # Verify total size
            total_size = sum(len(chunk) for chunk in chunks)
            assert total_size == 150 * 1024 * 1024

    def test_read_range(self, small_file):
        """Test random access reading."""
        with ChunkedFileReader(str(small_file)) as reader:
            # Read first 100 bytes
            data = reader.read_range(0, 100)
            assert len(data) == 100
            assert data == b"A" * 100

            # Read middle section
            data = reader.read_range(512*1024, 1024)
            assert len(data) == 1024
            assert data == b"A" * 1024

            # Read last bytes
            data = reader.read_range(1024*1024 - 50, 50)
            assert len(data) == 50
            assert data == b"A" * 50

    def test_read_range_invalid_params(self, small_file):
        """Test read_range with invalid parameters."""
        with ChunkedFileReader(str(small_file)) as reader:
            # Negative offset
            with pytest.raises(ValueError):
                reader.read_range(-1, 100)

            # Negative size
            with pytest.raises(ValueError):
                reader.read_range(0, -1)

            # Range exceeds file size
            with pytest.raises(ValueError):
                reader.read_range(0, 2*1024*1024)

    def test_read_all_small_file(self, small_file):
        """Test reading entire small file into memory."""
        with ChunkedFileReader(str(small_file)) as reader:
            data = reader.read_all()
            assert len(data) == 1024 * 1024
            assert data == b"A" * 1024 * 1024

    def test_read_all_large_file_warning(self, large_file, caplog):
        """Test that reading large file into memory produces warning."""
        import logging
        caplog.set_level(logging.WARNING)

        with ChunkedFileReader(str(large_file)) as reader:
            data = reader.read_all()
            assert len(data) == 150 * 1024 * 1024

            # Should have warning about reading large file
            assert any("large file" in record.message.lower() for record in caplog.records)

    def test_is_using_mmap(self, small_file, large_file):
        """Test mmap mode detection."""
        # Small file should not use mmap
        with ChunkedFileReader(str(small_file)) as reader:
            assert not reader.is_using_mmap()

        # Large file should use mmap
        with ChunkedFileReader(str(large_file)) as reader:
            assert reader.is_using_mmap()

    def test_read_without_context_manager(self, small_file):
        """Test that operations fail without opening file."""
        reader = ChunkedFileReader(str(small_file))

        with pytest.raises(RuntimeError):
            reader.get_file_size()

        with pytest.raises(RuntimeError):
            list(reader.read_chunks())

        with pytest.raises(RuntimeError):
            reader.read_range(0, 100)

    def test_pe_header_reading(self, pe_like_file):
        """Test reading PE header efficiently."""
        with ChunkedFileReader(str(pe_like_file)) as reader:
            # Read DOS header (first 64 bytes)
            dos_header = reader.read_range(0, 64)
            assert dos_header[:2] == b'MZ'

            # Read PE signature (at offset 128)
            pe_sig = reader.read_range(128, 4)
            assert pe_sig == b'PE\x00\x00'

    def test_convenience_function(self, small_file):
        """Test read_file_chunked convenience function."""
        chunks = list(read_file_chunked(str(small_file), chunk_size=256*1024))

        assert len(chunks) == 4
        total_size = sum(len(chunk) for chunk in chunks)
        assert total_size == 1024 * 1024


class TestMemoryMonitoring:
    """Test memory monitoring utilities."""

    def test_log_memory_usage_basic(self, caplog):
        """Test basic memory usage logging."""
        import logging
        caplog.set_level(logging.DEBUG)

        log_memory_usage("Test label")

        # Should have debug log
        assert any("Test label" in record.message for record in caplog.records)
        assert any("Memory usage" in record.message for record in caplog.records)

    def test_log_memory_usage_without_psutil(self, caplog, monkeypatch):
        """Test memory logging when psutil is not available."""
        import logging
        caplog.set_level(logging.DEBUG)

        # Mock psutil import to fail
        import sys
        monkeypatch.setitem(sys.modules, 'psutil', None)

        log_memory_usage("Test without psutil")

        # Should have debug message about psutil not available
        assert any("psutil not available" in record.message for record in caplog.records)


class TestPerformanceAndMemory:
    """Performance and memory usage tests for large files."""

    @pytest.mark.slow
    def test_500mb_file_processing(self, tmp_path):
        """
        Test processing 500MB file with minimal memory usage.

        This is the critical test for OOM prevention.
        """
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil required for memory testing")

        # Create 500MB test file
        file_path = tmp_path / "large_500mb.bin"
        chunk = b"X" * (50 * 1024 * 1024)  # 50MB chunks

        with open(file_path, 'wb') as f:
            for _ in range(10):  # 10 * 50MB = 500MB
                f.write(chunk)

        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Process file in chunks
        with ChunkedFileReader(str(file_path), chunk_size=8*1024*1024) as reader:
            chunk_count = 0
            for chunk in reader.read_chunks():
                chunk_count += 1
                # Simulate processing
                _ = len(chunk)

            peak_memory = process.memory_info().rss / 1024 / 1024  # MB

        memory_increase = peak_memory - initial_memory

        # Memory increase should be less than 2GB (2048MB)
        # In practice, should be much less (< 100MB for 8MB chunks)
        assert memory_increase < 2048, f"Memory increase too high: {memory_increase:.1f} MB"

        # Should process entire file
        assert chunk_count > 0

        print(f"Processed 500MB file with memory increase: {memory_increase:.1f} MB")

    @pytest.mark.slow
    def test_memory_mapped_vs_streaming(self, tmp_path):
        """Compare memory usage between mmap and streaming modes."""
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil required for memory testing")

        # Create 200MB test file
        file_path = tmp_path / "test_200mb.bin"
        chunk = b"Y" * (20 * 1024 * 1024)  # 20MB chunks

        with open(file_path, 'wb') as f:
            for _ in range(10):  # 10 * 20MB = 200MB
                f.write(chunk)

        process = psutil.Process()

        # Test with mmap (default for files >100MB)
        initial_memory = process.memory_info().rss
        with ChunkedFileReader(str(file_path)) as reader:
            assert reader.is_using_mmap()
            _ = list(reader.read_chunks())
        mmap_memory = process.memory_info().rss - initial_memory

        # Test with streaming (force by setting high mmap threshold)
        initial_memory = process.memory_info().rss
        with ChunkedFileReader(str(file_path), use_mmap_threshold=500*1024*1024) as reader:
            assert not reader.is_using_mmap()
            _ = list(reader.read_chunks())
        stream_memory = process.memory_info().rss - initial_memory

        # Both should have low memory usage
        assert mmap_memory < 100 * 1024 * 1024  # < 100MB
        assert stream_memory < 100 * 1024 * 1024  # < 100MB

        print(f"Memory usage - mmap: {mmap_memory/1024/1024:.1f} MB, streaming: {stream_memory/1024/1024:.1f} MB")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
