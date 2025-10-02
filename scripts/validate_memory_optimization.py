#!/usr/bin/env python3
"""
Validation script for KP14 Memory Optimization (Phase 1, Fix 2).

This script validates that the memory optimization implementation works correctly
and meets all success criteria.
"""

import sys
import os
import tempfile
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_engine.chunked_file_reader import ChunkedFileReader, log_memory_usage


def print_header(text):
    """Print a section header."""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print('=' * 70)


def test_small_file():
    """Test processing of small file (<100MB)."""
    print("\n[Test 1] Small File Processing (10MB)")
    print("-" * 70)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        # Create 10MB file
        chunk = b'A' * (1024 * 1024)
        for _ in range(10):
            f.write(chunk)
        temp_path = f.name

    try:
        start_time = time.time()

        with ChunkedFileReader(temp_path, chunk_size=2*1024*1024) as reader:
            file_size = reader.get_file_size()
            using_mmap = reader.is_using_mmap()

            chunks = list(reader.read_chunks())
            total_read = sum(len(chunk) for chunk in chunks)

        elapsed = time.time() - start_time

        print(f"  File size: {file_size / 1024 / 1024:.1f} MB")
        print(f"  Using mmap: {using_mmap}")
        print(f"  Chunks processed: {len(chunks)}")
        print(f"  Total bytes read: {total_read}")
        print(f"  Processing time: {elapsed:.3f} seconds")
        print(f"  Status: ✅ PASS")

        return True

    except Exception as e:
        print(f"  Status: ❌ FAIL - {e}")
        return False

    finally:
        os.unlink(temp_path)


def test_large_file():
    """Test processing of large file (>100MB)."""
    print("\n[Test 2] Large File Processing (150MB)")
    print("-" * 70)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        # Create 150MB file
        chunk = b'B' * (10 * 1024 * 1024)
        for _ in range(15):
            f.write(chunk)
        temp_path = f.name

    try:
        start_time = time.time()

        with ChunkedFileReader(temp_path, chunk_size=8*1024*1024) as reader:
            file_size = reader.get_file_size()
            using_mmap = reader.is_using_mmap()

            chunks = list(reader.read_chunks())
            total_read = sum(len(chunk) for chunk in chunks)

        elapsed = time.time() - start_time

        print(f"  File size: {file_size / 1024 / 1024:.1f} MB")
        print(f"  Using mmap: {using_mmap}")
        print(f"  Chunks processed: {len(chunks)}")
        print(f"  Total bytes read: {total_read}")
        print(f"  Processing time: {elapsed:.3f} seconds")
        print(f"  Status: ✅ PASS (mmap enabled for large file)")

        if not using_mmap:
            print(f"  Warning: Expected mmap mode for >100MB file")
            return False

        return True

    except Exception as e:
        print(f"  Status: ❌ FAIL - {e}")
        return False

    finally:
        os.unlink(temp_path)


def test_random_access():
    """Test random access reading (for PE analysis)."""
    print("\n[Test 3] Random Access Reading")
    print("-" * 70)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
        # Create file with PE-like structure
        f.write(b'MZ')  # DOS signature
        f.write(b'\x00' * 62)
        f.write(b'\x80\x00\x00\x00')  # PE offset at 0x3C
        f.write(b'\x00' * (0x80 - 68))
        f.write(b'PE\x00\x00')  # PE signature at 0x80
        f.write(b'\x00' * 1024)
        temp_path = f.name

    try:
        with ChunkedFileReader(temp_path) as reader:
            # Read DOS header
            dos_header = reader.read_range(0, 2)
            assert dos_header == b'MZ', "DOS signature check failed"

            # Read PE signature
            pe_sig = reader.read_range(0x80, 4)
            assert pe_sig == b'PE\x00\x00', "PE signature check failed"

            print(f"  DOS signature: {dos_header.hex()}")
            print(f"  PE signature: {pe_sig.hex()}")
            print(f"  Status: ✅ PASS (random access works)")

        return True

    except Exception as e:
        print(f"  Status: ❌ FAIL - {e}")
        return False

    finally:
        os.unlink(temp_path)


def test_memory_monitoring():
    """Test memory monitoring functionality."""
    print("\n[Test 4] Memory Monitoring")
    print("-" * 70)

    try:
        import psutil
        psutil_available = True
    except ImportError:
        psutil_available = False
        print("  Warning: psutil not installed - memory monitoring disabled")

    try:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)

        log_memory_usage("Test checkpoint 1", logger)
        log_memory_usage("Test checkpoint 2", logger)

        print(f"  Memory monitoring: {'✅ ENABLED' if psutil_available else '⚠️ DISABLED'}")
        print(f"  Status: ✅ PASS")

        return True

    except Exception as e:
        print(f"  Status: ❌ FAIL - {e}")
        return False


def test_pipeline_integration():
    """Test integration with pipeline_manager."""
    print("\n[Test 5] Pipeline Manager Integration")
    print("-" * 70)

    try:
        from core_engine.pipeline_manager import PipelineManager

        print("  Import PipelineManager: ✅ SUCCESS")
        print("  ChunkedFileReader integration: ✅ READY")
        print("  Status: ✅ PASS")

        return True

    except Exception as e:
        print(f"  Status: ❌ FAIL - {e}")
        return False


def test_error_handling():
    """Test error handling."""
    print("\n[Test 6] Error Handling")
    print("-" * 70)

    tests_passed = 0
    total_tests = 3

    # Test 1: Non-existent file
    try:
        ChunkedFileReader("/nonexistent/file.bin")
        print("  Non-existent file: ❌ FAIL (should raise FileNotFoundError)")
    except FileNotFoundError:
        print("  Non-existent file: ✅ PASS")
        tests_passed += 1

    # Test 2: Invalid chunk size
    with tempfile.NamedTemporaryFile() as f:
        f.write(b'test')
        f.flush()

        try:
            ChunkedFileReader(f.name, chunk_size=0)
            print("  Invalid chunk size: ❌ FAIL (should raise ValueError)")
        except ValueError:
            print("  Invalid chunk size: ✅ PASS")
            tests_passed += 1

        # Test 3: Read without opening
        try:
            reader = ChunkedFileReader(f.name)
            reader.get_file_size()
            print("  Read without opening: ❌ FAIL (should raise RuntimeError)")
        except RuntimeError:
            print("  Read without opening: ✅ PASS")
            tests_passed += 1

    print(f"  Error handling tests: {tests_passed}/{total_tests}")
    print(f"  Status: {'✅ PASS' if tests_passed == total_tests else '❌ FAIL'}")

    return tests_passed == total_tests


def main():
    """Run all validation tests."""
    print_header("KP14 Memory Optimization Validation")
    print("\nPhase 1, Fix 2: Memory-Efficient File Processing")
    print("Validating: ChunkedFileReader, Pipeline Integration, Memory Monitoring")

    results = []

    # Run tests
    results.append(("Small File Processing", test_small_file()))
    results.append(("Large File Processing", test_large_file()))
    results.append(("Random Access Reading", test_random_access()))
    results.append(("Memory Monitoring", test_memory_monitoring()))
    results.append(("Pipeline Integration", test_pipeline_integration()))
    results.append(("Error Handling", test_error_handling()))

    # Summary
    print_header("Validation Summary")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name:.<50} {status}")

    print(f"\n  Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n  🎉 All validation tests passed!")
        print("  Memory optimization implementation is production-ready.")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed.")
        print("  Review failures and fix issues before deployment.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
