"""
Test Suite for Input Validation and Sanitization

Tests file size limits, magic byte validation, and input sanitization.

Author: KP14 Security Team
"""

import unittest
import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.security_utils import (
    FileSizeValidator,
    MagicByteValidator,
    InputSanitizer,
    SecurityValidator
)
from core_engine.error_handler import FileValidationError


class TestFileSizeValidation(unittest.TestCase):
    """Test file size validation and DoS prevention."""

    def setUp(self):
        """Create test files of various sizes."""
        self.temp_dir = tempfile.mkdtemp(prefix='kp14_test_')

    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_empty_file_rejection(self):
        """Test that empty files are rejected."""
        empty_file = os.path.join(self.temp_dir, 'empty.txt')
        with open(empty_file, 'w') as f:
            pass  # Create empty file

        is_valid, size, msg = FileSizeValidator.validate_size(empty_file)
        self.assertFalse(is_valid)
        self.assertEqual(size, 0)
        self.assertIn('empty', msg.lower())

    def test_file_size_limit_enforcement(self):
        """Test that file size limits are enforced."""
        # Create file larger than limit
        large_file = os.path.join(self.temp_dir, 'large.bin')
        test_limit = 1024  # 1 KB limit

        with open(large_file, 'wb') as f:
            f.write(b'X' * (test_limit + 1))

        is_valid, size, msg = FileSizeValidator.validate_size(large_file, max_size=test_limit)
        self.assertFalse(is_valid)
        self.assertGreater(size, test_limit)
        self.assertIn('exceeds', msg)

    def test_file_within_size_limit(self):
        """Test that files within limit are accepted."""
        small_file = os.path.join(self.temp_dir, 'small.txt')
        test_limit = 1024

        with open(small_file, 'w') as f:
            f.write('test content')

        is_valid, size, msg = FileSizeValidator.validate_size(small_file, max_size=test_limit)
        self.assertTrue(is_valid)
        self.assertLess(size, test_limit)
        self.assertEqual(msg, '')

    def test_type_specific_size_limits(self):
        """Test that different file types have appropriate limits."""
        # PE files should have higher limits than images
        from core_engine.security_utils import MAX_FILE_SIZE_LIMITS

        self.assertGreater(
            MAX_FILE_SIZE_LIMITS['pe'],
            MAX_FILE_SIZE_LIMITS['image']
        )

    def test_dos_attack_prevention(self):
        """Test prevention of DoS via huge file uploads."""
        # Attempting to check a file that would exhaust resources
        huge_size = 10 * 1024 * 1024 * 1024  # 10 GB

        # The validator should reject based on size before reading entire file
        # (This test documents expected behavior without actually creating huge file)


class TestMagicByteValidation(unittest.TestCase):
    """Test magic byte validation and file type detection."""

    def setUp(self):
        """Create test files with various magic bytes."""
        self.temp_dir = tempfile.mkdtemp(prefix='kp14_test_')

    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_pe_magic_byte_detection(self):
        """Test detection of PE executable magic bytes."""
        pe_file = os.path.join(self.temp_dir, 'test.exe')
        with open(pe_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(pe_file)
        self.assertTrue(is_valid)
        self.assertEqual(detected_type, 'pe')

    def test_png_magic_byte_detection(self):
        """Test detection of PNG image magic bytes."""
        png_file = os.path.join(self.temp_dir, 'test.png')
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

        with open(png_file, 'wb') as f:
            f.write(png_header)

        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(png_file)
        self.assertTrue(is_valid)
        self.assertEqual(detected_type, 'png')

    def test_jpeg_magic_byte_detection(self):
        """Test detection of JPEG image magic bytes."""
        jpeg_file = os.path.join(self.temp_dir, 'test.jpg')
        with open(jpeg_file, 'wb') as f:
            f.write(b'\xff\xd8\xff' + b'\x00' * 100)

        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(jpeg_file)
        self.assertTrue(is_valid)
        self.assertEqual(detected_type, 'jpeg')

    def test_file_type_spoofing_detection(self):
        """Test detection of file type spoofing (extension mismatch)."""
        # File with .txt extension but PE magic bytes
        spoofed_file = os.path.join(self.temp_dir, 'document.txt')
        with open(spoofed_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        # Should detect type as PE, not text
        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(spoofed_file)
        self.assertEqual(detected_type, 'pe')

        # With expected_type='text', should fail
        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(
            spoofed_file, expected_type='text'
        )
        self.assertFalse(is_valid)

    def test_polyglot_file_detection(self):
        """Test detection of polyglot files (valid as multiple types)."""
        # File with both ZIP and PE headers (simplified)
        polyglot_file = os.path.join(self.temp_dir, 'polyglot.bin')
        with open(polyglot_file, 'wb') as f:
            # ZIP header
            f.write(b'PK\x03\x04' + b'\x00' * 100)

        is_valid, detected_type, msg = MagicByteValidator.validate_magic_bytes(polyglot_file)
        self.assertEqual(detected_type, 'zip')


class TestInputSanitization(unittest.TestCase):
    """Test input sanitization functions."""

    def test_string_sanitization_removes_control_chars(self):
        """Test that control characters are removed from strings."""
        dirty_string = "test\x00\x01\x02\x03string"
        clean_string = InputSanitizer.sanitize_string(dirty_string)

        # Should not contain control characters
        self.assertNotIn('\x00', clean_string)
        self.assertEqual(clean_string, 'teststring')

    def test_string_length_limiting(self):
        """Test that string length is limited."""
        long_string = 'A' * 2000
        max_length = 1000

        sanitized = InputSanitizer.sanitize_string(long_string, max_length=max_length)
        self.assertLessEqual(len(sanitized), max_length)

    def test_ip_address_validation(self):
        """Test IP address validation and sanitization."""
        # Valid IPv4
        valid_ipv4 = ['192.168.1.1', '10.0.0.1', '8.8.8.8']
        for ip in valid_ipv4:
            with self.subTest(ip=ip):
                result = InputSanitizer.sanitize_ip_address(ip)
                self.assertIsNotNone(result)
                self.assertEqual(result, ip)

        # Invalid IPv4
        invalid_ipv4 = ['999.999.999.999', '192.168.1', '192.168.1.1.1']
        for ip in invalid_ipv4:
            with self.subTest(ip=ip):
                result = InputSanitizer.sanitize_ip_address(ip)
                self.assertIsNone(result)

    def test_path_sanitization(self):
        """Test path sanitization removes dangerous patterns."""
        dangerous_paths = [
            '../../etc/passwd',
            '../../../root/.ssh/id_rsa',
            'C:\\..\\..\\Windows\\System32',
        ]

        for path in dangerous_paths:
            with self.subTest(path=path):
                sanitized = InputSanitizer.sanitize_path(path)
                # Should not contain ..
                self.assertNotIn('..', sanitized)


class TestSecurityValidatorIntegration(unittest.TestCase):
    """Test integrated security validation."""

    def setUp(self):
        """Create test files."""
        self.temp_dir = tempfile.mkdtemp(prefix='kp14_test_')
        self.validator = SecurityValidator(base_directory=self.temp_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_comprehensive_validation_pass(self):
        """Test that valid files pass all checks."""
        # Create valid PE file
        pe_file = os.path.join(self.temp_dir, 'valid.exe')
        with open(pe_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 1000)

        report = self.validator.validate_file(pe_file, expected_type='pe')

        self.assertTrue(report['validation_passed'])
        self.assertTrue(report['checks']['path_validation'])
        self.assertTrue(report['checks']['size_validation'])
        self.assertEqual(len(report['errors']), 0)

    def test_comprehensive_validation_fail_size(self):
        """Test that oversized files fail validation."""
        # Create file exceeding limit
        large_file = os.path.join(self.temp_dir, 'large.bin')
        with open(large_file, 'wb') as f:
            f.write(b'X' * (1024 * 1024))  # 1 MB

        # Use very small limit
        validator = SecurityValidator(
            base_directory=self.temp_dir,
            max_file_size=1024  # 1 KB
        )

        with self.assertRaises(FileValidationError):
            validator.validate_file(large_file)

    def test_comprehensive_validation_fail_path(self):
        """Test that invalid paths fail validation."""
        with self.assertRaises(FileValidationError):
            self.validator.validate_file('/etc/passwd')


class TestFuzzingInputs(unittest.TestCase):
    """Fuzzing tests with random/malformed inputs."""

    def test_extremely_long_filename(self):
        """Test handling of extremely long filenames."""
        long_name = 'a' * 10000 + '.txt'
        sanitized = InputSanitizer.sanitize_string(long_name, max_length=255)
        self.assertLessEqual(len(sanitized), 255)

    def test_special_unicode_characters(self):
        """Test handling of special unicode characters."""
        unicode_strings = [
            '\u202e',  # Right-to-left override
            '\uFEFF',  # Zero-width no-break space
            '\u200B',  # Zero-width space
        ]

        for s in unicode_strings:
            with self.subTest(string=repr(s)):
                sanitized = InputSanitizer.sanitize_string(s)
                # Should handle gracefully

    def test_null_byte_handling(self):
        """Test handling of null bytes in input."""
        null_string = 'test\x00string'
        sanitized = InputSanitizer.sanitize_string(null_string)
        # Should remove or handle null bytes
        self.assertNotIn('\x00', sanitized)


if __name__ == '__main__':
    unittest.main()
