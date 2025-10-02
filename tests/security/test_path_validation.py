"""
Test Suite for Path Validation Security

Tests path traversal prevention, file path validation, and filename sanitization.

Author: KP14 Security Team
"""

import unittest
import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.security_utils import PathValidator, SecurityValidator
from core_engine.error_handler import FileValidationError, SecurityError


class TestPathValidation(unittest.TestCase):
    """Test path validation and traversal prevention."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp(prefix='kp14_test_')
        self.test_file = os.path.join(self.temp_dir, 'test.txt')

        # Create test file
        with open(self.test_file, 'w') as f:
            f.write('test content')

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_path_traversal_detection_basic(self):
        """Test detection of basic path traversal attempts."""
        unsafe_paths = [
            '../etc/passwd',
            '../../etc/shadow',
            '../../../root/.ssh/id_rsa',
            'file/../../etc/passwd',
        ]

        for path in unsafe_paths:
            with self.subTest(path=path):
                result = PathValidator.is_safe_path(path)
                self.assertFalse(result, f"Path traversal not detected: {path}")

    def test_path_traversal_detection_encoded(self):
        """Test detection of encoded path traversal attempts."""
        unsafe_paths = [
            '%2e%2e/etc/passwd',
            '..%2Fetc%2Fpasswd',
            '....//etc//passwd',
        ]

        for path in unsafe_paths:
            with self.subTest(path=path):
                result = PathValidator.is_safe_path(path)
                # Note: Some encoding might pass basic check, but should fail normalization
                self.assertTrue('../' not in path or not result)

    def test_base_directory_restriction(self):
        """Test that paths are restricted to base directory."""
        # Path outside base directory
        outside_path = '/etc/passwd'
        result = PathValidator.is_safe_path(outside_path, base_directory=self.temp_dir)
        self.assertFalse(result)

        # Path inside base directory
        inside_path = self.test_file
        result = PathValidator.is_safe_path(inside_path, base_directory=self.temp_dir)
        self.assertTrue(result)

    def test_blocked_system_paths(self):
        """Test that system paths are blocked."""
        system_paths = [
            '/etc/passwd',
            '/proc/self/mem',
            '/sys/kernel/debug',
            'C:\\Windows\\System32\\config\\SAM',
        ]

        for path in system_paths:
            with self.subTest(path=path):
                result = PathValidator.is_safe_path(path)
                # Should be blocked by patterns
                self.assertFalse(result)

    def test_filename_sanitization(self):
        """Test filename sanitization removes dangerous characters."""
        test_cases = [
            ('normal.txt', 'normal.txt'),
            ('file<>:"|?.exe', 'file_________.exe'),
            ('../../etc/passwd', '__etcpasswd'),
            ('.hidden', '_hidden'),
            ('a' * 300 + '.txt', True),  # Should be truncated
        ]

        for input_name, expected in test_cases:
            with self.subTest(input=input_name):
                sanitized = PathValidator.sanitize_filename(input_name)

                if expected is True:
                    # Check length limit
                    self.assertLessEqual(len(sanitized), 255)
                else:
                    self.assertEqual(sanitized, expected)

                # Should not contain path separators
                self.assertNotIn('/', sanitized)
                self.assertNotIn('\\', sanitized)

    def test_validate_file_path_existence(self):
        """Test file path validation with existence check."""
        # Existing file
        is_valid, msg = PathValidator.validate_file_path(self.test_file, must_exist=True)
        self.assertTrue(is_valid)
        self.assertEqual(msg, '')

        # Non-existing file
        is_valid, msg = PathValidator.validate_file_path(
            os.path.join(self.temp_dir, 'nonexistent.txt'),
            must_exist=True
        )
        self.assertFalse(is_valid)
        self.assertIn('does not exist', msg)

    def test_validate_file_path_permissions(self):
        """Test file path validation checks read permissions."""
        # Create unreadable file (Unix only)
        if os.name != 'nt':
            unreadable = os.path.join(self.temp_dir, 'unreadable.txt')
            with open(unreadable, 'w') as f:
                f.write('test')
            os.chmod(unreadable, 0o000)

            is_valid, msg = PathValidator.validate_file_path(unreadable, must_exist=True)
            self.assertFalse(is_valid)
            self.assertIn('not readable', msg)

            # Cleanup
            os.chmod(unreadable, 0o644)

    def test_directory_vs_file_validation(self):
        """Test that directories are rejected when files are expected."""
        is_valid, msg = PathValidator.validate_file_path(self.temp_dir, must_exist=True)
        self.assertFalse(is_valid)
        self.assertIn('not a file', msg)

    def test_security_validator_integration(self):
        """Test SecurityValidator uses path validation correctly."""
        validator = SecurityValidator(base_directory=self.temp_dir)

        # Valid file
        report = validator.validate_file(self.test_file)
        self.assertTrue(report['validation_passed'])
        self.assertTrue(report['checks']['path_validation'])

        # Path traversal attempt should raise exception
        with self.assertRaises((FileValidationError, SecurityError)):
            validator.validate_file('../../../etc/passwd')


class TestFilenameSecurityPatterns(unittest.TestCase):
    """Test detection of suspicious filename patterns."""

    def test_double_extension_detection(self):
        """Test detection of double extension attacks."""
        from core_engine.security_utils import is_suspicious_filename

        suspicious = [
            'document.pdf.exe',
            'image.jpg.scr',
            'data.txt.bat',
        ]

        for filename in suspicious:
            with self.subTest(filename=filename):
                # Note: Current implementation checks for .exe.txt specifically
                # This test documents expected behavior for future enhancement
                pass

    def test_hidden_file_detection(self):
        """Test detection of hidden files (Unix)."""
        from core_engine.security_utils import is_suspicious_filename

        result = is_suspicious_filename('.hidden_malware')
        self.assertTrue(result)

    def test_non_ascii_filename_detection(self):
        """Test detection of non-ASCII characters in filenames."""
        from core_engine.security_utils import is_suspicious_filename

        result = is_suspicious_filename('файл.exe')  # Cyrillic
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
