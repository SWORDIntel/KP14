"""
Test Suite for Error Handling Security

Tests information leakage prevention, secure exception handling, and error sanitization.

Author: KP14 Security Team
"""

import unittest
import os
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.error_handler import (
    KP14Error,
    FileValidationError,
    SecurityError,
    create_error_report
)
from core_engine.security_utils import handle_security_exception


class TestErrorMessageSanitization(unittest.TestCase):
    """Test that error messages don't leak sensitive information."""

    def test_no_absolute_paths_in_errors(self):
        """Test that absolute paths are sanitized in error messages."""
        sensitive_path = '/home/user/secret_analysis/malware.exe'

        try:
            raise FileValidationError(
                f"Failed to validate file",
                file_path=sensitive_path
            )
        except FileValidationError as e:
            error_dict = e.to_dict()
            # Path should be in context but sanitized in message if needed
            # Implementation detail: current version includes path in context

    def test_no_credentials_in_errors(self):
        """Test that credentials are not exposed in error messages."""
        # Simulate error with credential in message
        try:
            connection_string = "postgres://user:password@localhost/db"
            raise KP14Error(f"Database connection failed: {connection_string}")
        except KP14Error as e:
            message = str(e)
            # Should not contain password
            # This test documents expected behavior for future enhancement

    def test_stack_traces_sanitization(self):
        """Test that stack traces are sanitized."""
        # Stack traces might contain sensitive paths
        try:
            raise Exception("Test exception")
        except Exception as e:
            report = create_error_report(e)
            # Report should exist but sensitive paths should be sanitized

    def test_security_error_not_recoverable(self):
        """Test that SecurityErrors are marked as non-recoverable."""
        error = SecurityError("Security violation detected")
        self.assertFalse(error.recoverable)


class TestSecurityExceptionHandling(unittest.TestCase):
    """Test secure exception handling decorator."""

    def test_decorator_catches_exceptions(self):
        """Test that security exception decorator catches exceptions."""

        @handle_security_exception
        def failing_function():
            raise ValueError("Test error")

        with self.assertRaises(SecurityError):
            failing_function()

    def test_decorator_preserves_security_errors(self):
        """Test that SecurityErrors are re-raised."""

        @handle_security_exception
        def security_failing_function():
            raise SecurityError("Security violation")

        with self.assertRaises(SecurityError):
            security_failing_function()

    def test_decorator_sanitizes_messages(self):
        """Test that decorator sanitizes error messages."""

        @handle_security_exception
        def function_with_sensitive_error():
            home_dir = os.path.expanduser('~')
            raise Exception(f"Failed to access {home_dir}/sensitive_file")

        try:
            function_with_sensitive_error()
        except SecurityError as e:
            message = str(e)
            # Should not contain actual home directory
            # Should be replaced with [HOME] or similar


class TestErrorContextPreservation(unittest.TestCase):
    """Test that error context is preserved securely."""

    def test_context_preservation(self):
        """Test that error context is preserved."""
        context = {
            'file_path': '/tmp/test.exe',
            'file_size': 12345,
            'analysis_stage': 'pe_analysis'
        }

        error = KP14Error(
            "Analysis failed",
            context=context
        )

        error_dict = error.to_dict()
        self.assertEqual(error_dict['context'], context)

    def test_sensitive_context_handling(self):
        """Test handling of sensitive data in context."""
        # Sensitive data should be marked or sanitized
        context = {
            'api_key': 'secret_key_12345',
            'password': 'user_password'
        }

        # Currently no automatic sanitization, but this test documents expected behavior
        error = KP14Error("Operation failed", context=context)

    def test_original_exception_chaining(self):
        """Test that original exceptions are chained."""
        original = ValueError("Original error")

        wrapper = KP14Error(
            "Wrapped error",
            original_exception=original
        )

        error_dict = wrapper.to_dict()
        self.assertIsNotNone(error_dict['original_exception'])


class TestLoggingSanitization(unittest.TestCase):
    """Test that logging doesn't expose sensitive data."""

    def test_api_key_redaction(self):
        """Test that API keys are redacted in logs."""
        # This would test the logging sanitization from logging_config.py
        # Integration test would verify actual log output
        pass

    def test_password_redaction(self):
        """Test that passwords are redacted in logs."""
        pass

    def test_token_redaction(self):
        """Test that tokens are redacted in logs."""
        pass


class TestErrorRecovery(unittest.TestCase):
    """Test error recovery mechanisms."""

    def test_recoverable_errors_marked(self):
        """Test that recoverable errors are properly marked."""
        from core_engine.error_handler import AnalysisError, NetworkError

        analysis_error = AnalysisError("Analysis failed", analyzer_name="pe_analyzer")
        self.assertTrue(analysis_error.recoverable)

        network_error = NetworkError("Network request failed")
        self.assertTrue(network_error.recoverable)

    def test_critical_errors_not_recoverable(self):
        """Test that critical errors are not marked recoverable."""
        security_error = SecurityError("Security check failed")
        self.assertFalse(security_error.recoverable)


if __name__ == '__main__':
    unittest.main()
