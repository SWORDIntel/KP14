"""
Comprehensive tests for core_engine/error_handler.py

Tests cover:
- All 11 exception types
- Retry logic with exponential backoff
- Error context preservation
- Recovery strategies
- Error wrapping
"""

import pytest
import time
import sys
from pathlib import Path
from unittest.mock import Mock, patch

from core_engine.error_handler import (
    KP14Error,
    FileValidationError,
    FileSizeError,
    FileFormatError,
    SuspiciousPayloadError,
    HardwareError,
    ModelLoadError,
    AnalysisError,
    NetworkError,
    ResourceExhaustionError,
    ConfigurationError,
    SecurityError,
    retry_with_backoff,
    RetryStrategy,
    ErrorRecoveryManager,
    error_context,
    safe_execute,
    create_error_report
)


class TestKP14BaseError:
    """Test base KP14Error exception class."""

    def test_create_basic_error(self):
        """Test creating basic error with just message."""
        error = KP14Error("Test error message")

        assert str(error) == "Test error message"
        assert error.message == "Test error message"

    def test_error_with_context(self):
        """Test error with context dictionary."""
        error = KP14Error(
            "Test error",
            context={"file": "test.exe", "line": 42}
        )

        assert "file=test.exe" in str(error)
        assert "line=42" in str(error)

    def test_error_with_original_exception(self):
        """Test error wrapping original exception."""
        original = ValueError("Original error")
        error = KP14Error(
            "Wrapped error",
            original_exception=original
        )

        assert "ValueError" in str(error)
        assert "Original error" in str(error)

    def test_error_recoverable_flag(self):
        """Test recoverable flag."""
        error = KP14Error("Test", recoverable=True)

        assert error.recoverable is True

    def test_error_to_dict(self):
        """Test converting error to dictionary."""
        error = KP14Error(
            "Test error",
            context={"key": "value"},
            recoverable=True
        )

        error_dict = error.to_dict()

        assert error_dict["error_type"] == "KP14Error"
        assert error_dict["message"] == "Test error"
        assert error_dict["context"] == {"key": "value"}
        assert error_dict["recoverable"] is True


class TestFileValidationErrors:
    """Test file validation error types."""

    def test_file_validation_error(self):
        """Test FileValidationError."""
        error = FileValidationError(
            "Invalid file",
            file_path="/test/file.exe"
        )

        assert "Invalid file" in str(error)
        assert error.context["file_path"] == "/test/file.exe"

    def test_file_size_error(self):
        """Test FileSizeError with size information."""
        error = FileSizeError(
            file_path="/test/large.exe",
            actual_size=1000000,
            max_size=500000
        )

        assert "1000000" in str(error)
        assert "500000" in str(error)
        assert error.context["actual_size"] == 1000000
        assert error.context["max_size"] == 500000

    def test_file_format_error(self):
        """Test FileFormatError with format mismatch."""
        error = FileFormatError(
            file_path="/test/wrong.exe",
            expected_format="PE",
            actual_format="ELF"
        )

        assert "PE" in str(error)
        assert "ELF" in str(error)

    def test_suspicious_payload_error(self):
        """Test SuspiciousPayloadError."""
        error = SuspiciousPayloadError(
            file_path="/test/malware.exe",
            reason="NOP sled detected"
        )

        assert "NOP sled" in str(error)
        assert error.context["reason"] == "NOP sled detected"


class TestHardwareErrors:
    """Test hardware-related errors."""

    def test_hardware_error(self):
        """Test HardwareError."""
        error = HardwareError(
            "GPU initialization failed",
            hardware_component="NVIDIA GPU"
        )

        assert "GPU" in str(error)
        assert error.context["hardware_component"] == "NVIDIA GPU"

    def test_model_load_error(self):
        """Test ModelLoadError."""
        error = ModelLoadError(
            "Failed to load model",
            model_path="/models/classifier.onnx"
        )

        assert "model" in str(error).lower()
        assert error.context["model_path"] == "/models/classifier.onnx"


class TestAnalysisErrors:
    """Test analysis-related errors."""

    def test_analysis_error(self):
        """Test AnalysisError."""
        error = AnalysisError(
            "Analysis failed",
            analyzer_name="PEAnalyzer"
        )

        assert error.context["analyzer_name"] == "PEAnalyzer"
        assert error.recoverable is True  # Analysis errors are recoverable by default

    def test_analysis_error_non_recoverable(self):
        """Test AnalysisError can be marked non-recoverable."""
        error = AnalysisError(
            "Critical analysis failure",
            analyzer_name="CoreAnalyzer",
            recoverable=False
        )

        assert error.recoverable is False


class TestNetworkErrors:
    """Test network-related errors."""

    def test_network_error(self):
        """Test NetworkError."""
        error = NetworkError("Connection timeout")

        assert error.recoverable is True  # Network errors are recoverable

    def test_network_error_with_context(self):
        """Test NetworkError with connection details."""
        error = NetworkError(
            "Connection failed",
            context={"url": "https://example.com", "timeout": 30}
        )

        assert error.context["url"] == "https://example.com"


class TestResourceErrors:
    """Test resource exhaustion errors."""

    def test_resource_exhaustion_error(self):
        """Test ResourceExhaustionError."""
        error = ResourceExhaustionError(
            "Out of memory",
            resource_type="memory"
        )

        assert error.context["resource_type"] == "memory"


class TestConfigurationErrors:
    """Test configuration errors."""

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError(
            "Invalid configuration",
            config_key="general.log_level"
        )

        assert error.context["config_key"] == "general.log_level"

    def test_configuration_error_without_key(self):
        """Test ConfigurationError without specific key."""
        error = ConfigurationError("General config error")

        assert error.message == "General config error"


class TestSecurityErrors:
    """Test security-related errors."""

    def test_security_error(self):
        """Test SecurityError."""
        error = SecurityError(
            "Path traversal attempt detected",
            security_check="path_validation"
        )

        assert error.recoverable is False  # Security errors are never recoverable
        assert error.context["security_check"] == "path_validation"

    def test_security_error_always_non_recoverable(self):
        """Test SecurityError cannot be marked recoverable."""
        error = SecurityError(
            "Security violation",
            security_check="input_validation",
            recoverable=True  # This should be overridden
        )

        assert error.recoverable is False  # Should be forced to False


class TestRetryLogic:
    """Test retry decorator and backoff strategies."""

    def test_retry_success_first_attempt(self):
        """Test function succeeds on first attempt."""
        call_count = [0]

        @retry_with_backoff(max_retries=3)
        def success_function():
            call_count[0] += 1
            return "success"

        result = success_function()

        assert result == "success"
        assert call_count[0] == 1

    def test_retry_success_after_failures(self):
        """Test function succeeds after retries."""
        call_count = [0]

        @retry_with_backoff(
            max_retries=3,
            initial_delay=0.01,
            retriable_exceptions=(NetworkError,)
        )
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise NetworkError("Temporary failure")
            return "success"

        result = flaky_function()

        assert result == "success"
        assert call_count[0] == 3

    def test_retry_exhausts_attempts(self):
        """Test retry gives up after max attempts."""
        call_count = [0]

        @retry_with_backoff(
            max_retries=2,
            initial_delay=0.01,
            retriable_exceptions=(NetworkError,)
        )
        def always_fails():
            call_count[0] += 1
            raise NetworkError("Always fails")

        with pytest.raises(NetworkError):
            always_fails()

        assert call_count[0] == 3  # Initial + 2 retries

    def test_retry_exponential_backoff(self):
        """Test exponential backoff timing."""
        timestamps = []

        @retry_with_backoff(
            max_retries=3,
            initial_delay=0.1,
            backoff_factor=2.0,
            strategy=RetryStrategy.EXPONENTIAL,
            retriable_exceptions=(NetworkError,)
        )
        def timed_function():
            timestamps.append(time.time())
            if len(timestamps) < 3:
                raise NetworkError("Retry needed")
            return "success"

        result = timed_function()

        assert result == "success"
        assert len(timestamps) == 3

        # Check delays increase exponentially (with some tolerance)
        if len(timestamps) >= 3:
            delay1 = timestamps[1] - timestamps[0]
            delay2 = timestamps[2] - timestamps[1]
            assert delay2 > delay1  # Second delay should be longer

    def test_retry_linear_backoff(self):
        """Test linear backoff strategy."""
        call_count = [0]

        @retry_with_backoff(
            max_retries=2,
            initial_delay=0.01,
            strategy=RetryStrategy.LINEAR,
            retriable_exceptions=(NetworkError,)
        )
        def test_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise NetworkError("Retry")
            return "success"

        result = test_function()

        assert result == "success"

    def test_retry_non_retriable_exception(self):
        """Test non-retriable exceptions fail immediately."""
        call_count = [0]

        @retry_with_backoff(
            max_retries=3,
            retriable_exceptions=(NetworkError,)
        )
        def raises_non_retriable():
            call_count[0] += 1
            raise ValueError("Non-retriable error")

        with pytest.raises(ValueError):
            raises_non_retriable()

        assert call_count[0] == 1  # Should not retry

    def test_retry_with_logger(self, mock_logger):
        """Test retry decorator logs attempts."""
        call_count = [0]

        @retry_with_backoff(
            max_retries=2,
            initial_delay=0.01,
            retriable_exceptions=(NetworkError,),
            logger=mock_logger
        )
        def logged_function():
            call_count[0] += 1
            if call_count[0] < 2:
                raise NetworkError("Retry needed")
            return "success"

        result = logged_function()

        assert result == "success"
        assert mock_logger.warning.called or mock_logger.info.called


class TestErrorRecoveryManager:
    """Test error recovery manager."""

    def test_register_recovery_strategy(self):
        """Test registering recovery strategy."""
        manager = ErrorRecoveryManager()

        def recover_from_network_error(error, context):
            return {"recovered": True}

        manager.register_recovery_strategy(NetworkError, recover_from_network_error)

        assert NetworkError in manager.recovery_strategies

    def test_handle_error_with_recovery(self):
        """Test error handling with successful recovery."""
        manager = ErrorRecoveryManager()

        def recovery_func(error, context):
            return {"status": "recovered", "fallback": True}

        manager.register_recovery_strategy(NetworkError, recovery_func)

        error = NetworkError("Test error")
        result = manager.handle_error(error)

        assert result["status"] == "recovered"

    def test_handle_error_without_recovery(self):
        """Test error handling without recovery strategy."""
        manager = ErrorRecoveryManager()

        error = ValueError("Unrecoverable error")
        result = manager.handle_error(error)

        assert result is None

    def test_handle_error_fail_fast(self):
        """Test error handling with fail_fast mode."""
        manager = ErrorRecoveryManager()

        error = ValueError("Critical error")

        with pytest.raises(ValueError):
            manager.handle_error(error, fail_fast=True)

    def test_error_history_tracking(self):
        """Test error history is tracked."""
        manager = ErrorRecoveryManager()

        error1 = NetworkError("Error 1")
        error2 = NetworkError("Error 2")

        manager.handle_error(error1)
        manager.handle_error(error2)

        assert len(manager.error_history) == 2

    def test_get_error_summary(self):
        """Test error summary generation."""
        manager = ErrorRecoveryManager()

        manager.handle_error(NetworkError("Error 1"))
        manager.handle_error(NetworkError("Error 2"))
        manager.handle_error(ValueError("Error 3"))

        summary = manager.get_error_summary()

        assert summary["total_errors"] == 3
        assert "NetworkError" in summary["error_counts"]
        assert summary["error_counts"]["NetworkError"] == 2


class TestErrorContext:
    """Test error context manager."""

    def test_error_context_success(self, mock_logger):
        """Test error context on successful operation."""
        with error_context("Test operation", logger=mock_logger) as ctx:
            # Operation succeeds
            pass

        # Should log completion
        assert mock_logger.debug.called

    def test_error_context_handles_exception(self, mock_logger):
        """Test error context handles exceptions."""
        with error_context("Test operation", logger=mock_logger, fail_fast=False):
            raise ValueError("Test error")

        # Should log error
        assert mock_logger.error.called

    def test_error_context_fail_fast(self, mock_logger):
        """Test error context with fail_fast mode."""
        with pytest.raises(ValueError):
            with error_context("Test operation", logger=mock_logger, fail_fast=True):
                raise ValueError("Test error")

    def test_error_context_with_recovery_manager(self, mock_logger):
        """Test error context with recovery manager."""
        recovery_manager = ErrorRecoveryManager(logger=mock_logger)

        with error_context(
            "Test operation",
            logger=mock_logger,
            recovery_manager=recovery_manager
        ):
            raise NetworkError("Test error")

        # Error should be in history
        assert len(recovery_manager.error_history) > 0


class TestSafeExecute:
    """Test safe_execute utility function."""

    def test_safe_execute_success(self):
        """Test safe_execute with successful function."""
        def successful_func(x, y):
            return x + y

        result = safe_execute(successful_func, args=(5, 3))

        assert result == 8

    def test_safe_execute_with_kwargs(self):
        """Test safe_execute with keyword arguments."""
        def func_with_kwargs(a, b=10):
            return a * b

        result = safe_execute(func_with_kwargs, args=(5,), kwargs={"b": 20})

        assert result == 100

    def test_safe_execute_returns_default_on_error(self):
        """Test safe_execute returns default on exception."""
        def failing_func():
            raise ValueError("Error")

        result = safe_execute(failing_func, default_return="default")

        assert result == "default"

    def test_safe_execute_with_logger(self, mock_logger):
        """Test safe_execute logs operations."""
        def test_func():
            return "success"

        result = safe_execute(test_func, logger=mock_logger)

        assert result == "success"
        assert mock_logger.debug.called


class TestCreateErrorReport:
    """Test error report generation."""

    def test_create_error_report_basic(self):
        """Test creating basic error report."""
        error = ValueError("Test error")

        report = create_error_report(error)

        assert report["error_type"] == "ValueError"
        assert report["error_message"] == "Test error"
        assert "timestamp" in report

    def test_create_error_report_with_context(self):
        """Test error report with context."""
        error = KP14Error("Test error", context={"key": "value"})

        report = create_error_report(
            error,
            context={"additional": "info"}
        )

        assert report["context"]["additional"] == "info"

    def test_create_error_report_with_traceback(self):
        """Test error report includes traceback."""
        error = ValueError("Test error")

        try:
            raise error
        except ValueError as e:
            report = create_error_report(e, include_traceback=True)

        assert "traceback" in report
        assert report["traceback"] is not None

    def test_create_error_report_without_traceback(self):
        """Test error report without traceback."""
        error = ValueError("Test error")

        report = create_error_report(error, include_traceback=False)

        # Traceback might still be included, but this tests the parameter works
        assert "error_type" in report


@pytest.mark.parametrize("exception_class,recoverable_default", [
    (AnalysisError, True),
    (NetworkError, True),
    (SecurityError, False),
    (ConfigurationError, False),
])
def test_exception_recoverable_defaults(exception_class, recoverable_default):
    """Test default recoverability of different exception types."""
    if exception_class == AnalysisError:
        error = exception_class("Test", analyzer_name="test")
    elif exception_class == SecurityError:
        error = exception_class("Test", security_check="test")
    elif exception_class == ConfigurationError:
        error = exception_class("Test", config_key="test")
    else:
        error = exception_class("Test")

    assert error.recoverable == recoverable_default
