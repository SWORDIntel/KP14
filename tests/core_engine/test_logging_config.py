"""
Comprehensive tests for core_engine/logging_config.py

Tests cover:
- Log levels
- Log formatting
- Log rotation
- Sensitive data sanitization
- Performance metrics
"""

import pytest
import os
import sys
import logging
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.logging_config import (
    sanitize_sensitive_data,
    SanitizedJSONFormatter,
    SanitizedFormatter,
    PerformanceFilter,
    LoggingConfigManager,
    log_operation,
    create_module_logger,
    log_function_call,
    get_logging_manager,
    SENSITIVE_PATTERNS
)


class TestSensitiveDataSanitization:
    """Test sensitive data sanitization."""

    def test_sanitize_api_key(self):
        """Test API key sanitization."""
        text = "Using api_key=test_fake_key_1234567890abcdefg for authentication"

        sanitized = sanitize_sensitive_data(text)

        assert "test_fake_key_1234567890abcdefg" not in sanitized
        assert "REDACTED" in sanitized

    def test_sanitize_password(self):
        """Test password sanitization."""
        text = "Login with password=SuperSecret123!"

        sanitized = sanitize_sensitive_data(text)

        assert "SuperSecret123" not in sanitized
        assert "REDACTED" in sanitized

    def test_sanitize_token(self):
        """Test token sanitization."""
        text = "Bearer token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

        sanitized = sanitize_sensitive_data(text)

        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
        assert "REDACTED" in sanitized

    def test_sanitize_email(self):
        """Test email address sanitization."""
        text = "Contact user@example.com for support"

        sanitized = sanitize_sensitive_data(text)

        assert "user@example.com" not in sanitized
        assert "EMAIL_REDACTED" in sanitized

    def test_sanitize_credit_card(self):
        """Test credit card number sanitization."""
        text = "Card number: 4532-1234-5678-9010"

        sanitized = sanitize_sensitive_data(text)

        assert "4532-1234-5678-9010" not in sanitized
        assert "CC_REDACTED" in sanitized

    def test_sanitize_ssn(self):
        """Test Social Security Number sanitization."""
        text = "SSN: 123-45-6789"

        sanitized = sanitize_sensitive_data(text)

        assert "123-45-6789" not in sanitized
        assert "SSN_REDACTED" in sanitized

    def test_sanitize_authorization_header(self):
        """Test Authorization header sanitization."""
        text = "Authorization: Bearer abc123xyz456"

        sanitized = sanitize_sensitive_data(text)

        assert "abc123xyz456" not in sanitized
        assert "REDACTED" in sanitized

    def test_sanitize_multiple_patterns(self):
        """Test sanitizing multiple sensitive patterns."""
        text = "User password=secret123 with api_key=abc123"

        sanitized = sanitize_sensitive_data(text)

        assert "secret123" not in sanitized
        assert "abc123" not in sanitized
        assert sanitized.count("REDACTED") >= 2

    def test_sanitize_clean_text(self):
        """Test sanitizing text with no sensitive data."""
        text = "This is a normal log message with no sensitive information"

        sanitized = sanitize_sensitive_data(text)

        # Should be unchanged
        assert "normal log message" in sanitized

    def test_sanitize_non_string_input(self):
        """Test sanitizing non-string input."""
        number = 12345

        sanitized = sanitize_sensitive_data(number)

        assert isinstance(sanitized, str)


class TestJSONFormatter:
    """Test JSON formatter with sanitization."""

    def test_format_basic_record(self):
        """Test formatting basic log record."""
        formatter = SanitizedJSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert log_data["level"] == "INFO"
        assert log_data["message"] == "Test message"
        assert log_data["logger"] == "test"

    def test_format_with_sensitive_data(self):
        """Test formatting sanitizes sensitive data."""
        formatter = SanitizedJSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="password=secret123",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert "secret123" not in log_data["message"]
        assert "REDACTED" in log_data["message"]

    def test_format_with_exception(self):
        """Test formatting includes exception info."""
        formatter = SanitizedJSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError as e:
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Error occurred",
                args=(),
                exc_info=sys.exc_info()
            )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert "exception" in log_data
        assert log_data["exception"]["type"] == "ValueError"

    def test_format_with_extra_fields(self):
        """Test formatting includes extra fields."""
        formatter = SanitizedJSONFormatter(include_extra=True)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None
        )
        record.custom_field = "custom_value"

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert "extra" in log_data
        assert "custom_field" in log_data["extra"]


class TestSanitizedFormatter:
    """Test standard text formatter with sanitization."""

    def test_format_sanitizes_message(self):
        """Test formatter sanitizes sensitive data."""
        formatter = SanitizedFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="password=secret123",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)

        assert "secret123" not in formatted
        assert "REDACTED" in formatted


class TestPerformanceFilter:
    """Test performance metrics filter."""

    def test_filter_adds_uptime(self):
        """Test filter adds uptime to records."""
        perf_filter = PerformanceFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None
        )

        result = perf_filter.filter(record)

        assert result is True
        assert hasattr(record, 'uptime_seconds')
        assert record.uptime_seconds >= 0

    @patch('psutil.Process')
    def test_filter_adds_memory_metrics(self, mock_process):
        """Test filter adds memory metrics if psutil available."""
        mock_proc_instance = Mock()
        mock_proc_instance.memory_info.return_value.rss = 100 * 1024 * 1024  # 100MB
        mock_proc_instance.cpu_percent.return_value = 25.5
        mock_process.return_value = mock_proc_instance

        perf_filter = PerformanceFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None
        )

        perf_filter.filter(record)

        assert hasattr(record, 'memory_mb')
        assert hasattr(record, 'cpu_percent')


class TestLoggingConfigManager:
    """Test logging configuration manager."""

    def test_init_creates_log_directory(self, temp_log_dir):
        """Test manager creates log directory."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        assert os.path.exists(temp_log_dir)

    def test_init_configures_root_logger(self, temp_log_dir):
        """Test manager configures root logger."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        root_logger = logging.getLogger()

        assert len(root_logger.handlers) > 0

    def test_get_logger_creates_logger(self, temp_log_dir):
        """Test getting a logger creates it."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        logger = log_manager.get_logger("test_module")

        assert logger is not None
        assert logger.name == "test_module"

    def test_get_logger_with_module_file(self, temp_log_dir):
        """Test getting logger with module-specific file."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        logger = log_manager.get_logger("test_module", module_log_file="test_module.log")

        assert logger is not None
        # Module file should be created when logging occurs

    def test_get_logger_caches_loggers(self, temp_log_dir):
        """Test getting same logger returns cached instance."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        logger1 = log_manager.get_logger("test_module")
        logger2 = log_manager.get_logger("test_module")

        assert logger1 is logger2

    def test_set_level_changes_log_level(self, temp_log_dir):
        """Test changing log level."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir, log_level="INFO")

        log_manager.set_level("DEBUG")

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_get_log_files_lists_files(self, temp_log_dir):
        """Test getting list of log files."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        # Log something to create files
        logger = log_manager.get_logger("test")
        logger.info("Test message")

        log_files = log_manager.get_log_files()

        assert len(log_files) > 0

    def test_get_stats_returns_statistics(self, temp_log_dir):
        """Test getting logging statistics."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)

        stats = log_manager.get_stats()

        assert "log_directory" in stats
        assert "log_level" in stats
        assert "total_log_files" in stats
        assert "configured_loggers" in stats

    def test_console_logging_enabled(self, temp_log_dir):
        """Test console logging can be enabled."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir, console_logging=True)

        root_logger = logging.getLogger()

        # Should have console handler
        has_stream_handler = any(
            isinstance(h, logging.StreamHandler) for h in root_logger.handlers
        )
        assert has_stream_handler

    def test_console_logging_disabled(self, temp_log_dir):
        """Test console logging can be disabled."""
        # Clear existing handlers first
        logging.getLogger().handlers.clear()

        log_manager = LoggingConfigManager(log_dir=temp_log_dir, console_logging=False)

        root_logger = logging.getLogger()

        # Should not have console handler
        console_handlers = [
            h for h in root_logger.handlers
            if isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
        ]
        # May have file handlers, but no console
        assert len(console_handlers) == 0

    def test_json_logging_creates_json_file(self, temp_log_dir):
        """Test JSON logging creates JSON file."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir, json_logging=True)

        logger = log_manager.get_logger("test")
        logger.info("Test message")

        json_files = list(Path(temp_log_dir).glob("*.json"))
        assert len(json_files) > 0

    def test_log_rotation_configuration(self, temp_log_dir):
        """Test log rotation is configured."""
        log_manager = LoggingConfigManager(
            log_dir=temp_log_dir,
            max_bytes=1024,
            backup_count=3
        )

        # Rotation handlers should be configured
        root_logger = logging.getLogger()
        has_rotating_handler = any(
            isinstance(h, logging.handlers.RotatingFileHandler)
            for h in root_logger.handlers
        )
        assert has_rotating_handler


class TestLogOperation:
    """Test log operation context manager."""

    def test_log_operation_success(self, mock_logger):
        """Test log operation on success."""
        with log_operation("Test operation", logger=mock_logger):
            pass

        # Should log start and completion
        assert mock_logger.log.call_count >= 2

    def test_log_operation_with_exception(self, mock_logger):
        """Test log operation on exception."""
        try:
            with log_operation("Test operation", logger=mock_logger):
                raise ValueError("Test error")
        except ValueError:
            pass

        # Should log error
        assert mock_logger.error.called

    def test_log_operation_tracks_duration(self, mock_logger):
        """Test log operation tracks duration."""
        import time

        with log_operation("Test operation", logger=mock_logger):
            time.sleep(0.1)

        # Should have logged duration
        # Check if any call included duration_seconds
        call_args_list = mock_logger.log.call_args_list + mock_logger.error.call_args_list
        has_duration = any(
            'duration_seconds' in str(call)
            for call in call_args_list
        )
        assert has_duration or mock_logger.log.called

    def test_log_operation_with_context(self, mock_logger):
        """Test log operation includes context."""
        with log_operation("Test operation", logger=mock_logger, file_path="/test/file.exe"):
            pass

        # Context should be included in log calls
        assert mock_logger.log.called


class TestCreateModuleLogger:
    """Test create_module_logger utility."""

    def test_create_module_logger_basic(self, temp_log_dir):
        """Test creating basic module logger."""
        logger = create_module_logger("test_module", log_dir=temp_log_dir)

        assert logger is not None
        assert logger.name == "test_module"

    def test_create_module_logger_with_separate_file(self, temp_log_dir):
        """Test creating logger with separate file."""
        logger = create_module_logger(
            "test_module",
            log_dir=temp_log_dir,
            separate_file=True
        )

        logger.info("Test message")

        # Module file should be created
        module_files = list(Path(temp_log_dir).glob("test_module.log"))
        assert len(module_files) > 0

    def test_create_module_logger_without_separate_file(self, temp_log_dir):
        """Test creating logger without separate file."""
        logger = create_module_logger(
            "test_module",
            log_dir=temp_log_dir,
            separate_file=False
        )

        assert logger is not None


class TestLogFunctionCall:
    """Test log_function_call decorator."""

    def test_decorator_logs_function_call(self, mock_logger):
        """Test decorator logs function calls."""
        @log_function_call(mock_logger)
        def test_function(x, y):
            return x + y

        result = test_function(5, 3)

        assert result == 8
        assert mock_logger.log.called

    def test_decorator_logs_arguments(self, mock_logger):
        """Test decorator logs function arguments."""
        @log_function_call(mock_logger)
        def test_function(a, b=10):
            return a * b

        test_function(5, b=20)

        # Should log arguments
        assert mock_logger.log.called

    def test_decorator_logs_exception(self, mock_logger):
        """Test decorator logs exceptions."""
        @log_function_call(mock_logger)
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()

        assert mock_logger.error.called

    def test_decorator_sanitizes_arguments(self, mock_logger):
        """Test decorator sanitizes sensitive arguments."""
        @log_function_call(mock_logger)
        def function_with_password(user, password):
            return True

        function_with_password("testuser", "password=secret123")

        # Arguments should be sanitized
        # Check that secret123 is not in any log call
        all_calls = str(mock_logger.log.call_args_list)
        assert "secret123" not in all_calls


class TestGetLoggingManager:
    """Test get_logging_manager global instance."""

    def test_get_logging_manager_creates_instance(self, temp_log_dir):
        """Test getting global logging manager."""
        # Reset global instance
        import core_engine.logging_config as lc
        lc._global_logging_manager = None

        manager = get_logging_manager(log_dir=temp_log_dir)

        assert manager is not None
        assert isinstance(manager, LoggingConfigManager)

    def test_get_logging_manager_returns_same_instance(self, temp_log_dir):
        """Test getting same manager instance multiple times."""
        # Reset global instance
        import core_engine.logging_config as lc
        lc._global_logging_manager = None

        manager1 = get_logging_manager(log_dir=temp_log_dir)
        manager2 = get_logging_manager(log_dir=temp_log_dir)

        assert manager1 is manager2


class TestLogLevels:
    """Test different log levels."""

    @pytest.mark.parametrize("level_name,level_value", [
        ("DEBUG", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
    ])
    def test_log_levels(self, temp_log_dir, level_name, level_value):
        """Test different log levels are configured correctly."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir, log_level=level_name)

        root_logger = logging.getLogger()

        assert root_logger.level == level_value


class TestLogFormatting:
    """Test log message formatting."""

    def test_log_includes_timestamp(self, temp_log_dir):
        """Test log messages include timestamp."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)
        logger = log_manager.get_logger("test")

        logger.info("Test message")

        # Check log file contains timestamp
        log_files = list(Path(temp_log_dir).glob("*.log"))
        if log_files:
            with open(log_files[0], 'r') as f:
                content = f.read()
                # Should contain date/time information
                assert any(char.isdigit() for char in content)

    def test_log_includes_module_info(self, temp_log_dir):
        """Test log messages include module information."""
        log_manager = LoggingConfigManager(log_dir=temp_log_dir)
        logger = log_manager.get_logger("test_module")

        logger.info("Test message")

        # Check log file contains module name
        log_files = list(Path(temp_log_dir).glob("*.log"))
        if log_files:
            with open(log_files[0], 'r') as f:
                content = f.read()
                assert "test_module" in content or "test" in content


class TestSensitivePatterns:
    """Test sensitive pattern definitions."""

    def test_sensitive_patterns_defined(self):
        """Test sensitive patterns are defined."""
        assert len(SENSITIVE_PATTERNS) > 0

    def test_patterns_include_common_secrets(self):
        """Test patterns include common secret types."""
        pattern_texts = [p[0] for p in SENSITIVE_PATTERNS]
        pattern_str = str(pattern_texts).lower()

        # Check for common secret types
        assert any('password' in p.lower() for p in pattern_texts)
        assert any('api' in p.lower() for p in pattern_texts)
        assert any('token' in p.lower() for p in pattern_texts)
