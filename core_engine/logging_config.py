"""
Logging Configuration Module for KP14 Analysis Framework

This module provides:
- Structured JSON logging
- Multiple log levels (DEBUG, INFO, WARN, ERROR, CRITICAL)
- Per-module log files
- Log rotation (size-based and time-based)
- Centralized log aggregation
- Sensitive data sanitization
- Performance metrics logging

Author: KP14 Development Team
Version: 1.0.0
"""

import logging
import logging.handlers
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from collections import OrderedDict


# ============================================================================
# Sensitive Data Patterns
# ============================================================================

SENSITIVE_PATTERNS = [
    # API Keys and Tokens
    (r'api[_-]?key["\s:=]+([a-zA-Z0-9_\-]{20,})', r'api_key=***REDACTED***'),
    (r'token["\s:=]+([a-zA-Z0-9_\-\.]{20,})', r'token=***REDACTED***'),
    (r'secret["\s:=]+([a-zA-Z0-9_\-]{20,})', r'secret=***REDACTED***'),
    (r'password["\s:=]+([^\s"\']+)', r'password=***REDACTED***'),
    (r'passwd["\s:=]+([^\s"\']+)', r'passwd=***REDACTED***'),

    # Authentication headers
    (r'Authorization:\s*Bearer\s+([^\s]+)', r'Authorization: Bearer ***REDACTED***'),
    (r'Authorization:\s*Basic\s+([^\s]+)', r'Authorization: Basic ***REDACTED***'),

    # Private keys (PEM format)
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
     r'-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----'),

    # IP addresses (optional - might be needed for analysis)
    # (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', r'***IP_REDACTED***'),

    # Email addresses
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'***EMAIL_REDACTED***'),

    # Credit card numbers
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', r'***CC_REDACTED***'),

    # Social Security Numbers
    (r'\b\d{3}-\d{2}-\d{4}\b', r'***SSN_REDACTED***'),
]


def sanitize_sensitive_data(text: str) -> str:
    """
    Sanitize sensitive data from log messages.

    Args:
        text: Text to sanitize

    Returns:
        Sanitized text with sensitive data redacted
    """
    if not isinstance(text, str):
        text = str(text)

    for pattern, replacement in SENSITIVE_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE | re.DOTALL)

    return text


# ============================================================================
# JSON Formatter with Sanitization
# ============================================================================

class SanitizedJSONFormatter(logging.Formatter):
    """
    Custom JSON formatter that sanitizes sensitive data and structures log records.
    """

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with sanitization."""
        # Build base log structure
        log_data = OrderedDict([
            ("timestamp", datetime.fromtimestamp(record.created).isoformat()),
            ("level", record.levelname),
            ("logger", record.name),
            ("module", record.module),
            ("function", record.funcName),
            ("line", record.lineno),
            ("message", sanitize_sensitive_data(record.getMessage())),
        ])

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": sanitize_sensitive_data(str(record.exc_info[1])),
                "traceback": sanitize_sensitive_data(self.formatException(record.exc_info))
            }

        # Add extra fields if configured
        if self.include_extra:
            # Get all extra attributes (those not in standard LogRecord)
            standard_attrs = {
                'name', 'msg', 'args', 'created', 'filename', 'funcName', 'levelname',
                'levelno', 'lineno', 'module', 'msecs', 'message', 'pathname', 'process',
                'processName', 'relativeCreated', 'thread', 'threadName', 'exc_info',
                'exc_text', 'stack_info', 'taskName'
            }

            extra_data = {
                key: sanitize_sensitive_data(str(value))
                for key, value in record.__dict__.items()
                if key not in standard_attrs and not key.startswith('_')
            }

            if extra_data:
                log_data["extra"] = extra_data

        # Add thread and process info
        log_data["process"] = {
            "id": record.process,
            "name": record.processName
        }
        log_data["thread"] = {
            "id": record.thread,
            "name": record.threadName
        }

        return json.dumps(log_data)


# ============================================================================
# Standard Formatter with Sanitization
# ============================================================================

class SanitizedFormatter(logging.Formatter):
    """Standard text formatter with sensitive data sanitization."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with sanitization."""
        # Format the message first
        formatted = super().format(record)
        # Then sanitize
        return sanitize_sensitive_data(formatted)


# ============================================================================
# Performance Metrics Filter
# ============================================================================

class PerformanceFilter(logging.Filter):
    """Filter to add performance metrics to log records."""

    def __init__(self):
        super().__init__()
        self.start_time = datetime.now()
        self.operation_stack = []

    def filter(self, record: logging.LogRecord) -> bool:
        """Add performance metrics to record."""
        # Add uptime
        record.uptime_seconds = (datetime.now() - self.start_time).total_seconds()

        # Add memory usage if available
        try:
            import psutil
            process = psutil.Process()
            record.memory_mb = process.memory_info().rss / 1024 / 1024
            record.cpu_percent = process.cpu_percent()
        except (ImportError, Exception):
            pass

        return True


# ============================================================================
# Logging Configuration Manager
# ============================================================================

class LoggingConfigManager:
    """
    Centralized logging configuration manager.

    Features:
    - Multiple handlers (console, file, JSON file)
    - Log rotation by size and time
    - Per-module log files
    - Structured logging with JSON
    - Automatic sanitization of sensitive data
    """

    def __init__(
        self,
        log_dir: str = "logs",
        log_level: str = "INFO",
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        json_logging: bool = True,
        console_logging: bool = True,
        sanitize_logs: bool = True
    ):
        """
        Initialize logging configuration.

        Args:
            log_dir: Directory for log files
            log_level: Default log level
            max_bytes: Maximum size of log file before rotation
            backup_count: Number of backup files to keep
            json_logging: Enable JSON formatted logs
            console_logging: Enable console output
            sanitize_logs: Enable sensitive data sanitization
        """
        self.log_dir = Path(log_dir)
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.json_logging = json_logging
        self.console_logging = console_logging
        self.sanitize_logs = sanitize_logs

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Store configured loggers
        self.configured_loggers: Dict[str, logging.Logger] = {}

        # Configure root logger
        self._configure_root_logger()

    def _configure_root_logger(self):
        """Configure the root logger with default handlers."""
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)

        # Remove existing handlers
        root_logger.handlers.clear()

        # Console handler
        if self.console_logging:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)

            if self.sanitize_logs:
                console_formatter = SanitizedFormatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            else:
                console_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )

            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)

        # Main log file handler (rotating)
        main_log_file = self.log_dir / "kp14_main.log"
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        file_handler.setLevel(self.log_level)

        if self.sanitize_logs:
            file_formatter = SanitizedFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
            )
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
            )

        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        # JSON log file handler (rotating)
        if self.json_logging:
            json_log_file = self.log_dir / "kp14_structured.json"
            json_handler = logging.handlers.RotatingFileHandler(
                json_log_file,
                maxBytes=self.max_bytes,
                backupCount=self.backup_count
            )
            json_handler.setLevel(self.log_level)
            json_handler.setFormatter(SanitizedJSONFormatter(include_extra=True))
            root_logger.addHandler(json_handler)

        # Add performance filter
        perf_filter = PerformanceFilter()
        root_logger.addFilter(perf_filter)

    def get_logger(
        self,
        name: str,
        module_log_file: Optional[str] = None,
        level: Optional[str] = None
    ) -> logging.Logger:
        """
        Get or create a logger with optional module-specific log file.

        Args:
            name: Logger name (typically module name)
            module_log_file: Optional separate log file for this module
            level: Optional log level override for this logger

        Returns:
            Configured logger instance
        """
        # Return existing logger if already configured
        if name in self.configured_loggers:
            return self.configured_loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()) if level else self.log_level)

        # Add module-specific file handler if requested
        if module_log_file:
            module_log_path = self.log_dir / module_log_file
            module_handler = logging.handlers.RotatingFileHandler(
                module_log_path,
                maxBytes=self.max_bytes,
                backupCount=self.backup_count
            )
            module_handler.setLevel(logger.level)

            if self.sanitize_logs:
                module_formatter = SanitizedFormatter(
                    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
                )
            else:
                module_formatter = logging.Formatter(
                    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
                )

            module_handler.setFormatter(module_formatter)
            logger.addHandler(module_handler)

        self.configured_loggers[name] = logger
        return logger

    def set_level(self, level: str, logger_name: Optional[str] = None):
        """
        Change log level dynamically.

        Args:
            level: New log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            logger_name: Specific logger to update, or None for root logger
        """
        log_level = getattr(logging, level.upper(), logging.INFO)

        if logger_name:
            logger = logging.getLogger(logger_name)
            logger.setLevel(log_level)
        else:
            logging.getLogger().setLevel(log_level)

    def get_log_files(self) -> List[Path]:
        """Get list of all log files in the log directory."""
        return list(self.log_dir.glob("*.log")) + list(self.log_dir.glob("*.json"))

    def cleanup_old_logs(self, days: int = 30):
        """
        Clean up log files older than specified days.

        Args:
            days: Delete logs older than this many days
        """
        import time
        cutoff_time = time.time() - (days * 86400)

        for log_file in self.get_log_files():
            try:
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logging.info(f"Deleted old log file: {log_file}")
            except Exception as e:
                logging.error(f"Failed to delete log file {log_file}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about logging."""
        stats = {
            "log_directory": str(self.log_dir),
            "log_level": logging.getLevelName(self.log_level),
            "total_log_files": 0,
            "total_size_mb": 0.0,
            "configured_loggers": list(self.configured_loggers.keys()),
            "handlers": []
        }

        # Calculate total log size
        for log_file in self.get_log_files():
            stats["total_log_files"] += 1
            stats["total_size_mb"] += log_file.stat().st_size / (1024 * 1024)

        # Get handler information
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            stats["handlers"].append({
                "type": type(handler).__name__,
                "level": logging.getLevelName(handler.level),
                "formatter": type(handler.formatter).__name__ if handler.formatter else None
            })

        return stats


# ============================================================================
# Context Manager for Operation Logging
# ============================================================================

class log_operation:
    """
    Context manager for logging operation start, completion, and duration.

    Example:
        with log_operation("Analyzing PE file", logger=logger, file_path=path):
            # ... perform analysis ...
            pass
    """

    def __init__(
        self,
        operation_name: str,
        logger: logging.Logger,
        level: int = logging.INFO,
        **context
    ):
        self.operation_name = operation_name
        self.logger = logger
        self.level = level
        self.context = context
        self.start_time = None

    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.log(
            self.level,
            f"Starting: {self.operation_name}",
            extra=self.context
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()

        if exc_type is None:
            self.logger.log(
                self.level,
                f"Completed: {self.operation_name} (duration: {duration:.2f}s)",
                extra={**self.context, "duration_seconds": duration}
            )
        else:
            self.logger.error(
                f"Failed: {self.operation_name} (duration: {duration:.2f}s)",
                extra={
                    **self.context,
                    "duration_seconds": duration,
                    "error_type": exc_type.__name__,
                    "error_message": str(exc_val)
                },
                exc_info=True
            )

        return False  # Don't suppress exceptions


# ============================================================================
# Utility Functions
# ============================================================================

def create_module_logger(
    module_name: str,
    log_dir: str = "logs",
    level: str = "INFO",
    separate_file: bool = True
) -> logging.Logger:
    """
    Create a logger for a specific module with optional separate log file.

    Args:
        module_name: Name of the module
        log_dir: Directory for log files
        level: Log level
        separate_file: Create separate log file for this module

    Returns:
        Configured logger instance
    """
    # Get or create logging config manager
    if not hasattr(create_module_logger, '_manager'):
        create_module_logger._manager = LoggingConfigManager(log_dir=log_dir, log_level=level)

    manager = create_module_logger._manager

    if separate_file:
        log_file = f"{module_name.replace('.', '_')}.log"
        return manager.get_logger(module_name, module_log_file=log_file, level=level)
    else:
        return manager.get_logger(module_name, level=level)


def log_function_call(logger: logging.Logger, level: int = logging.DEBUG):
    """
    Decorator to log function calls with arguments and return values.

    Args:
        logger: Logger instance to use
        level: Log level for function call logging
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Sanitize arguments for logging
            safe_args = [sanitize_sensitive_data(str(arg)) for arg in args]
            safe_kwargs = {k: sanitize_sensitive_data(str(v)) for k, v in kwargs.items()}

            logger.log(
                level,
                f"Calling {func.__name__}",
                extra={
                    "function": func.__name__,
                    "args": safe_args,
                    "kwargs": safe_kwargs
                }
            )

            try:
                result = func(*args, **kwargs)
                logger.log(
                    level,
                    f"Completed {func.__name__}",
                    extra={
                        "function": func.__name__,
                        "result_type": type(result).__name__
                    }
                )
                return result

            except Exception as e:
                logger.error(
                    f"Error in {func.__name__}: {type(e).__name__}",
                    extra={
                        "function": func.__name__,
                        "error": str(e)
                    },
                    exc_info=True
                )
                raise

        return wrapper
    return decorator


# ============================================================================
# Global Logging Manager Instance
# ============================================================================

# Create global instance that can be imported
_global_logging_manager = None


def get_logging_manager(
    log_dir: str = "logs",
    log_level: str = "INFO",
    **kwargs
) -> LoggingConfigManager:
    """
    Get or create the global logging manager instance.

    Args:
        log_dir: Directory for log files
        log_level: Default log level
        **kwargs: Additional arguments for LoggingConfigManager

    Returns:
        Global LoggingConfigManager instance
    """
    global _global_logging_manager

    if _global_logging_manager is None:
        _global_logging_manager = LoggingConfigManager(
            log_dir=log_dir,
            log_level=log_level,
            **kwargs
        )

    return _global_logging_manager


if __name__ == "__main__":
    # Demonstration and testing of logging capabilities
    print("=== KP14 Logging Configuration Module - Testing ===\n")

    # Create logging manager
    log_manager = LoggingConfigManager(
        log_dir="test_logs",
        log_level="DEBUG",
        json_logging=True,
        console_logging=True
    )

    # Test 1: Basic logging
    print("Test 1: Basic Logging")
    logger = log_manager.get_logger("test_module")
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    logger.critical("Critical message")

    # Test 2: Sensitive data sanitization
    print("\nTest 2: Sensitive Data Sanitization")
    logger.info("API key: api_key=test_fake_api_key_12345678")
    logger.info("Password: password=SuperSecret123!")
    logger.info("Email: user@example.com")

    # Test 3: Structured logging with extra data
    print("\nTest 3: Structured Logging")
    logger.info(
        "Analysis completed",
        extra={
            "file_path": "/test/malware.exe",
            "file_size": 102400,
            "analysis_type": "PE",
            "duration": 5.23
        }
    )

    # Test 4: Module-specific logger
    print("\nTest 4: Module-Specific Logger")
    pe_logger = log_manager.get_logger("pe_analyzer", module_log_file="pe_analyzer.log")
    pe_logger.info("PE analysis started")

    # Test 5: Operation logging context manager
    print("\nTest 5: Operation Logging")
    with log_operation("Test operation", logger=logger, test_param="value"):
        import time
        time.sleep(0.1)
        logger.info("Operation in progress...")

    # Test 6: Exception logging
    print("\nTest 6: Exception Logging")
    try:
        raise ValueError("Test exception with sensitive data: password=secret123")
    except ValueError as e:
        logger.error("Caught exception", exc_info=True)

    # Test 7: Statistics
    print("\nTest 7: Logging Statistics")
    stats = log_manager.get_stats()
    print(json.dumps(stats, indent=2))

    print("\n=== All tests completed ===")
    print(f"Check the 'test_logs' directory for output files")
