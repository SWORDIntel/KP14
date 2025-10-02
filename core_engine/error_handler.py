"""
Error Handling Module for KP14 Analysis Framework

This module provides:
- Custom exception classes with context preservation
- Graceful degradation strategies
- Error recovery mechanisms
- Retry logic with exponential backoff

Author: KP14 Development Team
Version: 1.0.0
"""

import functools
import time
import traceback
from typing import Optional, Callable, Any, Dict, List
from enum import Enum


# ============================================================================
# Custom Exception Classes
# ============================================================================

class KP14Error(Exception):
    """Base exception for all KP14-related errors.

    Attributes:
        message: Human-readable error message
        context: Dictionary containing error context (file paths, line numbers, etc.)
        original_exception: The original exception that was caught (if any)
        recoverable: Whether this error can be recovered from
    """

    def __init__(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        original_exception: Optional[Exception] = None,
        recoverable: bool = False
    ):
        self.message = message
        self.context = context or {}
        self.original_exception = original_exception
        self.recoverable = recoverable

        # Build full error message with context
        full_message = f"{message}"
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            full_message += f" [Context: {context_str}]"
        if self.original_exception:
            full_message += f" [Caused by: {type(original_exception).__name__}: {str(original_exception)}]"

        super().__init__(full_message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
            "recoverable": self.recoverable,
            "original_exception": str(self.original_exception) if self.original_exception else None,
            "traceback": traceback.format_exc() if self.original_exception else None
        }


class FileValidationError(KP14Error):
    """Raised when file validation fails (magic bytes, size limits, format, etc.)."""

    def __init__(self, message: str, file_path: str, **kwargs: Any) -> None:
        context = {"file_path": file_path}
        context.update(kwargs.get("context", {}))
        super().__init__(message, context=context, **{k: v for k, v in kwargs.items() if k != "context"})


class FileSizeError(FileValidationError):
    """Raised when file size exceeds limits (DoS prevention)."""

    def __init__(self, file_path: str, actual_size: int, max_size: int, **kwargs: Any) -> None:
        message = f"File size {actual_size} bytes exceeds maximum allowed size of {max_size} bytes"
        context = {"actual_size": actual_size, "max_size": max_size}
        context.update(kwargs.get("context", {}))
        super().__init__(message, file_path, context=context, **{k: v for k, v in kwargs.items() if k != "context"})


class FileFormatError(FileValidationError):
    """Raised when file format is invalid or corrupted."""

    def __init__(self, file_path: str, expected_format: str, actual_format: Optional[str] = None, **kwargs: Any) -> None:
        message = f"Invalid file format. Expected: {expected_format}"
        if actual_format:
            message += f", Got: {actual_format}"
        context = {"expected_format": expected_format, "actual_format": actual_format}
        context.update(kwargs.get("context", {}))
        super().__init__(message, file_path, context=context, **{k: v for k, v in kwargs.items() if k != "context"})


class SuspiciousPayloadError(FileValidationError):
    """Raised when suspicious payload patterns are detected."""

    def __init__(self, file_path: str, reason: str, **kwargs: Any) -> None:
        message = f"Suspicious payload detected: {reason}"
        context = {"reason": reason}
        context.update(kwargs.get("context", {}))
        super().__init__(message, file_path, context=context, **{k: v for k, v in kwargs.items() if k != "context"})


class HardwareError(KP14Error):
    """Raised when hardware-related operations fail (OpenVINO, GPU, etc.)."""

    def __init__(self, message: str, hardware_component: str, **kwargs: Any) -> None:
        context = {"hardware_component": hardware_component}
        context.update(kwargs.get("context", {}))
        super().__init__(message, context=context, **kwargs)


class ModelLoadError(KP14Error):
    """Raised when ML model loading fails."""

    def __init__(self, message: str, model_path: str, **kwargs: Any) -> None:
        context = {"model_path": model_path}
        context.update(kwargs.get("context", {}))
        super().__init__(message, context=context, **kwargs)


class AnalysisError(KP14Error):
    """Raised when analysis operations fail."""

    def __init__(self, message: str, analyzer_name: str, **kwargs: Any) -> None:
        context = {"analyzer_name": analyzer_name}
        context.update(kwargs.get("context", {}))
        # Most analysis errors are recoverable (can skip that analyzer)
        kwargs.setdefault("recoverable", True)
        super().__init__(message, context=context, **kwargs)


class NetworkError(KP14Error):
    """Raised when network operations fail."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        # Network errors are typically recoverable with retries
        kwargs.setdefault("recoverable", True)
        super().__init__(message, **kwargs)


class ResourceExhaustionError(KP14Error):
    """Raised when system resources are exhausted (memory, disk, etc.)."""

    def __init__(self, message: str, resource_type: str, **kwargs: Any) -> None:
        context = {"resource_type": resource_type}
        context.update(kwargs.get("context", {}))
        super().__init__(message, context=context, **kwargs)


class ConfigurationError(KP14Error):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs: Any) -> None:
        context = {"config_key": config_key} if config_key else {}
        context.update(kwargs.get("context", {}))
        super().__init__(message, context=context, **kwargs)


class SecurityError(KP14Error):
    """Raised when security validation fails or security threats are detected.

    This includes:
    - Path traversal attempts
    - Command injection attempts
    - File access outside allowed directories
    - Suspicious file patterns
    - Input validation failures with security implications
    """

    def __init__(self, message: str, security_check: Optional[str] = None, **kwargs: Any) -> None:
        context = {"security_check": security_check} if security_check else {}
        context.update(kwargs.get("context", {}))
        # Security errors are never recoverable - fail immediately
        kwargs["recoverable"] = False
        super().__init__(message, context=context, **kwargs)


# ============================================================================
# Retry Logic with Exponential Backoff
# ============================================================================

class RetryStrategy(Enum):
    """Retry strategies for different error types."""
    NO_RETRY = "no_retry"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
    retriable_exceptions: tuple = (NetworkError, ResourceExhaustionError),
    logger: Optional[Any] = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for retrying functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay between retries
        backoff_factor: Multiplier for exponential backoff
        strategy: Retry strategy to use
        retriable_exceptions: Tuple of exception types to retry on
        logger: Logger instance for logging retry attempts

    Returns:
        Decorated function with retry logic

    Example:
        @retry_with_backoff(max_retries=3, retriable_exceptions=(NetworkError,))
        def fetch_data_from_network():
            # ... network operation ...
            pass
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            delay = initial_delay
            fibonacci_prev, fibonacci_curr = 1, 1

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except retriable_exceptions as e:
                    last_exception = e

                    # Don't retry on last attempt
                    if attempt >= max_retries:
                        if logger:
                            logger.error(
                                f"Failed after {max_retries} retries: {func.__name__}",
                                extra={"error": str(e), "attempts": attempt + 1}
                            )
                        raise

                    # Calculate delay based on strategy
                    if strategy == RetryStrategy.LINEAR:
                        current_delay = initial_delay
                    elif strategy == RetryStrategy.EXPONENTIAL:
                        current_delay = min(delay, max_delay)
                        delay *= backoff_factor
                    elif strategy == RetryStrategy.FIBONACCI:
                        current_delay = min(fibonacci_curr * initial_delay, max_delay)
                        fibonacci_prev, fibonacci_curr = fibonacci_curr, fibonacci_prev + fibonacci_curr
                    else:  # NO_RETRY
                        raise

                    if logger:
                        logger.warning(
                            f"Retry attempt {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after {current_delay:.2f}s delay",
                            extra={
                                "error": str(e),
                                "attempt": attempt + 1,
                                "delay": current_delay,
                                "function": func.__name__
                            }
                        )

                    time.sleep(current_delay)

                except Exception as e:
                    # Non-retriable exception, fail immediately
                    if logger:
                        logger.error(
                            f"Non-retriable error in {func.__name__}: {type(e).__name__}",
                            extra={"error": str(e)}
                        )
                    raise

            # Should never reach here, but just in case
            if last_exception:
                raise last_exception

        return wrapper
    return decorator


# ============================================================================
# Error Recovery Mechanisms
# ============================================================================

class ErrorRecoveryManager:
    """Manages error recovery strategies and graceful degradation."""

    def __init__(self, logger: Optional[Any] = None):
        self.logger = logger
        self.error_history: List[Dict[str, Any]] = []
        self.recovery_strategies: Dict[type, Callable] = {}

    def register_recovery_strategy(
        self,
        exception_type: type,
        recovery_function: Callable[[Exception, Optional[Dict[str, Any]]], Any]
    ) -> None:
        """
        Register a recovery strategy for a specific exception type.

        Args:
            exception_type: The exception class to handle
            recovery_function: Function to call for recovery (should return a fallback value)
        """
        self.recovery_strategies[exception_type] = recovery_function

    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        fail_fast: bool = False
    ) -> Optional[Any]:
        """
        Handle an error with registered recovery strategies.

        Args:
            error: The exception to handle
            context: Additional context about the error
            fail_fast: If True, raise unrecoverable errors immediately

        Returns:
            Recovery value if available, None otherwise

        Raises:
            Exception if fail_fast is True and error is unrecoverable
        """
        error_info = {
            "timestamp": time.time(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {},
            "traceback": traceback.format_exc()
        }

        self.error_history.append(error_info)

        if self.logger:
            self.logger.error(
                f"Error occurred: {type(error).__name__}",
                extra=error_info
            )

        # Check if error is recoverable
        is_recoverable = (
            isinstance(error, KP14Error) and error.recoverable
        ) or type(error) in self.recovery_strategies

        if not is_recoverable and fail_fast:
            if self.logger:
                self.logger.critical(
                    "Unrecoverable error encountered with fail_fast=True",
                    extra=error_info
                )
            raise error

        # Try registered recovery strategies
        for exception_type, recovery_func in self.recovery_strategies.items():
            if isinstance(error, exception_type):
                try:
                    if self.logger:
                        self.logger.info(
                            f"Attempting recovery for {type(error).__name__}",
                            extra={"recovery_strategy": recovery_func.__name__}
                        )
                    return recovery_func(error, context)
                except Exception as recovery_error:
                    if self.logger:
                        self.logger.error(
                            f"Recovery strategy failed: {recovery_func.__name__}",
                            extra={"recovery_error": str(recovery_error)}
                        )

        # No recovery available
        if self.logger:
            self.logger.warning(
                f"No recovery strategy available for {type(error).__name__}",
                extra=error_info
            )

        return None

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors encountered."""
        error_counts: Dict[str, int] = {}
        for error in self.error_history:
            error_type = error["error_type"]
            error_counts[error_type] = error_counts.get(error_type, 0) + 1

        return {
            "total_errors": len(self.error_history),
            "error_counts": error_counts,
            "recent_errors": self.error_history[-10:] if self.error_history else []
        }


# ============================================================================
# Context Manager for Error Handling
# ============================================================================

class error_context:
    """
    Context manager for wrapping code blocks with error handling.

    Example:
        with error_context("Loading PE file", file_path=path, logger=logger):
            pe = pefile.PE(path)
    """

    def __init__(
        self,
        operation_name: str,
        logger: Optional[Any] = None,
        recovery_manager: Optional[ErrorRecoveryManager] = None,
        fail_fast: bool = False,
        **context_kwargs: Any
    ) -> None:
        self.operation_name = operation_name
        self.logger = logger
        self.recovery_manager = recovery_manager
        self.fail_fast = fail_fast
        self.context = context_kwargs

    def __enter__(self) -> "error_context":
        if self.logger:
            self.logger.debug(
                f"Starting operation: {self.operation_name}",
                extra=self.context
            )
        return self

    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> bool:
        if exc_type is None:
            # Success
            if self.logger:
                self.logger.debug(
                    f"Completed operation: {self.operation_name}",
                    extra=self.context
                )
            return True

        # Error occurred
        if self.logger:
            self.logger.error(
                f"Error in operation '{self.operation_name}': {exc_type.__name__}",
                extra={
                    **self.context,
                    "error": str(exc_val),
                    "traceback": traceback.format_exc()
                }
            )

        # Try recovery if manager is available
        if self.recovery_manager:
            self.recovery_manager.handle_error(
                exc_val,
                context={**self.context, "operation": self.operation_name},
                fail_fast=self.fail_fast
            )

        # Suppress exception unless fail_fast is True
        return not self.fail_fast


# ============================================================================
# Utility Functions
# ============================================================================

def safe_execute(
    func: Callable,
    args: tuple = (),
    kwargs: Optional[Dict] = None,
    default_return: Any = None,
    logger: Optional[Any] = None,
    operation_name: Optional[str] = None
) -> Any:
    """
    Safely execute a function with error handling.

    Args:
        func: Function to execute
        args: Positional arguments for the function
        kwargs: Keyword arguments for the function
        default_return: Value to return if function fails
        logger: Logger instance
        operation_name: Name of the operation for logging

    Returns:
        Function result or default_return on error
    """
    kwargs = kwargs or {}
    op_name = operation_name or func.__name__

    try:
        if logger:
            logger.debug(f"Executing: {op_name}")
        result = func(*args, **kwargs)
        if logger:
            logger.debug(f"Successfully executed: {op_name}")
        return result

    except Exception as e:
        if logger:
            logger.error(
                f"Error executing {op_name}: {type(e).__name__}",
                extra={
                    "error": str(e),
                    "function": func.__name__,
                    "traceback": traceback.format_exc()
                }
            )
        return default_return


def create_error_report(
    error: Exception,
    context: Optional[Dict[str, Any]] = None,
    include_traceback: bool = True
) -> Dict[str, Any]:
    """
    Create a structured error report for logging/debugging.

    Args:
        error: The exception to report
        context: Additional context information
        include_traceback: Whether to include full traceback

    Returns:
        Dictionary containing error details
    """
    report = {
        "error_type": type(error).__name__,
        "error_message": str(error),
        "timestamp": time.time(),
        "context": context or {}
    }

    if isinstance(error, KP14Error):
        report.update(error.to_dict())

    if include_traceback:
        report["traceback"] = traceback.format_exc()

    return report


# ============================================================================
# Module-level Error Handler Instance
# ============================================================================

# Global error recovery manager that can be used throughout the application
global_error_manager = ErrorRecoveryManager()


if __name__ == "__main__":
    # Demonstration and testing of error handling capabilities
    print("=== KP14 Error Handler Module - Testing ===\n")

    # Test 1: Custom exceptions
    print("Test 1: Custom Exceptions")
    try:
        raise FileValidationError(
            "Invalid PE signature",
            file_path="/test/malware.exe",
            context={"expected": "MZ", "found": "ZM"}
        )
    except KP14Error as e:
        print(f"Caught: {e}")
        print(f"Error dict: {e.to_dict()}\n")

    # Test 2: Retry logic
    print("Test 2: Retry Logic")
    attempt_count = [0]

    @retry_with_backoff(max_retries=3, initial_delay=0.1, retriable_exceptions=(ValueError,))
    def flaky_function():
        attempt_count[0] += 1
        print(f"  Attempt {attempt_count[0]}")
        if attempt_count[0] < 3:
            raise ValueError("Simulated transient error")
        return "Success!"

    try:
        result = flaky_function()
        print(f"  Result: {result}\n")
    except Exception as e:
        print(f"  Failed: {e}\n")

    # Test 3: Error recovery
    print("Test 3: Error Recovery Manager")
    recovery_mgr = ErrorRecoveryManager()

    def recover_from_file_error(error, context):
        print(f"  Recovery strategy called for: {error}")
        return {"status": "recovered", "fallback_used": True}

    recovery_mgr.register_recovery_strategy(FileValidationError, recover_from_file_error)

    try:
        raise FileValidationError("Test error", "/test/file.exe")
    except FileValidationError as e:
        result = recovery_mgr.handle_error(e, context={"test": True})
        print(f"  Recovery result: {result}\n")

    # Test 4: Context manager
    print("Test 4: Error Context Manager")
    with error_context("Testing context manager", test_param="value") as ctx:
        print("  Inside context manager")
        # No error - should complete successfully

    print("\n=== All tests completed ===")
