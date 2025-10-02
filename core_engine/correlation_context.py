"""
Distributed Tracing and Correlation Context for KP14
====================================================

This module provides distributed tracing capabilities using correlation IDs
to track operations across the analysis pipeline.

Features:
- Unique correlation IDs for each analysis session
- Parent-child context relationships
- Thread-safe context storage
- Integration with logging system
- Performance timing and metrics

Author: KP14 Development Team
Version: 1.0.0
"""

import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List


# ============================================================================
# Correlation Context Data Classes
# ============================================================================

@dataclass
class AnalysisContext:
    """
    Context for tracking a single analysis operation.

    Attributes:
        correlation_id: Unique ID for this operation
        parent_id: ID of parent operation (if any)
        operation_name: Name of the operation being performed
        start_time: When operation started
        end_time: When operation completed
        metadata: Additional contextual information
        tags: Tags for categorization
    """
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_id: Optional[str] = None
    operation_name: str = "unknown"
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def create_child_context(self, operation_name: str = "child_operation") -> 'AnalysisContext':
        """
        Create a child context for a sub-operation.

        Args:
            operation_name: Name of the child operation

        Returns:
            New AnalysisContext with this context as parent

        Example:
            >>> parent_ctx = AnalysisContext(operation_name="analyze_file")
            >>> child_ctx = parent_ctx.create_child_context("extract_strings")
            >>> print(child_ctx.parent_id == parent_ctx.correlation_id)
            True
        """
        child = AnalysisContext(
            parent_id=self.correlation_id,
            operation_name=operation_name,
            metadata=self.metadata.copy(),  # Inherit parent metadata
            tags=self.tags.copy()  # Inherit parent tags
        )
        return child

    def finish(self) -> float:
        """
        Mark operation as finished and return duration.

        Returns:
            Duration in seconds

        Example:
            >>> ctx = AnalysisContext(operation_name="process")
            >>> time.sleep(0.1)
            >>> duration = ctx.finish()
            >>> print(f"Duration: {duration:.2f}s")
        """
        self.end_time = time.time()
        return self.get_duration()

    def get_duration(self) -> float:
        """
        Get duration of operation.

        Returns:
            Duration in seconds (0.0 if not finished)

        Example:
            >>> ctx = AnalysisContext()
            >>> time.sleep(0.1)
            >>> ctx.finish()
            >>> print(f"Duration: {ctx.get_duration():.2f}s")
        """
        if self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def add_metadata(self, **kwargs) -> None:
        """
        Add metadata to context.

        Args:
            **kwargs: Key-value pairs to add to metadata

        Example:
            >>> ctx = AnalysisContext()
            >>> ctx.add_metadata(file_name="malware.exe", file_size=12345)
        """
        self.metadata.update(kwargs)

    def add_tag(self, *tags: str) -> None:
        """
        Add tags to context.

        Args:
            *tags: Tags to add

        Example:
            >>> ctx = AnalysisContext()
            >>> ctx.add_tag("malware", "pe", "keyplug")
        """
        self.tags.extend(tags)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary.

        Returns:
            Dictionary representation of context

        Example:
            >>> ctx = AnalysisContext(operation_name="test")
            >>> data = ctx.to_dict()
            >>> print(data['operation_name'])
            'test'
        """
        return {
            'correlation_id': self.correlation_id,
            'parent_id': self.parent_id,
            'operation_name': self.operation_name,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.get_duration(),
            'metadata': self.metadata,
            'tags': self.tags
        }

    def get_log_extra(self) -> Dict[str, Any]:
        """
        Get extra fields for structured logging.

        Returns:
            Dictionary of fields to add to log records

        Example:
            >>> ctx = AnalysisContext(operation_name="analyze")
            >>> logger.info("Starting analysis", extra=ctx.get_log_extra())
        """
        return {
            'correlation_id': self.correlation_id,
            'parent_id': self.parent_id,
            'operation': self.operation_name,
            **self.metadata
        }


# ============================================================================
# Thread-Local Context Storage
# ============================================================================

class ContextManager:
    """
    Thread-safe manager for correlation contexts.

    Manages a stack of contexts per thread, allowing nested operations.
    """

    def __init__(self):
        """Initialize context manager."""
        self._local = threading.local()
        self._lock = threading.Lock()
        self._all_contexts: List[AnalysisContext] = []
        self.logger = logging.getLogger(__name__)

    def _get_stack(self) -> List[AnalysisContext]:
        """Get context stack for current thread."""
        if not hasattr(self._local, 'context_stack'):
            self._local.context_stack = []
        return self._local.context_stack

    def push_context(self, context: AnalysisContext) -> None:
        """
        Push context onto stack.

        Args:
            context: Context to push

        Example:
            >>> mgr = ContextManager()
            >>> ctx = AnalysisContext(operation_name="test")
            >>> mgr.push_context(ctx)
        """
        stack = self._get_stack()
        stack.append(context)

        # Track all contexts (thread-safe)
        with self._lock:
            self._all_contexts.append(context)

        self.logger.debug(
            f"Pushed context: {context.operation_name}",
            extra=context.get_log_extra()
        )

    def pop_context(self) -> Optional[AnalysisContext]:
        """
        Pop context from stack.

        Returns:
            Popped context or None if stack is empty

        Example:
            >>> mgr = ContextManager()
            >>> ctx = AnalysisContext(operation_name="test")
            >>> mgr.push_context(ctx)
            >>> popped = mgr.pop_context()
            >>> print(popped.operation_name)
            'test'
        """
        stack = self._get_stack()
        if not stack:
            return None

        context = stack.pop()
        self.logger.debug(
            f"Popped context: {context.operation_name}",
            extra=context.get_log_extra()
        )
        return context

    def get_current_context(self) -> Optional[AnalysisContext]:
        """
        Get current (top) context from stack.

        Returns:
            Current context or None if stack is empty

        Example:
            >>> mgr = ContextManager()
            >>> ctx = AnalysisContext(operation_name="test")
            >>> mgr.push_context(ctx)
            >>> current = mgr.get_current_context()
            >>> print(current.operation_name)
            'test'
        """
        stack = self._get_stack()
        return stack[-1] if stack else None

    def get_all_contexts(self) -> List[AnalysisContext]:
        """
        Get all contexts created (across all threads).

        Returns:
            List of all contexts

        Example:
            >>> mgr = ContextManager()
            >>> ctx1 = AnalysisContext(operation_name="op1")
            >>> ctx2 = AnalysisContext(operation_name="op2")
            >>> mgr.push_context(ctx1)
            >>> mgr.push_context(ctx2)
            >>> all_ctx = mgr.get_all_contexts()
            >>> print(len(all_ctx))
            2
        """
        with self._lock:
            return self._all_contexts.copy()

    def clear_all(self) -> None:
        """
        Clear all contexts (for testing/cleanup).

        Example:
            >>> mgr = ContextManager()
            >>> mgr.clear_all()
        """
        # Clear thread-local stack
        if hasattr(self._local, 'context_stack'):
            self._local.context_stack.clear()

        # Clear global list
        with self._lock:
            self._all_contexts.clear()

        self.logger.debug("Cleared all contexts")


# ============================================================================
# Global Context Manager Instance
# ============================================================================

_global_context_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    """
    Get global context manager instance (singleton).

    Returns:
        Global ContextManager instance

    Example:
        >>> mgr = get_context_manager()
        >>> ctx = AnalysisContext(operation_name="test")
        >>> mgr.push_context(ctx)
    """
    global _global_context_manager

    if _global_context_manager is None:
        _global_context_manager = ContextManager()

    return _global_context_manager


# ============================================================================
# Context Manager Decorators and Context Managers
# ============================================================================

@contextmanager
def analysis_context(
    operation_name: str,
    **metadata
):
    """
    Context manager for automatic context management.

    Creates and manages an AnalysisContext, automatically pushing/popping
    from the context stack and finishing timing.

    Args:
        operation_name: Name of the operation
        **metadata: Initial metadata for context

    Yields:
        AnalysisContext for the operation

    Example:
        >>> with analysis_context("analyze_pe", file_name="malware.exe") as ctx:
        ...     # Analysis code here
        ...     ctx.add_metadata(section_count=5)
        ...     print(f"Correlation ID: {ctx.correlation_id}")
    """
    mgr = get_context_manager()

    # Get parent context if exists
    parent = mgr.get_current_context()

    # Create new context
    if parent:
        context = parent.create_child_context(operation_name)
    else:
        context = AnalysisContext(operation_name=operation_name)

    # Add initial metadata
    context.add_metadata(**metadata)

    # Push context
    mgr.push_context(context)

    logger = logging.getLogger(__name__)
    logger.info(
        f"Starting operation: {operation_name}",
        extra=context.get_log_extra()
    )

    try:
        yield context
    except Exception as e:
        # Add error information to context
        context.add_metadata(
            error=str(e),
            error_type=type(e).__name__
        )
        context.add_tag("error")
        logger.error(
            f"Operation failed: {operation_name}",
            extra=context.get_log_extra(),
            exc_info=True
        )
        raise
    finally:
        # Finish context and pop
        duration = context.finish()
        mgr.pop_context()

        logger.info(
            f"Completed operation: {operation_name} (duration: {duration:.3f}s)",
            extra=context.get_log_extra()
        )


def traced(operation_name: Optional[str] = None):
    """
    Decorator for automatic function tracing.

    Args:
        operation_name: Name for operation (default: function name)

    Returns:
        Decorated function

    Example:
        >>> @traced("process_file")
        ... def analyze_file(file_path):
        ...     # Analysis code here
        ...     pass
    """
    def decorator(func):
        import functools

        op_name = operation_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with analysis_context(op_name):
                return func(*args, **kwargs)

        return wrapper
    return decorator


# ============================================================================
# Utility Functions
# ============================================================================

def get_current_correlation_id() -> Optional[str]:
    """
    Get correlation ID of current context.

    Returns:
        Correlation ID or None if no context

    Example:
        >>> with analysis_context("test"):
        ...     corr_id = get_current_correlation_id()
        ...     print(f"ID: {corr_id}")
    """
    mgr = get_context_manager()
    context = mgr.get_current_context()
    return context.correlation_id if context else None


def add_context_metadata(**kwargs) -> None:
    """
    Add metadata to current context.

    Args:
        **kwargs: Metadata to add

    Example:
        >>> with analysis_context("test"):
        ...     add_context_metadata(file_size=12345, file_type="PE")
    """
    mgr = get_context_manager()
    context = mgr.get_current_context()
    if context:
        context.add_metadata(**kwargs)


def add_context_tags(*tags: str) -> None:
    """
    Add tags to current context.

    Args:
        *tags: Tags to add

    Example:
        >>> with analysis_context("test"):
        ...     add_context_tags("malware", "suspicious")
    """
    mgr = get_context_manager()
    context = mgr.get_current_context()
    if context:
        context.add_tag(*tags)


# ============================================================================
# Main (for testing)
# ============================================================================

if __name__ == "__main__":
    import json

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - '
                '[%(correlation_id)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    print("=== KP14 Correlation Context - Testing ===\n")

    # Test 1: Basic context usage
    print("Test 1: Basic Context Usage")
    with analysis_context("main_analysis", file_name="test.exe") as ctx:
        print(f"Correlation ID: {ctx.correlation_id}")
        add_context_metadata(file_size=12345)

        # Nested context
        with analysis_context("sub_analysis") as sub_ctx:
            print(f"Parent ID: {sub_ctx.parent_id}")
            print(f"Child ID: {sub_ctx.correlation_id}")
            add_context_tags("nested", "test")
            time.sleep(0.1)

        time.sleep(0.1)

    # Test 2: Decorator usage
    print("\nTest 2: Decorator Usage")

    @traced("process_data")
    def process_data(data_id: int):
        print(f"Processing data {data_id}")
        add_context_metadata(data_id=data_id)
        time.sleep(0.1)
        return f"Result for {data_id}"

    result = process_data(42)
    print(f"Result: {result}")

    # Test 3: Context tracking
    print("\nTest 3: Context Tracking")
    mgr = get_context_manager()
    all_contexts = mgr.get_all_contexts()
    print(f"Total contexts created: {len(all_contexts)}")

    for ctx in all_contexts:
        ctx_dict = ctx.to_dict()
        print(f"\nContext: {ctx_dict['operation_name']}")
        print(f"  Duration: {ctx_dict['duration']:.3f}s")
        print(f"  Metadata: {json.dumps(ctx_dict['metadata'], indent=2)}")
        print(f"  Tags: {ctx_dict['tags']}")

    print("\n=== All tests completed ===")
