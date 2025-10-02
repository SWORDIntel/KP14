"""
Performance Profiling and Monitoring for KP14 Analysis Framework
================================================================

Provides comprehensive performance monitoring:
- CPU profiling
- Memory profiling
- I/O profiling
- Hot path identification
- Performance metrics collection
- Real-time monitoring

Features:
- Low-overhead profiling
- Detailed performance reports
- Bottleneck identification
- Memory leak detection
- Timeline visualization data

Author: KP14 Development Team
Version: 1.0.0
"""

import cProfile
import functools
import gc
import io
import logging
import pstats
import resource
import sys
import threading
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ============================================================================
# Performance Metrics Data Classes
# ============================================================================


@dataclass
class TimingMetrics:
    """Timing metrics for an operation."""

    operation_name: str
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    cpu_time: float = 0.0
    call_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation": self.operation_name,
            "duration_seconds": self.duration,
            "cpu_time_seconds": self.cpu_time,
            "call_count": self.call_count,
        }


@dataclass
class MemoryMetrics:
    """Memory metrics for an operation."""

    operation_name: str
    start_memory: int = 0
    peak_memory: int = 0
    end_memory: int = 0
    memory_delta: int = 0
    allocations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation": self.operation_name,
            "memory_delta_mb": self.memory_delta / (1024 * 1024),
            "peak_memory_mb": self.peak_memory / (1024 * 1024),
            "allocations": self.allocations,
        }


@dataclass
class PerformanceReport:
    """Complete performance report."""

    timing_metrics: List[TimingMetrics] = field(default_factory=list)
    memory_metrics: List[MemoryMetrics] = field(default_factory=list)
    hot_paths: List[Dict[str, Any]] = field(default_factory=list)
    total_duration: float = 0.0
    total_memory_delta: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "total_duration_seconds": self.total_duration,
            "total_memory_delta_mb": self.total_memory_delta / (1024 * 1024),
            "timing_metrics": [m.to_dict() for m in self.timing_metrics],
            "memory_metrics": [m.to_dict() for m in self.memory_metrics],
            "hot_paths": self.hot_paths,
        }


# ============================================================================
# Performance Monitor
# ============================================================================


class PerformanceMonitor:
    """Central performance monitoring system."""

    def __init__(self, enable_memory_profiling: bool = True):
        """
        Initialize performance monitor.

        Args:
            enable_memory_profiling: Enable memory profiling (adds overhead)
        """
        self.enable_memory_profiling = enable_memory_profiling
        self.timing_metrics: List[TimingMetrics] = []
        self.memory_metrics: List[MemoryMetrics] = []
        self.active_timers: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__ + ".PerformanceMonitor")

        # Start memory tracking if enabled
        if self.enable_memory_profiling:
            try:
                tracemalloc.start()
            except Exception as e:
                self.logger.warning(f"Could not start memory profiling: {e}")
                self.enable_memory_profiling = False

    @contextmanager
    def measure_operation(self, operation_name: str):
        """
        Context manager for measuring operation performance.

        Args:
            operation_name: Name of operation to measure

        Yields:
            None
        """
        # Start measurements
        start_time = time.time()
        start_cpu = time.process_time()
        start_memory = 0
        memory_snapshot = None

        if self.enable_memory_profiling:
            try:
                start_memory = self._get_current_memory()
                memory_snapshot = tracemalloc.take_snapshot()
            except Exception:
                pass

        try:
            yield
        finally:
            # End measurements
            end_time = time.time()
            end_cpu = time.process_time()
            duration = end_time - start_time
            cpu_time = end_cpu - start_cpu

            # Record timing metrics
            timing = TimingMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                cpu_time=cpu_time,
                call_count=1,
            )

            with self.lock:
                self.timing_metrics.append(timing)

            # Record memory metrics
            if self.enable_memory_profiling:
                try:
                    end_memory = self._get_current_memory()
                    peak_memory = self._get_peak_memory()

                    memory = MemoryMetrics(
                        operation_name=operation_name,
                        start_memory=start_memory,
                        peak_memory=peak_memory,
                        end_memory=end_memory,
                        memory_delta=end_memory - start_memory,
                    )

                    with self.lock:
                        self.memory_metrics.append(memory)

                except Exception as e:
                    self.logger.debug(f"Error collecting memory metrics: {e}")

    def _get_current_memory(self) -> int:
        """Get current memory usage in bytes."""
        try:
            current, peak = tracemalloc.get_traced_memory()
            return current
        except Exception:
            return 0

    def _get_peak_memory(self) -> int:
        """Get peak memory usage in bytes."""
        try:
            current, peak = tracemalloc.get_traced_memory()
            return peak
        except Exception:
            return 0

    def profile_function(self, func: Callable) -> Callable:
        """
        Decorator for profiling functions.

        Args:
            func: Function to profile

        Returns:
            Decorated function
        """

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self.measure_operation(func.__name__):
                return func(*args, **kwargs)

        return wrapper

    def get_report(self) -> PerformanceReport:
        """
        Get performance report.

        Returns:
            PerformanceReport object
        """
        with self.lock:
            total_duration = sum(m.duration for m in self.timing_metrics)
            total_memory_delta = sum(m.memory_delta for m in self.memory_metrics)

            report = PerformanceReport(
                timing_metrics=self.timing_metrics.copy(),
                memory_metrics=self.memory_metrics.copy(),
                total_duration=total_duration,
                total_memory_delta=total_memory_delta,
            )

        return report

    def print_summary(self):
        """Print performance summary."""
        report = self.get_report()

        print("\n" + "=" * 80)
        print("PERFORMANCE SUMMARY")
        print("=" * 80)
        print(f"Total Duration: {report.total_duration:.3f} seconds")
        print(f"Total Memory Delta: {report.total_memory_delta / (1024*1024):.2f} MB")
        print()

        # Timing summary
        print("Top 10 Operations by Duration:")
        print("-" * 80)
        sorted_timing = sorted(report.timing_metrics, key=lambda x: x.duration, reverse=True)[:10]
        for metric in sorted_timing:
            print(
                f"  {metric.operation_name:40s} {metric.duration:8.3f}s  (CPU: {metric.cpu_time:.3f}s)"
            )

        # Memory summary
        if report.memory_metrics:
            print()
            print("Top 10 Operations by Memory:")
            print("-" * 80)
            sorted_memory = sorted(
                report.memory_metrics, key=lambda x: abs(x.memory_delta), reverse=True
            )[:10]
            for metric in sorted_memory:
                delta_mb = metric.memory_delta / (1024 * 1024)
                peak_mb = metric.peak_memory / (1024 * 1024)
                print(f"  {metric.operation_name:40s} {delta_mb:8.2f}MB  (Peak: {peak_mb:.2f}MB)")

        print("=" * 80 + "\n")

    def reset(self):
        """Reset all metrics."""
        with self.lock:
            self.timing_metrics.clear()
            self.memory_metrics.clear()
            self.active_timers.clear()

    def __del__(self):
        """Cleanup on deletion."""
        if self.enable_memory_profiling:
            try:
                tracemalloc.stop()
            except Exception:
                pass


# ============================================================================
# CPU Profiler
# ============================================================================


class CPUProfiler:
    """CPU profiling utilities."""

    def __init__(self):
        """Initialize CPU profiler."""
        self.profiler = cProfile.Profile()
        self.logger = logging.getLogger(__name__ + ".CPUProfiler")

    @contextmanager
    def profile(self):
        """
        Context manager for CPU profiling.

        Yields:
            None
        """
        self.profiler.enable()
        try:
            yield
        finally:
            self.profiler.disable()

    def get_stats(self, sort_by: str = "cumulative", limit: int = 20) -> str:
        """
        Get profiling statistics.

        Args:
            sort_by: Sort order (cumulative, time, calls, etc.)
            limit: Number of entries to show

        Returns:
            Formatted statistics string
        """
        stream = io.StringIO()
        stats = pstats.Stats(self.profiler, stream=stream)
        stats.strip_dirs()
        stats.sort_stats(sort_by)
        stats.print_stats(limit)
        return stream.getvalue()

    def save_stats(self, output_file: str):
        """
        Save profiling statistics to file.

        Args:
            output_file: Path to output file
        """
        self.profiler.dump_stats(output_file)
        self.logger.info(f"Profiling stats saved to {output_file}")

    def identify_hot_paths(self, threshold_percent: float = 5.0) -> List[Dict[str, Any]]:
        """
        Identify hot paths (functions consuming > threshold_percent of time).

        Args:
            threshold_percent: Minimum percentage to consider a hot path

        Returns:
            List of hot path information
        """
        stats = pstats.Stats(self.profiler)
        stats.strip_dirs()
        stats.sort_stats("cumulative")

        hot_paths = []
        total_time = stats.total_tt

        for func, (cc, nc, tt, ct, callers) in stats.stats.items():
            percent = (ct / total_time * 100) if total_time > 0 else 0

            if percent >= threshold_percent:
                hot_paths.append(
                    {
                        "function": f"{func[0]}:{func[1]}:{func[2]}",
                        "cumulative_time": ct,
                        "percent_time": percent,
                        "calls": cc,
                        "time_per_call": ct / cc if cc > 0 else 0,
                    }
                )

        return hot_paths


# ============================================================================
# Memory Profiler
# ============================================================================


class MemoryProfiler:
    """Memory profiling utilities."""

    def __init__(self):
        """Initialize memory profiler."""
        self.snapshots: List[Tuple[str, Any]] = []
        self.logger = logging.getLogger(__name__ + ".MemoryProfiler")
        self.enabled = False

        try:
            tracemalloc.start()
            self.enabled = True
        except Exception as e:
            self.logger.warning(f"Could not start memory profiler: {e}")

    def take_snapshot(self, label: str = "snapshot"):
        """
        Take memory snapshot.

        Args:
            label: Label for snapshot
        """
        if not self.enabled:
            return

        try:
            snapshot = tracemalloc.take_snapshot()
            self.snapshots.append((label, snapshot))
            self.logger.debug(f"Memory snapshot taken: {label}")
        except Exception as e:
            self.logger.error(f"Error taking snapshot: {e}")

    def compare_snapshots(
        self, label1: str, label2: str, top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Compare two snapshots to identify memory changes.

        Args:
            label1: First snapshot label
            label2: Second snapshot label
            top_n: Number of top differences to return

        Returns:
            List of top memory differences
        """
        if not self.enabled:
            return []

        # Find snapshots
        snap1 = None
        snap2 = None

        for label, snapshot in self.snapshots:
            if label == label1:
                snap1 = snapshot
            if label == label2:
                snap2 = snapshot

        if not snap1 or not snap2:
            self.logger.warning(f"Could not find snapshots: {label1}, {label2}")
            return []

        # Compare
        try:
            differences = snap2.compare_to(snap1, "lineno")
            top_diffs = []

            for i, stat in enumerate(differences[:top_n]):
                top_diffs.append(
                    {
                        "rank": i + 1,
                        "file": stat.traceback.format()[0] if stat.traceback else "unknown",
                        "size_diff": stat.size_diff,
                        "size_diff_mb": stat.size_diff / (1024 * 1024),
                        "count_diff": stat.count_diff,
                    }
                )

            return top_diffs

        except Exception as e:
            self.logger.error(f"Error comparing snapshots: {e}")
            return []

    def get_current_memory(self) -> Dict[str, Any]:
        """
        Get current memory usage.

        Returns:
            Dictionary with memory information
        """
        if not self.enabled:
            return {}

        try:
            current, peak = tracemalloc.get_traced_memory()

            return {
                "current_mb": current / (1024 * 1024),
                "peak_mb": peak / (1024 * 1024),
            }
        except Exception:
            return {}

    def get_top_allocations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top memory allocations.

        Args:
            limit: Number of top allocations to return

        Returns:
            List of top allocations
        """
        if not self.enabled:
            return []

        try:
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics("lineno")

            allocations = []
            for i, stat in enumerate(top_stats[:limit]):
                allocations.append(
                    {
                        "rank": i + 1,
                        "file": str(stat.traceback),
                        "size_mb": stat.size / (1024 * 1024),
                        "count": stat.count,
                    }
                )

            return allocations

        except Exception as e:
            self.logger.error(f"Error getting allocations: {e}")
            return []

    def __del__(self):
        """Cleanup on deletion."""
        if self.enabled:
            try:
                tracemalloc.stop()
            except Exception:
                pass


# ============================================================================
# Resource Monitor
# ============================================================================


class ResourceMonitor:
    """Monitor system resource usage."""

    def __init__(self):
        """Initialize resource monitor."""
        self.logger = logging.getLogger(__name__ + ".ResourceMonitor")

    def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get current resource usage.

        Returns:
            Dictionary with resource usage information
        """
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)

            return {
                "user_time": usage.ru_utime,
                "system_time": usage.ru_stime,
                "max_rss_mb": usage.ru_maxrss / 1024,  # Convert to MB
                "page_faults": usage.ru_majflt,
                "io_operations": usage.ru_inblock + usage.ru_oublock,
            }
        except Exception as e:
            self.logger.error(f"Error getting resource usage: {e}")
            return {}

    def monitor_continuously(
        self, interval: float = 1.0, duration: float = 10.0
    ) -> List[Dict[str, Any]]:
        """
        Monitor resources continuously.

        Args:
            interval: Sampling interval in seconds
            duration: Total duration in seconds

        Returns:
            List of resource usage samples
        """
        samples = []
        start_time = time.time()

        while time.time() - start_time < duration:
            sample = self.get_resource_usage()
            sample["timestamp"] = time.time() - start_time
            samples.append(sample)
            time.sleep(interval)

        return samples


# ============================================================================
# Global Performance Monitor Instance
# ============================================================================

_global_perf_monitor: Optional[PerformanceMonitor] = None
_monitor_lock = threading.Lock()


def get_performance_monitor(enable_memory_profiling: bool = True) -> PerformanceMonitor:
    """
    Get global performance monitor instance.

    Args:
        enable_memory_profiling: Enable memory profiling

    Returns:
        PerformanceMonitor instance
    """
    global _global_perf_monitor

    with _monitor_lock:
        if _global_perf_monitor is None:
            _global_perf_monitor = PerformanceMonitor(enable_memory_profiling)

    return _global_perf_monitor


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    print("=== Testing Performance Profiling ===\n")

    # Test performance monitor
    print("1. Testing Performance Monitor:")
    monitor = get_performance_monitor()

    # Simulate some operations
    with monitor.measure_operation("operation_1"):
        time.sleep(0.1)
        data = [i * i for i in range(100000)]

    with monitor.measure_operation("operation_2"):
        time.sleep(0.05)
        result = sum(data)

    # Print summary
    monitor.print_summary()

    # Test CPU profiler
    print("\n2. Testing CPU Profiler:")
    cpu_profiler = CPUProfiler()

    with cpu_profiler.profile():
        # Some CPU-intensive work
        result = sum(i * i for i in range(1000000))

    print("CPU Profiling Stats (Top 10):")
    print(cpu_profiler.get_stats(limit=10))

    # Identify hot paths
    hot_paths = cpu_profiler.identify_hot_paths(threshold_percent=1.0)
    print(f"\nFound {len(hot_paths)} hot paths")

    # Test memory profiler
    print("\n3. Testing Memory Profiler:")
    mem_profiler = MemoryProfiler()

    if mem_profiler.enabled:
        mem_profiler.take_snapshot("before")

        # Allocate some memory
        big_list = [i for i in range(1000000)]

        mem_profiler.take_snapshot("after")

        # Compare snapshots
        diffs = mem_profiler.compare_snapshots("before", "after", top_n=5)
        print("Top memory differences:")
        for diff in diffs:
            print(f"  {diff}")

        # Get current memory
        mem_info = mem_profiler.get_current_memory()
        print(f"\nCurrent memory: {mem_info}")

    print("\n=== Tests Complete ===")
