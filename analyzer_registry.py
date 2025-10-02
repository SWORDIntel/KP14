#!/usr/bin/env python3
"""
Analyzer Registry - Plugin discovery and management system

This module provides automatic discovery, registration, and lifecycle management
for analyzer plugins in the KP14 platform.
"""

import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Type, Any
from collections import defaultdict
import threading

from base_analyzer import (
    BaseAnalyzer,
    AnalyzerCapabilities,
    AnalyzerCategory,
    AnalysisPhase,
    FileType,
    AnalysisResult
)


class AnalyzerRegistry:
    """
    Centralized registry for all analyzer plugins.

    Features:
    - Automatic plugin discovery from directories
    - Dependency resolution
    - Load order determination
    - Lifecycle management
    - Thread-safe registration
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._analyzers: Dict[str, Type[BaseAnalyzer]] = {}
        self._instances: Dict[str, BaseAnalyzer] = {}
        self._capabilities: Dict[str, AnalyzerCapabilities] = {}
        self._load_order: List[str] = []
        self._lock = threading.Lock()

    def discover_analyzers(self, search_paths: List[Path]) -> int:
        """
        Automatically discover analyzer plugins from directories.

        Searches for Python modules that contain classes inheriting from BaseAnalyzer.

        Args:
            search_paths: List of directories to search

        Returns:
            Number of analyzers discovered
        """
        discovered_count = 0

        for search_path in search_paths:
            if not search_path.exists():
                self.logger.warning(f"Search path does not exist: {search_path}")
                continue

            self.logger.info(f"Searching for analyzers in: {search_path}")

            # Find all Python files
            for py_file in search_path.glob("**/*.py"):
                if py_file.name.startswith("_"):
                    continue

                try:
                    # Load the module
                    module_name = py_file.stem
                    spec = importlib.util.spec_from_file_location(module_name, py_file)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Find analyzer classes
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if (issubclass(obj, BaseAnalyzer) and
                                obj is not BaseAnalyzer and
                                not inspect.isabstract(obj)):
                                self.register_analyzer(obj)
                                discovered_count += 1
                                self.logger.debug(f"Discovered analyzer: {name} in {py_file}")

                except Exception as e:
                    self.logger.error(f"Error loading module {py_file}: {e}")

        self.logger.info(f"Discovered {discovered_count} analyzers")
        return discovered_count

    def register_analyzer(self, analyzer_class: Type[BaseAnalyzer]) -> bool:
        """
        Register an analyzer class.

        Args:
            analyzer_class: Analyzer class to register

        Returns:
            True if registered successfully, False otherwise
        """
        with self._lock:
            try:
                # Create temporary instance to get capabilities
                temp_instance = analyzer_class({})
                capabilities = temp_instance.get_capabilities()

                analyzer_name = capabilities.name

                # Check for duplicate registration
                if analyzer_name in self._analyzers:
                    existing_version = self._capabilities[analyzer_name].version
                    new_version = capabilities.version

                    # Allow re-registration if newer version
                    if self._compare_versions(new_version, existing_version) <= 0:
                        self.logger.warning(
                            f"Analyzer {analyzer_name} already registered "
                            f"(existing: {existing_version}, new: {new_version})"
                        )
                        return False

                # Register the analyzer
                self._analyzers[analyzer_name] = analyzer_class
                self._capabilities[analyzer_name] = capabilities
                self.logger.info(f"Registered analyzer: {analyzer_name} v{capabilities.version}")

                # Invalidate load order - needs recalculation
                self._load_order = []

                return True

            except Exception as e:
                self.logger.error(f"Error registering analyzer {analyzer_class}: {e}")
                return False

    def unregister_analyzer(self, analyzer_name: str):
        """
        Unregister an analyzer.

        Args:
            analyzer_name: Name of the analyzer to unregister
        """
        with self._lock:
            if analyzer_name in self._analyzers:
                del self._analyzers[analyzer_name]
                del self._capabilities[analyzer_name]
                if analyzer_name in self._instances:
                    # Cleanup instance
                    try:
                        self._instances[analyzer_name].cleanup()
                    except Exception as e:
                        self.logger.error(f"Error cleaning up {analyzer_name}: {e}")
                    del self._instances[analyzer_name]
                self._load_order = []
                self.logger.info(f"Unregistered analyzer: {analyzer_name}")

    def get_analyzer(self, analyzer_name: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseAnalyzer]:
        """
        Get an analyzer instance.

        Creates a new instance or returns cached instance.

        Args:
            analyzer_name: Name of the analyzer
            config: Configuration for the analyzer

        Returns:
            Analyzer instance or None if not found
        """
        with self._lock:
            if analyzer_name not in self._analyzers:
                self.logger.error(f"Analyzer not found: {analyzer_name}")
                return None

            # Return cached instance if no config provided
            if config is None and analyzer_name in self._instances:
                return self._instances[analyzer_name]

            # Create new instance
            try:
                analyzer_class = self._analyzers[analyzer_name]
                instance = analyzer_class(config)

                # Cache if no custom config
                if config is None:
                    self._instances[analyzer_name] = instance

                return instance

            except Exception as e:
                self.logger.error(f"Error creating analyzer instance {analyzer_name}: {e}")
                return None

    def get_analyzers_by_category(self, category: AnalyzerCategory) -> List[str]:
        """
        Get all analyzer names for a specific category.

        Args:
            category: Analyzer category to filter by

        Returns:
            List of analyzer names
        """
        return [
            name for name, caps in self._capabilities.items()
            if caps.category == category
        ]

    def get_analyzers_by_phase(self, phase: AnalysisPhase) -> List[str]:
        """
        Get all analyzer names for a specific analysis phase.

        Args:
            phase: Analysis phase to filter by

        Returns:
            List of analyzer names
        """
        return [
            name for name, caps in self._capabilities.items()
            if phase in caps.supported_phases
        ]

    def get_analyzers_for_file_type(self, file_type: FileType) -> List[str]:
        """
        Get all analyzer names that support a file type.

        Args:
            file_type: File type to filter by

        Returns:
            List of analyzer names
        """
        return [
            name for name, caps in self._capabilities.items()
            if not caps.supported_file_types or file_type in caps.supported_file_types
        ]

    def get_load_order(self) -> List[str]:
        """
        Get analyzers in execution order (considering dependencies and priority).

        Returns:
            Ordered list of analyzer names
        """
        if self._load_order:
            return self._load_order.copy()

        with self._lock:
            self._load_order = self._calculate_load_order()
            return self._load_order.copy()

    def _calculate_load_order(self) -> List[str]:
        """
        Calculate load order using topological sort with priority.

        Returns:
            Ordered list of analyzer names
        """
        # Build dependency graph
        graph = defaultdict(set)
        in_degree = defaultdict(int)
        all_analyzers = set(self._analyzers.keys())

        for name, caps in self._capabilities.items():
            # Add dependencies
            for dep in caps.dependencies:
                if dep in all_analyzers:
                    graph[dep].add(name)
                    in_degree[name] += 1
                else:
                    self.logger.warning(f"Analyzer {name} depends on unknown analyzer: {dep}")

            # Ensure all nodes are in graph
            if name not in in_degree:
                in_degree[name] = 0

        # Topological sort with priority
        result = []
        available = []

        # Find all nodes with no dependencies
        for name in all_analyzers:
            if in_degree[name] == 0:
                available.append(name)

        while available:
            # Sort by priority
            available.sort(key=lambda x: self._get_priority(x))

            # Process highest priority
            current = available.pop(0)
            result.append(current)

            # Update neighbors
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    available.append(neighbor)

        # Check for circular dependencies
        if len(result) != len(all_analyzers):
            missing = all_analyzers - set(result)
            self.logger.error(f"Circular dependency detected! Unprocessed analyzers: {missing}")
            # Add remaining analyzers to avoid total failure
            result.extend(sorted(missing, key=lambda x: self._get_priority(x)))

        return result

    def _get_priority(self, analyzer_name: str) -> int:
        """Get priority for an analyzer"""
        try:
            instance = self.get_analyzer(analyzer_name)
            return instance.get_priority() if instance else 999
        except Exception:
            return 999

    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare version strings.

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split(".")]
            v2_parts = [int(x) for x in version2.split(".")]

            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1

            if len(v1_parts) < len(v2_parts):
                return -1
            elif len(v1_parts) > len(v2_parts):
                return 1

            return 0
        except Exception:
            return 0

    def get_capabilities(self, analyzer_name: str) -> Optional[AnalyzerCapabilities]:
        """
        Get capabilities for an analyzer.

        Args:
            analyzer_name: Name of the analyzer

        Returns:
            AnalyzerCapabilities or None
        """
        return self._capabilities.get(analyzer_name)

    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        List all registered analyzers with metadata.

        Returns:
            List of analyzer information dictionaries
        """
        analyzers = []
        for name, caps in self._capabilities.items():
            analyzers.append({
                "name": name,
                "version": caps.version,
                "category": caps.category.value,
                "description": caps.description,
                "author": caps.author,
                "file_types": [ft.value for ft in caps.supported_file_types],
                "phases": [phase.value for phase in caps.supported_phases],
                "hardware_accelerated": caps.hardware_accelerated,
                "dependencies": list(caps.dependencies),
            })
        return analyzers

    def validate_dependencies(self) -> Dict[str, List[str]]:
        """
        Validate that all analyzer dependencies are satisfied.

        Returns:
            Dictionary mapping analyzer names to lists of missing dependencies
        """
        missing_deps = {}
        all_analyzers = set(self._analyzers.keys())

        for name, caps in self._capabilities.items():
            missing = []
            for dep in caps.dependencies:
                if dep not in all_analyzers:
                    missing.append(dep)

            if missing:
                missing_deps[name] = missing

        return missing_deps

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get registry statistics.

        Returns:
            Dictionary with statistics
        """
        by_category = defaultdict(int)
        by_phase = defaultdict(int)
        hardware_count = 0

        for caps in self._capabilities.values():
            by_category[caps.category.value] += 1
            for phase in caps.supported_phases:
                by_phase[phase.value] += 1
            if caps.hardware_accelerated:
                hardware_count += 1

        return {
            "total_analyzers": len(self._analyzers),
            "by_category": dict(by_category),
            "by_phase": dict(by_phase),
            "hardware_accelerated": hardware_count,
            "missing_dependencies": len(self.validate_dependencies()),
        }

    def cleanup_all(self):
        """Cleanup all analyzer instances"""
        with self._lock:
            for name, instance in self._instances.items():
                try:
                    instance.cleanup()
                except Exception as e:
                    self.logger.error(f"Error cleaning up {name}: {e}")
            self._instances.clear()


# Global registry instance
_global_registry: Optional[AnalyzerRegistry] = None
_registry_lock = threading.Lock()


def get_global_registry() -> AnalyzerRegistry:
    """
    Get the global analyzer registry instance (singleton).

    Returns:
        Global AnalyzerRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        with _registry_lock:
            if _global_registry is None:
                _global_registry = AnalyzerRegistry()
    return _global_registry


def register_analyzer(analyzer_class: Type[BaseAnalyzer]) -> bool:
    """
    Convenience function to register an analyzer with the global registry.

    Args:
        analyzer_class: Analyzer class to register

    Returns:
        True if registered successfully
    """
    return get_global_registry().register_analyzer(analyzer_class)
