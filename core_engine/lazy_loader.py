"""
Lazy Loading Module for KP14 Analysis Framework
===============================================

Provides lazy loading capabilities for:
- Analyzer modules (load on first use)
- Heavy dependencies (radare2, numpy, OpenVINO)
- ML models
- Large datasets

Features:
- Deferred imports
- Automatic dependency resolution
- Memory-efficient loading
- Thread-safe initialization
- Import error handling with fallbacks

Author: KP14 Development Team
Version: 1.0.0
"""

import importlib
import logging
import sys
import threading
import weakref
from typing import Any, Callable, Dict, Optional, Type, Union


# ============================================================================
# Lazy Import Proxy
# ============================================================================


class LazyImportProxy:
    """Proxy object that defers module import until first access."""

    def __init__(self, module_name: str, attribute: Optional[str] = None):
        """
        Initialize lazy import proxy.

        Args:
            module_name: Name of module to import
            attribute: Optional attribute to access from module
        """
        self._module_name = module_name
        self._attribute = attribute
        self._module = None
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__ + ".LazyImportProxy")

    def _load_module(self):
        """Load the module if not already loaded."""
        if self._module is None:
            with self._lock:
                if self._module is None:  # Double-check locking
                    try:
                        self._logger.debug(f"Lazy loading module: {self._module_name}")
                        self._module = importlib.import_module(self._module_name)

                        if self._attribute:
                            self._module = getattr(self._module, self._attribute)

                    except ImportError as e:
                        self._logger.error(f"Failed to lazy load {self._module_name}: {e}")
                        raise

    def __getattr__(self, name: str):
        """Get attribute from loaded module."""
        self._load_module()
        return getattr(self._module, name)

    def __call__(self, *args, **kwargs):
        """Call the loaded module/attribute if callable."""
        self._load_module()
        return self._module(*args, **kwargs)

    def __repr__(self):
        """String representation."""
        loaded = "loaded" if self._module is not None else "not loaded"
        return f"<LazyImportProxy {self._module_name} ({loaded})>"


# ============================================================================
# Lazy Class Loader
# ============================================================================


class LazyClassLoader:
    """Lazy loader for class instances."""

    def __init__(self, module_path: str, class_name: str, *init_args, **init_kwargs):
        """
        Initialize lazy class loader.

        Args:
            module_path: Import path of module
            class_name: Name of class to instantiate
            *init_args: Arguments for class initialization
            **init_kwargs: Keyword arguments for class initialization
        """
        self.module_path = module_path
        self.class_name = class_name
        self.init_args = init_args
        self.init_kwargs = init_kwargs
        self._instance = None
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__ + ".LazyClassLoader")

    def _create_instance(self):
        """Create class instance if not already created."""
        if self._instance is None:
            with self._lock:
                if self._instance is None:  # Double-check locking
                    try:
                        self._logger.debug(
                            f"Lazy loading class: {self.class_name} from {self.module_path}"
                        )
                        module = importlib.import_module(self.module_path)
                        class_obj = getattr(module, self.class_name)
                        self._instance = class_obj(*self.init_args, **self.init_kwargs)

                    except Exception as e:
                        self._logger.error(
                            f"Failed to lazy load {self.class_name} from {self.module_path}: {e}"
                        )
                        raise

    def get_instance(self):
        """
        Get the class instance, loading it if necessary.

        Returns:
            Instance of the class
        """
        self._create_instance()
        return self._instance

    def __getattr__(self, name: str):
        """Proxy attribute access to the instance."""
        self._create_instance()
        return getattr(self._instance, name)

    def __call__(self, *args, **kwargs):
        """Proxy calls to the instance."""
        self._create_instance()
        return self._instance(*args, **kwargs)


# ============================================================================
# Lazy Dependency Manager
# ============================================================================


class LazyDependencyManager:
    """Manages lazy loading of heavy dependencies."""

    def __init__(self):
        """Initialize lazy dependency manager."""
        self._dependencies: Dict[str, Any] = {}
        self._availability: Dict[str, bool] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__ + ".LazyDependencyManager")

    def register_dependency(self, name: str, import_path: str, attribute: Optional[str] = None):
        """
        Register a lazy dependency.

        Args:
            name: Name to identify dependency
            import_path: Module import path
            attribute: Optional attribute to access
        """
        with self._lock:
            if name not in self._dependencies:
                self._dependencies[name] = LazyImportProxy(import_path, attribute)
                self._availability[name] = None  # Unknown until first access

    def get_dependency(self, name: str) -> Optional[Any]:
        """
        Get dependency, loading it if necessary.

        Args:
            name: Name of dependency

        Returns:
            Loaded dependency or None if unavailable
        """
        with self._lock:
            if name not in self._dependencies:
                self._logger.warning(f"Unknown dependency: {name}")
                return None

            # Check if already tested
            if self._availability[name] is False:
                return None

            # Try to load
            try:
                dep = self._dependencies[name]
                dep._load_module()  # Force loading
                self._availability[name] = True
                return dep

            except Exception as e:
                self._logger.warning(f"Dependency {name} not available: {e}")
                self._availability[name] = False
                return None

    def is_available(self, name: str) -> bool:
        """
        Check if dependency is available.

        Args:
            name: Name of dependency

        Returns:
            True if available, False otherwise
        """
        dep = self.get_dependency(name)
        return dep is not None

    def get_available_dependencies(self) -> Dict[str, bool]:
        """
        Get status of all dependencies.

        Returns:
            Dictionary mapping dependency names to availability status
        """
        with self._lock:
            result = {}
            for name in self._dependencies:
                result[name] = self.is_available(name)
            return result


# ============================================================================
# Analyzer Module Registry
# ============================================================================


class AnalyzerRegistry:
    """Registry for lazy-loaded analyzer modules."""

    def __init__(self):
        """Initialize analyzer registry."""
        self._analyzers: Dict[str, Dict[str, Any]] = {}
        self._instances: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__ + ".AnalyzerRegistry")

    def register_analyzer(
        self,
        name: str,
        module_path: str,
        class_name: str,
        dependencies: Optional[list[str]] = None,
        enabled: bool = True,
    ):
        """
        Register an analyzer for lazy loading.

        Args:
            name: Analyzer name
            module_path: Import path of module
            class_name: Name of analyzer class
            dependencies: Optional list of required dependencies
            enabled: Whether analyzer is enabled
        """
        with self._lock:
            self._analyzers[name] = {
                "module_path": module_path,
                "class_name": class_name,
                "dependencies": dependencies or [],
                "enabled": enabled,
                "loaded": False,
            }

    def get_analyzer(self, name: str, *init_args, **init_kwargs) -> Optional[Any]:
        """
        Get analyzer instance, loading it if necessary.

        Args:
            name: Analyzer name
            *init_args: Arguments for analyzer initialization
            **init_kwargs: Keyword arguments for analyzer initialization

        Returns:
            Analyzer instance or None if unavailable
        """
        with self._lock:
            if name not in self._analyzers:
                self._logger.warning(f"Unknown analyzer: {name}")
                return None

            info = self._analyzers[name]

            if not info["enabled"]:
                self._logger.debug(f"Analyzer {name} is disabled")
                return None

            # Check if already instantiated
            instance_key = f"{name}:{id(init_args)}:{id(init_kwargs)}"
            if instance_key in self._instances:
                return self._instances[instance_key]

            # Load and instantiate
            try:
                self._logger.info(f"Loading analyzer: {name}")
                module = importlib.import_module(info["module_path"])
                analyzer_class = getattr(module, info["class_name"])
                instance = analyzer_class(*init_args, **init_kwargs)

                self._instances[instance_key] = instance
                info["loaded"] = True

                return instance

            except Exception as e:
                self._logger.error(f"Failed to load analyzer {name}: {e}")
                return None

    def unload_analyzer(self, name: str):
        """
        Unload analyzer and free memory.

        Args:
            name: Analyzer name
        """
        with self._lock:
            # Remove all instances of this analyzer
            keys_to_remove = [k for k in self._instances if k.startswith(f"{name}:")]
            for key in keys_to_remove:
                del self._instances[key]

            if name in self._analyzers:
                self._analyzers[name]["loaded"] = False

    def get_loaded_analyzers(self) -> list[str]:
        """
        Get list of currently loaded analyzers.

        Returns:
            List of analyzer names
        """
        with self._lock:
            return [name for name, info in self._analyzers.items() if info["loaded"]]

    def get_registry_info(self) -> Dict[str, Any]:
        """
        Get information about registered analyzers.

        Returns:
            Dictionary with registry information
        """
        with self._lock:
            return {
                "total_registered": len(self._analyzers),
                "enabled": sum(1 for info in self._analyzers.values() if info["enabled"]),
                "loaded": sum(1 for info in self._analyzers.values() if info["loaded"]),
                "instances": len(self._instances),
            }


# ============================================================================
# Global Instances
# ============================================================================

_dependency_manager: Optional[LazyDependencyManager] = None
_analyzer_registry: Optional[AnalyzerRegistry] = None
_manager_lock = threading.Lock()


def get_dependency_manager() -> LazyDependencyManager:
    """
    Get global dependency manager instance.

    Returns:
        LazyDependencyManager instance
    """
    global _dependency_manager

    with _manager_lock:
        if _dependency_manager is None:
            _dependency_manager = LazyDependencyManager()

            # Register common heavy dependencies
            _dependency_manager.register_dependency("radare2", "r2pipe")
            _dependency_manager.register_dependency("numpy", "numpy")
            _dependency_manager.register_dependency("openvino", "openvino.runtime", "Core")
            _dependency_manager.register_dependency("capstone", "capstone")
            _dependency_manager.register_dependency("pefile", "pefile")
            _dependency_manager.register_dependency("yara", "yara")

    return _dependency_manager


def get_analyzer_registry() -> AnalyzerRegistry:
    """
    Get global analyzer registry instance.

    Returns:
        AnalyzerRegistry instance
    """
    global _analyzer_registry

    with _manager_lock:
        if _analyzer_registry is None:
            _analyzer_registry = AnalyzerRegistry()

    return _analyzer_registry


# ============================================================================
# Lazy Loading Decorators
# ============================================================================


def lazy_import(module_name: str, attribute: Optional[str] = None):
    """
    Decorator for lazy importing modules.

    Args:
        module_name: Name of module to import
        attribute: Optional attribute to access

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        proxy = LazyImportProxy(module_name, attribute)

        def wrapper(*args, **kwargs):
            # Inject lazy-loaded module as first argument
            return func(proxy, *args, **kwargs)

        return wrapper

    return decorator


def require_dependencies(*dependency_names: str):
    """
    Decorator that checks for required dependencies before execution.

    Args:
        *dependency_names: Names of required dependencies

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            dep_manager = get_dependency_manager()

            # Check all dependencies
            missing = []
            for name in dependency_names:
                if not dep_manager.is_available(name):
                    missing.append(name)

            if missing:
                raise RuntimeError(
                    f"Required dependencies not available: {', '.join(missing)}"
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s"
    )

    print("=== Testing Lazy Loading ===\n")

    # Test dependency manager
    print("1. Testing Dependency Manager:")
    dep_mgr = get_dependency_manager()
    available = dep_mgr.get_available_dependencies()
    for name, status in available.items():
        status_str = "available" if status else "not available"
        print(f"   {name}: {status_str}")

    # Test analyzer registry
    print("\n2. Testing Analyzer Registry:")
    registry = get_analyzer_registry()

    # Register a test analyzer
    registry.register_analyzer(
        name="TestAnalyzer",
        module_path="pathlib",
        class_name="Path",
        enabled=True,
    )

    info = registry.get_registry_info()
    print(f"   Registry info: {info}")

    # Load analyzer
    analyzer = registry.get_analyzer("TestAnalyzer", "/tmp")
    print(f"   Loaded analyzer: {analyzer}")

    # Test lazy import decorator
    print("\n3. Testing Lazy Import Decorator:")

    @lazy_import("json")
    def test_json_func(json_module, data):
        return json_module.dumps(data)

    result = test_json_func({"test": "value"})
    print(f"   JSON result: {result}")

    # Test dependency decorator
    print("\n4. Testing Dependency Decorator:")

    @require_dependencies("numpy")
    def test_numpy_func():
        return "NumPy is available!"

    try:
        result = test_numpy_func()
        print(f"   {result}")
    except RuntimeError as e:
        print(f"   Error: {e}")

    print("\n=== Tests Complete ===")
