#!/usr/bin/env python3
"""
KEYPLUG Module Loader
---------------------
Handles the dynamic loading and initialization of analysis modules.
Provides utilities for discovering, importing, and instantiating analysis classes.
"""

import os
import sys
import importlib
import traceback
from types import ModuleType
from typing import Dict, List, Any, Optional, Type, Tuple

# OpenVINO initialization
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    OV_CORE = Core()
    
    # Select preferred device
    PREFERRED_DEVICE = "CPU"  # Default
    available_devices = [dev.lower() for dev in OV_CORE.available_devices]
    
    if "gpu" in available_devices:
        PREFERRED_DEVICE = "GPU"
    elif "vpu" in available_devices:
        PREFERRED_DEVICE = "VPU"
    elif "npu" in available_devices:
        PREFERRED_DEVICE = "NPU"
    
    print(f"OpenVINO runtime available. Preferred device: {PREFERRED_DEVICE}")
    print(f"Available devices: {OV_CORE.available_devices}")
    
except ImportError:
    OPENVINO_AVAILABLE = False
    OV_CORE = None
    PREFERRED_DEVICE = "CPU"  # Fallback
    print("WARNING: OpenVINO not available. Performance may be degraded.")


class PlaceholderFactory:
    """
    Factory for creating placeholder classes when actual modules cannot be loaded.
    This ensures the orchestrator continues to work even when some modules are missing.
    """
    
    @staticmethod
    def create_placeholder_class(class_name: str, base_class_name: str = "BaseAnalyzer") -> Type:
        """
        Create a placeholder class that can be used when the actual module is not available.
        
        Args:
            class_name: Name of the class to create
            base_class_name: Name of the base class to inherit from
        
        Returns:
            A placeholder class
        """
        # Define the placeholder class
        class_dict = {
            "__init__": lambda self, ov_core=None, device_name="CPU", output_dir=".", **kwargs: 
                        PlaceholderFactory._init_placeholder(self, class_name, ov_core, device_name, output_dir, **kwargs),
                        
            "analyze": lambda self, file_path, context=None, **kwargs:
                      PlaceholderFactory._analyze_placeholder(self, file_path, context, **kwargs),
                      
            "analyze_dump": lambda self, dump_path, profile=None, context=None, **kwargs:
                           PlaceholderFactory._analyze_dump_placeholder(self, dump_path, profile, context, **kwargs),
                           
            "__placeholder__": True,  # Flag to identify placeholder classes
        }
        
        # Create and return the class
        return type(f"Placeholder_{class_name}", (), class_dict)
    
    @staticmethod
    def _init_placeholder(self, class_name, ov_core, device_name, output_dir, **kwargs):
        """Placeholder initialization"""
        self.class_name = class_name
        self.ov_core = ov_core
        self.device_name = device_name
        self.output_dir = output_dir
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Store all additional kwargs as attributes
        for key, value in kwargs.items():
            setattr(self, key, value)
        
        print(f"Warning: Using placeholder for {class_name}. Actual module not loaded.")
    
    @staticmethod
    def _analyze_placeholder(self, file_path, context=None, **kwargs):
        """Placeholder analyze method"""
        print(f"Placeholder {self.class_name} analyzing file: {os.path.basename(file_path)}")
        
        # Return a basic result
        result = {
            "status": "placeholder_completed",
            "module": self.class_name,
            "file_analyzed": os.path.basename(file_path),
            "placeholder_warning": f"This is a placeholder result. The actual {self.class_name} module was not available."
        }
        
        return result
    
    @staticmethod
    def _analyze_dump_placeholder(self, dump_path, profile=None, context=None, **kwargs):
        """Placeholder analyze_dump method (for memory forensics)"""
        print(f"Placeholder {self.class_name} analyzing memory dump: {os.path.basename(dump_path)}")
        
        # Return a basic result
        result = {
            "status": "placeholder_completed",
            "module": self.class_name,
            "dump_analyzed": os.path.basename(dump_path),
            "placeholder_warning": f"This is a placeholder result. The actual {self.class_name} module was not available."
        }
        
        return result


class ModuleLoader:
    """
    Handles the dynamic loading of analysis modules and instantiation of analyzer classes.
    Provides fallback to placeholder classes when needed.
    """
    
    def __init__(self, module_import_map: Dict[str, str], use_openvino: bool = True):
        """
        Initialize the module loader.
        
        Args:
            module_import_map: Mapping of class names to import paths
            use_openvino: Whether to use OpenVINO acceleration
        """
        self.module_import_map = module_import_map
        self.use_openvino = use_openvino and OPENVINO_AVAILABLE
        self.loaded_modules = {}
        self.loaded_classes = {}
        self.placeholder_factory = PlaceholderFactory()
    
    def load_module(self, import_path: str) -> Optional[ModuleType]:
        """
        Dynamically load a Python module by its import path.
        
        Args:
            import_path: Import path of the module (e.g., 'keyplug_extractor')
            
        Returns:
            Loaded module or None if loading failed
        """
        # If already loaded, return from cache
        if import_path in self.loaded_modules:
            return self.loaded_modules[import_path]
        
        # Split into module path and class name if needed
        if "." in import_path:
            module_path = import_path.split(".")[0]
        else:
            module_path = import_path
        
        try:
            # Attempt to import the module
            module = importlib.import_module(module_path)
            self.loaded_modules[import_path] = module
            return module
        
        except ImportError as e:
            print(f"Error importing module {module_path}: {e}")
            return None
    
    def get_class(self, class_name: str) -> Type:
        """
        Get a class by name, either by importing the real module or creating a placeholder.
        
        Args:
            class_name: Name of the class to get
            
        Returns:
            Class object (real or placeholder)
        """
        # If already loaded, return from cache
        if class_name in self.loaded_classes:
            return self.loaded_classes[class_name]
        
        # Get the import path from the mapping
        import_path = self.module_import_map.get(class_name)
        if not import_path:
            print(f"Warning: No import path found for {class_name}. Using placeholder.")
            placeholder_class = self.placeholder_factory.create_placeholder_class(class_name)
            self.loaded_classes[class_name] = placeholder_class
            return placeholder_class
        
        # Split into module path and class name
        module_path, class_name_in_module = self._split_import_path(import_path)
        
        # Try to load the module
        module = self.load_module(module_path)
        if not module:
            print(f"Warning: Failed to load module for {class_name}. Using placeholder.")
            placeholder_class = self.placeholder_factory.create_placeholder_class(class_name)
            self.loaded_classes[class_name] = placeholder_class
            return placeholder_class
        
        # Try to get the class from the module
        try:
            class_obj = getattr(module, class_name_in_module)
            self.loaded_classes[class_name] = class_obj
            return class_obj
        except AttributeError as e:
            print(f"Warning: Class {class_name_in_module} not found in module {module_path}. Using placeholder.")
            placeholder_class = self.placeholder_factory.create_placeholder_class(class_name)
            self.loaded_classes[class_name] = placeholder_class
            return placeholder_class
    
    def create_instance(self, class_name: str, output_dir: str, **kwargs) -> Any:
        """
        Create an instance of a class with appropriate initialization parameters.
        
        Args:
            class_name: Name of the class to instantiate
            output_dir: Output directory for the analyzer
            **kwargs: Additional keyword arguments to pass to the class constructor
            
        Returns:
            Instance of the class or a placeholder
        """
        # Get the class
        class_obj = self.get_class(class_name)
        
        # Prepare OpenVINO parameters if available and needed
        openvino_params = {}
        if self.use_openvino:
            openvino_params = {
                "ov_core": OV_CORE,
                "device_name": PREFERRED_DEVICE
            }
        
        # Create and return an instance
        try:
            instance = class_obj(**openvino_params, output_dir=output_dir, **kwargs)
            return instance
        except Exception as e:
            print(f"Error creating instance of {class_name}: {e}\n{traceback.format_exc()}")
            
            # Fall back to a placeholder
            placeholder_class = self.placeholder_factory.create_placeholder_class(class_name)
            return placeholder_class(**openvino_params, output_dir=output_dir, **kwargs)
    
    def _split_import_path(self, import_path: str) -> Tuple[str, str]:
        """
        Split an import path into module path and class name.
        
        Args:
            import_path: Import path (e.g., 'keyplug_extractor.KeyplugExtractor')
            
        Returns:
            Tuple of (module_path, class_name)
        """
        if "." in import_path:
            parts = import_path.split(".")
            return ".".join(parts[:-1]), parts[-1]
        else:
            # If no dot, assume the module and class have the same name
            return import_path, import_path


if __name__ == "__main__":
    # Simple test
    from keyplug_pipeline_config import get_module_import_map
    
    print("Testing ModuleLoader")
    loader = ModuleLoader(get_module_import_map())
    
    # Try to load a few modules
    test_classes = [
        "KeyplugExtractor",
        "MLMalwareAnalyzer",
        "NonExistentModule"
    ]
    
    for class_name in test_classes:
        print(f"\nTrying to load {class_name}:")
        class_obj = loader.get_class(class_name)
        print(f"  Class: {class_obj}")
        
        instance = loader.create_instance(class_name, "./test_output")
        print(f"  Instance: {instance}")
        print(f"  Is placeholder: {hasattr(instance, '__placeholder__')}")
