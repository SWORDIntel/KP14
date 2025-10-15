# KP14 Analyzer Migration Guide

## Overview

This guide provides step-by-step instructions for migrating existing analyzer modules to the new plugin architecture. Whether you're migrating an existing module or creating a new analyzer, this document will help you adopt the standardized plugin interface.

**Target Audience:**
- Developers migrating existing analyzers
- New plugin authors
- Code reviewers

**Prerequisites:**
- Python 3.11+
- Understanding of abstract base classes
- Familiarity with existing analyzer code

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Migration Checklist](#migration-checklist)
3. [Step-by-Step Migration](#step-by-step-migration)
4. [Common Migration Patterns](#common-migration-patterns)
5. [Testing Your Migration](#testing-your-migration)
6. [Troubleshooting](#troubleshooting)
7. [Examples](#examples)
8. [Best Practices](#best-practices)

---

## Quick Start

### 1. Copy Template

```bash
# Copy the analyzer template
cp templates/analyzer_template.py analyzers/my_new_analyzer.py
```

### 2. Implement Required Methods

```python
from base_analyzer import BaseAnalyzer, AnalyzerCapabilities

class MyAnalyzer(BaseAnalyzer):
    def get_capabilities(self):
        # Define what your analyzer can do
        return AnalyzerCapabilities(...)

    def analyze(self, file_data, metadata):
        # Perform your analysis
        return AnalysisResult(...)

    def get_priority(self):
        # Set execution order
        return 200
```

### 3. Register and Test

```python
# Automatic registration via discovery
registry = get_global_registry()
registry.discover_analyzers([Path("analyzers")])

# Test
analyzer = registry.get_analyzer("my_analyzer")
result = analyzer.analyze(test_data, {})
```

---

## Migration Checklist

Use this checklist when migrating an existing module:

### Pre-Migration
- [ ] Read existing module code
- [ ] Identify dependencies
- [ ] List all exported functions/classes
- [ ] Document expected inputs/outputs
- [ ] Collect test cases

### Implementation
- [ ] Create new analyzer class inheriting BaseAnalyzer
- [ ] Implement get_capabilities()
- [ ] Implement analyze()
- [ ] Implement get_priority()
- [ ] (Optional) Implement validate_input()
- [ ] (Optional) Implement cleanup()
- [ ] Declare dependencies in capabilities
- [ ] Add configuration support

### Testing
- [ ] Write unit tests
- [ ] Test with sample files
- [ ] Verify results match old module
- [ ] Performance benchmark
- [ ] Test error handling

### Integration
- [ ] Register with registry
- [ ] Test in pipeline
- [ ] Update documentation
- [ ] Add deprecation warning to old module

### Cleanup
- [ ] Code review
- [ ] Update imports across codebase
- [ ] Mark old module as deprecated
- [ ] Schedule old module removal

---

## Step-by-Step Migration

### Step 1: Analyze Existing Module

**Identify Core Functionality**

Look at the old module and answer:
- What file types does it process?
- What data does it extract?
- What are the inputs and outputs?
- What other modules does it depend on?

**Example: Old Module**
```python
# old_modules/crypto_analyzer.py

def decrypt_xor(data, key):
    """Decrypt XOR-encrypted data"""
    return bytes([b ^ key for b in data])

def analyze_crypto(file_path):
    """Analyze file for encryption"""
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try XOR keys
    for key in range(256):
        decrypted = decrypt_xor(data, key)
        if looks_valid(decrypted):
            return {
                "encrypted": True,
                "algorithm": "XOR",
                "key": key,
                "decrypted": decrypted
            }

    return {"encrypted": False}
```

### Step 2: Create New Analyzer Class

**File Structure**
```
analyzers/
├── __init__.py
├── crypto_analyzer.py  # New plugin
└── ...
```

**Basic Structure**
```python
# analyzers/crypto_analyzer.py

from base_analyzer import (
    BaseAnalyzer,
    AnalyzerCapabilities,
    AnalyzerCategory,
    AnalysisPhase,
    FileType,
    AnalysisResult
)
from typing import Dict, Any
import time

class CryptoAnalyzer(BaseAnalyzer):
    """
    Analyzes files for encryption and performs decryption.

    Migrated from: old_modules/crypto_analyzer.py
    Version: 2.0.0
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        # Initialize any state
        self.max_attempts = self.get_config("max_attempts", 256)

    def get_capabilities(self) -> AnalyzerCapabilities:
        """Define analyzer capabilities"""
        return AnalyzerCapabilities(
            name="crypto_analyzer",
            version="2.0.0",
            category=AnalyzerCategory.CRYPTOGRAPHIC,
            supported_file_types={FileType.BINARY, FileType.PE},
            supported_phases={AnalysisPhase.DECRYPTION},
            can_decrypt=True,
            description="Cryptographic analysis and decryption",
            author="KP14 Team",
            dependencies=set()  # No dependencies
        )

    def analyze(self, file_data: bytes, metadata: Dict[str, Any]) -> AnalysisResult:
        """Perform cryptographic analysis"""
        start_time = time.time()

        result = AnalysisResult(
            analyzer_name="crypto_analyzer",
            analyzer_version="2.0.0",
            success=True
        )

        try:
            # Migrate old logic
            decryption_result = self._try_xor_decryption(file_data)

            if decryption_result:
                result.data = {
                    "encrypted": True,
                    "algorithm": "XOR",
                    "key": decryption_result["key"]
                }
                result.add_threat_indicator(
                    "encryption",
                    "XOR encryption detected",
                    confidence=0.9
                )
                result.confidence_score = 0.9
            else:
                result.data = {"encrypted": False}
                result.confidence_score = 0.1

        except Exception as e:
            result.success = False
            result.error_message = str(e)
            self.log_error(f"Analysis failed: {e}")

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    def get_priority(self) -> int:
        """Set execution priority"""
        return 300  # CRYPTOGRAPHIC category: 300-399

    def _try_xor_decryption(self, data: bytes) -> Dict[str, Any]:
        """Try XOR decryption (migrated from old module)"""
        for key in range(self.max_attempts):
            decrypted = bytes([b ^ key for b in data])
            if self._looks_valid(decrypted):
                return {"key": key, "decrypted": decrypted}
        return None

    def _looks_valid(self, data: bytes) -> bool:
        """Check if decrypted data looks valid"""
        # Simple heuristic: check for common file signatures
        signatures = [
            b'MZ',      # PE
            b'PK',      # ZIP
            b'\xFF\xD8', # JPEG
        ]
        return any(data.startswith(sig) for sig in signatures)
```

### Step 3: Handle Dependencies

**Old Way (Circular Import)**
```python
# OLD: Don't do this!
from other_module import other_function

def my_function():
    return other_function()  # Circular dependency risk
```

**New Way (Service Locator)**
```python
class MyAnalyzer(BaseAnalyzer):
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.service_locator = None  # Injected by pipeline

    def analyze(self, file_data, metadata):
        # Declare dependency in capabilities
        # Get dependency at runtime
        pe_analyzer = self.service_locator.get_analyzer("pe_analyzer")

        if pe_analyzer:
            pe_result = pe_analyzer.analyze(file_data, metadata)
            # Use pe_result.data
```

**Declare Dependency**
```python
def get_capabilities(self):
    return AnalyzerCapabilities(
        name="my_analyzer",
        version="1.0.0",
        dependencies={"pe_analyzer"}  # Explicit dependency
    )
```

### Step 4: Add Configuration Support

**Define Configuration**
```python
class MyAnalyzer(BaseAnalyzer):
    def __init__(self, config: Dict = None):
        super().__init__(config)

        # Load config with defaults
        self.enabled = self.get_config("enabled", True)
        self.threshold = self.get_config("threshold", 0.7)
        self.max_size = self.get_config("max_size_mb", 100) * 1024 * 1024
```

**Configuration File (settings.ini)**
```ini
[analyzer.my_analyzer]
enabled = true
threshold = 0.8
max_size_mb = 50
```

### Step 5: Implement Error Handling

**Robust Error Handling**
```python
def analyze(self, file_data, metadata):
    result = AnalysisResult(
        analyzer_name=self.get_capabilities().name,
        analyzer_version=self.get_capabilities().version,
        success=True
    )

    try:
        # Your analysis logic
        data = self._process(file_data)
        result.data = data

    except ValueError as e:
        # Validation errors
        result.success = False
        result.error_message = f"Invalid input: {e}"
        self.log_warning(f"Validation error: {e}")

    except FileNotFoundError as e:
        # File errors
        result.success = False
        result.error_message = f"File error: {e}"
        self.log_error(f"File not found: {e}")

    except Exception as e:
        # Catch-all for unexpected errors
        result.success = False
        result.error_message = f"Unexpected error: {e}"
        self.log_error(f"Unexpected error: {e}")

    return result
```

### Step 6: Add Logging

**Use Built-in Logging**
```python
class MyAnalyzer(BaseAnalyzer):
    def analyze(self, file_data, metadata):
        self.log_info("Starting analysis")

        try:
            self.log_debug(f"Processing {len(file_data)} bytes")

            result = self._do_analysis(file_data)

            self.log_info(f"Analysis complete: {result}")

        except Exception as e:
            self.log_error(f"Analysis failed: {e}")

        return result
```

### Step 7: Write Tests

**Unit Test Template**
```python
# tests/analyzers/test_my_analyzer.py

import pytest
from analyzers.my_analyzer import MyAnalyzer
from base_analyzer import FileType

class TestMyAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return MyAnalyzer({})

    def test_capabilities(self, analyzer):
        caps = analyzer.get_capabilities()
        assert caps.name == "my_analyzer"
        assert caps.version == "1.0.0"

    def test_analyze_valid_file(self, analyzer):
        data = b"valid test data"
        metadata = {"file_type": FileType.BINARY}
        result = analyzer.analyze(data, metadata)

        assert result.success
        assert "key" in result.data

    def test_analyze_invalid_file(self, analyzer):
        data = b""  # Empty
        metadata = {"file_type": FileType.BINARY}
        result = analyzer.analyze(data, metadata)

        assert not result.success
        assert result.error_message is not None

    def test_priority(self, analyzer):
        priority = analyzer.get_priority()
        assert 300 <= priority < 400  # CRYPTOGRAPHIC range
```

---

## Common Migration Patterns

### Pattern 1: Simple Function to Analyzer

**Before:**
```python
# old_module.py
def analyze_strings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    strings = extract_strings(data)
    return {"strings": strings}
```

**After:**
```python
# analyzers/string_analyzer.py
class StringAnalyzer(BaseAnalyzer):
    def analyze(self, file_data, metadata):
        result = AnalysisResult(
            analyzer_name="string_analyzer",
            analyzer_version="1.0.0",
            success=True
        )

        strings = self._extract_strings(file_data)
        result.data = {"strings": strings}

        return result

    def _extract_strings(self, data):
        # Original logic from old module
        return [s for s in data.split(b'\x00') if len(s) > 4]
```

### Pattern 2: Class to Analyzer

**Before:**
```python
# old_module.py
class OldAnalyzer:
    def __init__(self, config):
        self.config = config

    def process(self, file_path):
        # Analysis logic
        return results
```

**After:**
```python
# analyzers/new_analyzer.py
class NewAnalyzer(BaseAnalyzer):
    # BaseAnalyzer already has __init__ with config

    def analyze(self, file_data, metadata):
        # Migrate process() logic here
        return AnalysisResult(...)
```

### Pattern 3: Module with Multiple Functions

**Before:**
```python
# old_module.py
def extract_imports(pe):
    # ...

def extract_exports(pe):
    # ...

def extract_resources(pe):
    # ...

def analyze_pe(file_path):
    pe = pefile.PE(file_path)
    return {
        "imports": extract_imports(pe),
        "exports": extract_exports(pe),
        "resources": extract_resources(pe)
    }
```

**After:**
```python
# analyzers/pe_analyzer.py
class PEAnalyzer(BaseAnalyzer):
    def analyze(self, file_data, metadata):
        pe = pefile.PE(data=file_data)

        result = AnalysisResult(...)
        result.data = {
            "imports": self._extract_imports(pe),
            "exports": self._extract_exports(pe),
            "resources": self._extract_resources(pe)
        }
        return result

    def _extract_imports(self, pe):
        # Original logic

    def _extract_exports(self, pe):
        # Original logic

    def _extract_resources(self, pe):
        # Original logic
```

### Pattern 4: Hardware-Accelerated Analyzer

**Before:**
```python
# old_module.py
class MLAnalyzer:
    def __init__(self):
        try:
            from openvino.runtime import Core
            self.ov_core = Core()
            self.hw_available = True
        except:
            self.hw_available = False

    def analyze(self, data):
        if self.hw_available:
            return self._hw_analyze(data)
        else:
            return self._cpu_analyze(data)
```

**After:**
```python
# analyzers/ml_analyzer.py
from base_analyzer import HardwareAcceleratedAnalyzer

class MLAnalyzer(HardwareAcceleratedAnalyzer):
    # HardwareAcceleratedAnalyzer handles OpenVINO setup

    def analyze(self, file_data, metadata):
        if self.is_hardware_available():
            return self._hw_analyze(file_data)
        else:
            return self._cpu_analyze(file_data)
```

### Pattern 5: Consolidating Multiple Modules

**Before (3 separate modules):**
```python
# keyplug_extractor.py
def extract_payload(odg_path):
    # ...

# keyplug_decompiler.py
def decompile_payload(payload):
    # ...

# keyplug_peb_detector.py
def detect_peb(binary):
    # ...
```

**After (1 consolidated module):**
```python
# analyzers/keyplug_analyzer.py
class KeyPlugAnalyzer(BaseAnalyzer):
    def __init__(self, config=None):
        super().__init__(config)
        # Sub-components
        self.extractor = PayloadExtractor()
        self.decompiler = PayloadDecompiler()
        self.peb_detector = PEBDetector()

    def analyze(self, file_data, metadata):
        result = AnalysisResult(...)

        # Use sub-components
        if metadata["file_type"] == FileType.ODG:
            payloads = self.extractor.extract(file_data)
            result.data["payloads"] = payloads

        if metadata["file_type"] == FileType.PE:
            peb_findings = self.peb_detector.detect(file_data)
            result.data["peb_traversal"] = peb_findings

        return result

# Sub-component classes (internal, not analyzers)
class PayloadExtractor:
    def extract(self, data):
        # Original keyplug_extractor logic
        pass

class PayloadDecompiler:
    def decompile(self, payload):
        # Original keyplug_decompiler logic
        pass
```

---

## Testing Your Migration

### Regression Testing

**Ensure equivalent results:**
```python
# tests/regression/test_crypto_migration.py

def test_crypto_analyzer_regression():
    # Old module
    from old_modules.crypto_analyzer import analyze_crypto as old_analyze

    # New module
    from analyzers.crypto_analyzer import CryptoAnalyzer
    new_analyzer = CryptoAnalyzer({})

    # Test sample
    with open("samples/encrypted.bin", "rb") as f:
        test_data = f.read()

    # Compare results
    old_result = old_analyze("samples/encrypted.bin")
    new_result = new_analyzer.analyze(test_data, {"file_type": FileType.BINARY})

    # Verify equivalence
    assert old_result["encrypted"] == (new_result.data.get("encrypted", False))
    if old_result["encrypted"]:
        assert old_result["algorithm"] == new_result.data["algorithm"]
        assert old_result["key"] == new_result.data["key"]
```

### Performance Testing

**Benchmark before/after:**
```python
# tests/performance/test_migration_performance.py
import time

def test_performance_not_degraded():
    # Setup
    new_analyzer = CryptoAnalyzer({})
    test_data = b"x" * (1024 * 1024)  # 1MB

    # Benchmark
    start = time.time()
    for _ in range(100):
        result = new_analyzer.analyze(test_data, {})
    duration = time.time() - start

    # Should process at least 100 MB/s
    throughput_mb_s = (100 * len(test_data) / 1024 / 1024) / duration
    assert throughput_mb_s >= 100
```

---

## Troubleshooting

### Issue: Circular Import Error

**Symptom:**
```
ImportError: cannot import name 'X' from partially initialized module 'Y'
```

**Solution:**
```python
# Don't import at module level
# from other_analyzer import OtherAnalyzer  # BAD

# Use service locator instead
def analyze(self, file_data, metadata):
    other = self.service_locator.get_analyzer("other_analyzer")  # GOOD
```

### Issue: Analyzer Not Discovered

**Symptom:**
```python
analyzer = registry.get_analyzer("my_analyzer")
# Returns None
```

**Solution:**
```python
# 1. Check class inherits BaseAnalyzer
class MyAnalyzer(BaseAnalyzer):  # Must inherit

# 2. Check not abstract
# Don't use ABC directly
from abc import ABC
class MyAnalyzer(ABC):  # BAD

# 3. Check file in search path
registry.discover_analyzers([Path("analyzers")])  # Must include directory

# 4. Check no syntax errors
# Run: python -m py_compile analyzers/my_analyzer.py
```

### Issue: Wrong Execution Order

**Symptom:**
Analyzer runs before its dependencies.

**Solution:**
```python
# 1. Check priority is correct
def get_priority(self):
    return 500  # Should be higher than dependencies

# 2. Declare dependencies
def get_capabilities(self):
    return AnalyzerCapabilities(
        dependencies={"pe_analyzer"}  # Must declare
    )
```

### Issue: Configuration Not Loading

**Symptom:**
Config values are always default.

**Solution:**
```python
# 1. Check config section name matches analyzer name
# settings.ini:
[analyzer.my_analyzer]  # Must match capabilities.name
enabled = true

# 2. Use get_config() not direct access
self.threshold = self.get_config("threshold", 0.7)  # GOOD
# self.threshold = self.config["threshold"]  # BAD (KeyError if missing)
```

---

## Examples

### Example 1: Minimal Migration

**Old Module:**
```python
# old_modules/hash_analyzer.py
import hashlib

def calculate_hashes(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }
```

**New Analyzer:**
```python
# analyzers/hash_analyzer.py
import hashlib
from base_analyzer import *

class HashAnalyzer(BaseAnalyzer):
    def get_capabilities(self):
        return AnalyzerCapabilities(
            name="hash_analyzer",
            version="1.0.0",
            category=AnalyzerCategory.FORMAT,
            supported_file_types=set(),  # All types
            supported_phases={AnalysisPhase.PRE_SCAN}
        )

    def analyze(self, file_data, metadata):
        result = AnalysisResult(
            analyzer_name="hash_analyzer",
            analyzer_version="1.0.0",
            success=True
        )

        result.data = {
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": hashlib.sha256(file_data).hexdigest()
        }

        return result

    def get_priority(self):
        return 10  # Very early
```

### Example 2: Complex Migration

See `analyzers/keyplug_analyzer.py` in the codebase for a complete example of consolidating 7 modules.

---

## Best Practices

### 1. Keep Analyzers Focused

**DO:**
```python
class PEAnalyzer(BaseAnalyzer):
    """Analyzes PE file format only"""
```

**DON'T:**
```python
class PEAndJPEGAndEverythingAnalyzer(BaseAnalyzer):
    """Does too much"""
```

### 2. Use Descriptive Names

**DO:**
```python
def get_capabilities(self):
    return AnalyzerCapabilities(
        name="pe_import_analyzer",  # Clear
        description="Analyzes PE import tables"
    )
```

**DON'T:**
```python
def get_capabilities(self):
    return AnalyzerCapabilities(
        name="analyzer1",  # Not descriptive
        description="Stuff"
    )
```

### 3. Handle Errors Gracefully

**DO:**
```python
def analyze(self, file_data, metadata):
    result = AnalysisResult(...)

    try:
        # Analysis
        pass
    except SpecificError as e:
        result.success = False
        result.error_message = str(e)
        result.add_warning(f"Non-fatal error: {e}")
        # Continue with partial results

    return result
```

**DON'T:**
```python
def analyze(self, file_data, metadata):
    # Let exceptions propagate
    data = risky_operation()  # Might crash
    return AnalysisResult(...)
```

### 4. Document Dependencies

**DO:**
```python
def get_capabilities(self):
    return AnalyzerCapabilities(
        name="threat_scorer",
        dependencies={
            "pe_analyzer",      # Required
            "behavioral_analyzer"
        },
        optional_dependencies={
            "ml_classifier"  # Nice to have
        }
    )
```

### 5. Use Type Hints

**DO:**
```python
def analyze(self, file_data: bytes, metadata: Dict[str, Any]) -> AnalysisResult:
    result: AnalysisResult = AnalysisResult(...)
    return result
```

### 6. Test Thoroughly

**DO:**
```python
# tests/analyzers/test_my_analyzer.py
class TestMyAnalyzer:
    def test_valid_input(self):
        pass

    def test_invalid_input(self):
        pass

    def test_empty_input(self):
        pass

    def test_large_input(self):
        pass

    def test_error_handling(self):
        pass
```

---

## Checklist Summary

Quick reference for migration:

```
☐ Create new analyzer class
☐ Inherit from BaseAnalyzer
☐ Implement get_capabilities()
☐ Implement analyze()
☐ Implement get_priority()
☐ Add configuration support
☐ Handle errors gracefully
☐ Add logging
☐ Declare dependencies
☐ Write unit tests
☐ Write regression tests
☐ Benchmark performance
☐ Update documentation
☐ Code review
☐ Mark old module deprecated
```

---

## Getting Help

**Resources:**
- [PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md) - Architecture overview
- [MODULE_CONSOLIDATION_PLAN.md](MODULE_CONSOLIDATION_PLAN.md) - Migration plan
- `templates/analyzer_template.py` - Copy-paste template
- `examples/sample_analyzer.py` - Reference implementation

**Support:**
- GitHub Issues: Bug reports and questions
- Code Reviews: Submit PR for review
- Team Chat: Real-time help

---

## Conclusion

Migrating to the new plugin architecture improves code organization, eliminates circular dependencies, and provides a consistent interface. Follow this guide step-by-step, and don't hesitate to refer to examples in the codebase.

**Remember:**
- Start with simple analyzers first
- Test thoroughly
- Ask for help when needed
- Document your changes

Happy migrating!
