# KP14 Comprehensive Testing Strategy

**Version:** 2.0
**Date:** 2025-10-02
**Target Coverage:** 80%+
**Current Coverage:** ~15%

## Executive Summary

This document defines the comprehensive testing strategy for the KP14 platform. The project currently has 24 existing test files (161 Python source files, ~45,000 LOC) with significant import errors and outdated dependencies preventing execution. This strategy aims to achieve 80%+ code coverage through systematic test development, infrastructure modernization, and quality automation.

---

## 1. Current State Assessment

### 1.1 Existing Test Infrastructure

**Test Inventory (24 files total):**

**Tests Directory (`tests/`):**
- `tests/security/` (6 files)
  - `test_input_validation.py` - BROKEN (import errors)
  - `test_path_validation.py` - BROKEN (import errors)
  - `test_command_injection.py` - BROKEN (import errors)
  - `test_error_handling.py` - BROKEN (import errors)
  - `run_security_tests.py` - Test runner
  - `__init__.py`

**Stego-Analyzer Tests (`stego-analyzer/tests/`):**
- `static_analyzer/` (3 files)
  - `test_pe_analyzer.py` - EXISTS
  - `test_code_analyzer.py` - EXISTS
  - `test_obfuscation_analyzer.py` - EXISTS

- `extraction_analyzer/` (3 files)
  - `test_crypto_analyzer.py` - WORKING (15 tests)
  - `test_polyglot_analyzer.py` - WORKING (6 tests)
  - `test_steganography_analyzer.py` - WORKING (9 tests)

- `analysis/` (1 file)
  - `test_static_analyzer.py` - EXISTS

- `utils/` (3 files)
  - `test_compiler_specific_recovery.py` - EXISTS
  - `test_malware_pattern_learner.py` - EXISTS
  - `test_type_propagation.py` - EXISTS

- `tools/` (1 file)
  - `test_import_resolver.py` - EXISTS

- Root level (4 files)
  - `test_pipeline.py` - BROKEN (import errors, needs stego_test.py)
  - `test_f5.py` - BROKEN (missing jpegio)
  - `test_jsteg.py` - EXISTS
  - `minimal_jpegio_test.py` - EXISTS

**Test Fixtures:**
- `tests/core_engine/conftest.py` - PARTIAL (good fixtures, needs expansion)
- `stego-analyzer/tests/fixtures/` - EMPTY (needs test samples)
  - `crypto/` - EMPTY
  - `images/` - EMPTY
  - `pe/` - EMPTY
  - `polyglot/` - EMPTY

### 1.2 Critical Issues

**Import Errors:**
1. `core_engine.security_utils` module missing for security tests
2. `jpegio` module missing (required by F5/JSTEG tests)
3. Path resolution issues in test files
4. Missing dependencies in requirements.txt

**Infrastructure Gaps:**
1. No pytest configuration in pyproject.toml
2. No CI/CD test automation
3. No coverage reporting
4. Missing test data samples
5. No integration test suite
6. No performance benchmarking tests

**Test Quality Issues:**
1. Outdated import patterns (sys.path manipulation)
2. Hard-coded paths instead of fixtures
3. No test isolation (shared state risks)
4. Minimal error case coverage
5. No mocking strategy for external dependencies

### 1.3 Source Code Coverage Analysis

**Module Inventory (161 Python files):**

**Core Engine (`core_engine/`):** 8 files
- `configuration_manager.py` - NO TESTS
- `error_handler.py` - NO TESTS
- `file_validator.py` - NO TESTS
- `logging_config.py` - NO TESTS
- `pipeline_manager.py` - NO TESTS
- `secure_subprocess.py` - NO TESTS
- `security_utils.py` - BROKEN TESTS (4 files)
- `SECURITY_README.md` (doc)

**Stego Analyzer Analysis (`stego-analyzer/analysis/`):** 24 files
- `keyplug_advanced_analysis.py` - NO TESTS
- `keyplug_accelerated_multilayer.py` - NO TESTS
- `keyplug_extractor.py` - NO TESTS
- `keyplug_decompiler.py` - NO TESTS
- `ml_malware_analyzer.py` - NO TESTS
- `behavioral_analyzer.py` - NO TESTS
- `code_intent_classifier.py` - NO TESTS
- +17 more analysis modules - NO TESTS

**Intelligence Module (`intelligence/`):** 13+ files
- `intelligence_orchestrator.py` - NO TESTS
- `extractors/c2_extractor.py` - NO TESTS
- `scorers/threat_scorer.py` - NO TESTS
- `generators/yara_generator.py` - NO TESTS
- `generators/sigma_generator.py` - NO TESTS
- `exporters/stix_exporter.py` - NO TESTS
- `exporters/misp_exporter.py` - NO TESTS
- +6 more intelligence modules - NO TESTS

**Exporters (`exporters/`):** 6 files
- `json_exporter.py` - NO TESTS
- `csv_exporter.py` - NO TESTS
- `stix_exporter.py` - NO TESTS
- `misp_exporter.py` - NO TESTS
- `rule_exporter.py` - NO TESTS
- `__init__.py`

**Utilities & Tools:** 50+ files
- Hash detector (5 files) - NO TESTS
- String decoder (3 files) - NO TESTS
- Multi-layer decrypt (2 files) - NO TESTS
- Compiler detection (3 files) - PARTIAL TESTS
- Pattern learner - PARTIAL TESTS

---

## 2. Testing Strategy & Architecture

### 2.1 Test Pyramid

```
                    /\
                   /  \
                  / E2E\          5% - End-to-End (10-15 tests)
                 /______\
                /        \
               /Integration\      15% - Integration (50-75 tests)
              /____________\
             /              \
            /  Unit Tests    \    80% - Unit (300-400 tests)
           /__________________\
```

**Target Distribution:**
- **Unit Tests:** 80% (300-400 tests) - Individual functions/classes
- **Integration Tests:** 15% (50-75 tests) - Module interactions
- **End-to-End Tests:** 5% (10-15 tests) - Full pipeline scenarios

### 2.2 Coverage Targets by Module

| Module | Target Coverage | Priority | Estimated Tests |
|--------|----------------|----------|----------------|
| `core_engine/` | **85%** | CRITICAL | 80-100 |
| `stego-analyzer/analysis/` | **75%** | HIGH | 120-150 |
| `intelligence/` | **80%** | HIGH | 60-80 |
| `exporters/` | **70%** | MEDIUM | 30-40 |
| `stego-analyzer/utils/` | **70%** | MEDIUM | 50-70 |
| `stego-analyzer/core/` | **80%** | HIGH | 40-50 |
| Integration tests | N/A | HIGH | 50-75 |
| E2E tests | N/A | MEDIUM | 10-15 |

**Total Estimated Tests:** 440-580 tests

### 2.3 Test Categories

#### 2.3.1 Unit Tests

**Purpose:** Validate individual functions/classes in isolation

**Scope:**
- Pure functions (crypto algorithms, parsing, encoding)
- Data transformations
- Validation logic
- Utility functions
- Error handling paths

**Approach:**
- Use mocks for external dependencies
- Fast execution (<1ms per test)
- High code coverage (90%+ for utilities)
- Property-based testing for algorithms

**Example Modules:**
```python
# tests/unit/core_engine/test_file_validator.py
# tests/unit/core_engine/test_error_handler.py
# tests/unit/intelligence/test_c2_extractor.py
# tests/unit/exporters/test_json_exporter.py
```

#### 2.3.2 Integration Tests

**Purpose:** Validate interactions between modules

**Scope:**
- Pipeline stage interactions
- Analyzer coordination
- Database operations
- File I/O operations
- Report generation

**Approach:**
- Use test doubles for expensive operations
- Realistic test data
- Medium execution time (<100ms per test)
- Focus on interface contracts

**Example Modules:**
```python
# tests/integration/test_extraction_pipeline.py
# tests/integration/test_intelligence_workflow.py
# tests/integration/test_export_chain.py
```

#### 2.3.3 End-to-End Tests

**Purpose:** Validate complete workflows

**Scope:**
- Full analysis pipeline (sample → report)
- Batch processing
- API endpoints
- CLI commands
- Error recovery

**Approach:**
- Real file samples (small, synthetic)
- Complete configuration
- Slower execution (<5s per test)
- Focus on user scenarios

**Example Modules:**
```python
# tests/e2e/test_full_pipeline.py
# tests/e2e/test_batch_analysis.py
# tests/e2e/test_cli_interface.py
```

#### 2.3.4 Performance Tests

**Purpose:** Ensure acceptable performance characteristics

**Scope:**
- Benchmark critical paths
- Memory usage validation
- Hardware acceleration validation
- Scalability testing

**Approach:**
- Statistical benchmarking
- Regression detection
- Resource monitoring
- Hardware-specific tests

**Example Modules:**
```python
# tests/performance/test_crypto_benchmarks.py
# tests/performance/test_memory_limits.py
# tests/performance/test_npu_acceleration.py
```

#### 2.3.5 Security Tests

**Purpose:** Validate security controls

**Scope:**
- Input validation
- Path traversal prevention
- Command injection prevention
- Resource exhaustion (DoS)
- Cryptographic correctness

**Approach:**
- Fuzzing inputs
- Attack vectors
- Boundary conditions
- Security regression tests

**Example Modules:**
```python
# tests/security/test_input_validation.py (FIX EXISTING)
# tests/security/test_path_validation.py (FIX EXISTING)
# tests/security/test_command_injection.py (FIX EXISTING)
# tests/security/test_crypto_security.py (NEW)
```

#### 2.3.6 Regression Tests

**Purpose:** Prevent known bugs from reoccurring

**Scope:**
- Bug fix validation
- Known failure cases
- Edge case handling

**Approach:**
- Test per bug fix
- Minimal reproduction case
- Clear bug reference

**Example:**
```python
# tests/regression/test_bug_001_xor_key_overflow.py
# tests/regression/test_bug_002_jpeg_eof_crash.py
```

---

## 3. Test Infrastructure Design

### 3.1 Directory Structure

```
kp14/
├── tests/
│   ├── conftest.py                    # Root fixtures (project-wide)
│   ├── pytest.ini                     # Pytest configuration
│   ├── __init__.py
│   │
│   ├── unit/                          # Unit tests (80%)
│   │   ├── conftest.py               # Unit test fixtures
│   │   ├── core_engine/
│   │   │   ├── conftest.py
│   │   │   ├── test_configuration_manager.py
│   │   │   ├── test_error_handler.py
│   │   │   ├── test_file_validator.py
│   │   │   ├── test_logging_config.py
│   │   │   ├── test_pipeline_manager.py
│   │   │   ├── test_secure_subprocess.py
│   │   │   └── test_security_utils.py
│   │   │
│   │   ├── stego_analyzer/
│   │   │   ├── conftest.py
│   │   │   ├── analysis/
│   │   │   │   ├── test_keyplug_extractor.py
│   │   │   │   ├── test_ml_malware_analyzer.py
│   │   │   │   ├── test_behavioral_analyzer.py
│   │   │   │   └── ...
│   │   │   ├── extraction/
│   │   │   │   ├── test_crypto_analyzer.py (MIGRATE)
│   │   │   │   ├── test_polyglot_analyzer.py (MIGRATE)
│   │   │   │   └── test_steganography_analyzer.py (MIGRATE)
│   │   │   └── utils/
│   │   │       ├── test_hash_detector.py
│   │   │       ├── test_string_decoder.py
│   │   │       └── ...
│   │   │
│   │   ├── intelligence/
│   │   │   ├── conftest.py
│   │   │   ├── extractors/
│   │   │   │   └── test_c2_extractor.py
│   │   │   ├── scorers/
│   │   │   │   └── test_threat_scorer.py
│   │   │   ├── generators/
│   │   │   │   ├── test_yara_generator.py
│   │   │   │   ├── test_sigma_generator.py
│   │   │   │   └── test_network_rules.py
│   │   │   └── exporters/
│   │   │       ├── test_stix_exporter.py
│   │   │       └── test_misp_exporter.py
│   │   │
│   │   └── exporters/
│   │       ├── test_json_exporter.py
│   │       ├── test_csv_exporter.py
│   │       ├── test_stix_exporter.py
│   │       ├── test_misp_exporter.py
│   │       └── test_rule_exporter.py
│   │
│   ├── integration/                   # Integration tests (15%)
│   │   ├── conftest.py
│   │   ├── test_extraction_pipeline.py
│   │   ├── test_decryption_chain.py
│   │   ├── test_static_analysis_flow.py
│   │   ├── test_intelligence_workflow.py
│   │   ├── test_export_chain.py
│   │   ├── test_recursive_analysis.py
│   │   └── test_hardware_acceleration.py
│   │
│   ├── e2e/                           # End-to-end tests (5%)
│   │   ├── conftest.py
│   │   ├── test_full_pipeline.py
│   │   ├── test_batch_analysis.py
│   │   ├── test_cli_interface.py
│   │   ├── test_tui_interface.py
│   │   ├── test_api_server.py
│   │   └── test_docker_deployment.py
│   │
│   ├── performance/                   # Performance benchmarks
│   │   ├── conftest.py
│   │   ├── test_crypto_benchmarks.py
│   │   ├── test_image_analysis_benchmarks.py
│   │   ├── test_memory_limits.py
│   │   ├── test_npu_acceleration.py
│   │   └── test_batch_scalability.py
│   │
│   ├── security/                      # Security tests
│   │   ├── conftest.py
│   │   ├── test_input_validation.py (FIX)
│   │   ├── test_path_validation.py (FIX)
│   │   ├── test_command_injection.py (FIX)
│   │   ├── test_error_handling.py (FIX)
│   │   ├── test_crypto_security.py (NEW)
│   │   ├── test_dos_prevention.py (NEW)
│   │   └── test_data_sanitization.py (NEW)
│   │
│   ├── regression/                    # Regression tests
│   │   └── test_known_bugs.py
│   │
│   └── fixtures/                      # Test data repository
│       ├── README.md                  # Test data documentation
│       ├── samples/
│       │   ├── pe/
│       │   │   ├── simple_pe32.exe
│       │   │   ├── simple_pe64.exe
│       │   │   ├── packed_upx.exe
│       │   │   ├── corrupted.exe
│       │   │   └── large_sample.exe
│       │   │
│       │   ├── images/
│       │   │   ├── clean.jpg
│       │   │   ├── clean.png
│       │   │   ├── lsb_embedded.png
│       │   │   ├── jpeg_appended.jpg
│       │   │   └── corrupt.jpg
│       │   │
│       │   ├── polyglot/
│       │   │   ├── jpeg_pe.jpg
│       │   │   ├── zip_pe.zip
│       │   │   ├── pdf_pe.pdf
│       │   │   └── nested_archive.zip
│       │   │
│       │   ├── encrypted/
│       │   │   ├── xor_encrypted.bin
│       │   │   ├── aes_cbc.bin
│       │   │   ├── rc4_encrypted.bin
│       │   │   └── multi_layer.bin
│       │   │
│       │   └── malicious/
│       │       ├── keyplug_sample.exe (SYNTHETIC)
│       │       ├── packed_malware.exe (SYNTHETIC)
│       │       └── dropper.dll (SYNTHETIC)
│       │
│       ├── configs/
│       │   ├── minimal.ini
│       │   ├── full_featured.ini
│       │   ├── hardware_accel.ini
│       │   └── invalid.ini
│       │
│       └── expected_outputs/
│           ├── simple_pe32_report.json
│           ├── lsb_embedded_report.json
│           └── ...
│
└── pyproject.toml                     # Add [tool.pytest.ini_options]
```

### 3.2 Pytest Configuration

**Add to `pyproject.toml`:**

```toml
[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]

# Addopts for all test runs
addopts = [
    "-v",                              # Verbose output
    "--strict-markers",                # Ensure markers are registered
    "--tb=short",                      # Shorter tracebacks
    "--cov=core_engine",              # Coverage for core_engine
    "--cov=stego-analyzer",           # Coverage for stego-analyzer
    "--cov=intelligence",             # Coverage for intelligence
    "--cov=exporters",                # Coverage for exporters
    "--cov-report=term-missing",      # Show missing lines
    "--cov-report=html:htmlcov",      # HTML coverage report
    "--cov-report=json:.coverage.json", # JSON for CI/CD
    "--cov-fail-under=80",            # Fail if coverage < 80%
    "-p no:warnings",                 # Suppress warnings
]

# Markers for test categorization
markers = [
    "unit: Unit tests (fast, isolated)",
    "integration: Integration tests (moderate speed)",
    "e2e: End-to-end tests (slow, full system)",
    "performance: Performance benchmarks",
    "security: Security tests",
    "regression: Regression tests for known bugs",
    "slow: Tests that take >1s to run",
    "requires_gpu: Tests requiring GPU hardware",
    "requires_npu: Tests requiring NPU hardware",
    "requires_samples: Tests requiring real malware samples",
    "network: Tests requiring network access",
]

# Ignore paths
norecursedirs = [
    ".*",
    "keyplug_venv",
    "kp14_qa_venv",
    "archive",
    "build",
    "dist",
    "*.egg",
]

# Timeout for tests (prevent hangs)
timeout = 300  # 5 minutes max per test

# Coverage configuration
[tool.coverage.run]
source = ["core_engine", "stego-analyzer", "intelligence", "exporters"]
omit = [
    "*/tests/*",
    "*/keyplug_venv/*",
    "*/kp14_qa_venv/*",
    "*/archive/*",
    "*/__pycache__/*",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
    "@abstract",
]
```

### 3.3 Root Conftest.py

**Create `tests/conftest.py`:**

```python
"""
Root conftest.py for KP14 test suite.

Provides project-wide fixtures, configuration, and test utilities.
"""

import pytest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test data paths
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
SAMPLES_DIR = FIXTURES_DIR / "samples"
CONFIGS_DIR = FIXTURES_DIR / "configs"
EXPECTED_OUTPUTS_DIR = FIXTURES_DIR / "expected_outputs"


# ============================================================================
# Session-scoped fixtures (shared across all tests)
# ============================================================================

@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    """Return the test samples directory."""
    return SAMPLES_DIR


# ============================================================================
# Function-scoped fixtures (isolated per test)
# ============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test isolation.
    Automatically cleaned up after test completion.
    """
    temp_path = Path(tempfile.mkdtemp(prefix="kp14_test_"))
    yield temp_path
    # Cleanup
    if temp_path.exists():
        shutil.rmtree(temp_path)


@pytest.fixture
def test_output_dir(temp_dir: Path) -> Path:
    """Create a temporary output directory for test results."""
    output_dir = temp_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# ============================================================================
# Configuration fixtures
# ============================================================================

@pytest.fixture
def minimal_config(temp_dir: Path) -> Path:
    """
    Create a minimal test configuration file.
    """
    config_path = temp_dir / "test_settings.ini"
    config_content = f"""
[general]
project_root = {temp_dir}
output_dir = {temp_dir / 'output'}
log_level = DEBUG
verbose = True

[paths]
log_dir_name = logs
extracted_dir_name = extracted
graphs_dir_name = graphs
models_dir_name = models

[pe_analyzer]
enabled = True
max_file_size_mb = 50

[code_analyzer]
enabled = True
use_radare2 = False

[obfuscation_analyzer]
enabled = True
"""
    config_path.write_text(config_content)
    return config_path


# ============================================================================
# Hardware detection fixtures
# ============================================================================

@pytest.fixture(scope="session")
def has_gpu() -> bool:
    """Detect if GPU is available."""
    try:
        import openvino as ov
        core = ov.Core()
        return "GPU" in core.available_devices
    except:
        return False


@pytest.fixture(scope="session")
def has_npu() -> bool:
    """Detect if NPU is available."""
    try:
        import openvino as ov
        core = ov.Core()
        return "NPU" in core.available_devices
    except:
        return False


# ============================================================================
# Test markers
# ============================================================================

def pytest_configure(config):
    """
    Configure pytest with custom markers and settings.
    """
    config.addinivalue_line(
        "markers", "unit: Unit tests (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests (moderate speed)"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests (slow, full system)"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers automatically.
    """
    for item in items:
        # Auto-mark tests based on path
        if "unit" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        elif "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "e2e" in item.nodeid:
            item.add_marker(pytest.mark.e2e)
        elif "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "security" in item.nodeid:
            item.add_marker(pytest.mark.security)


# ============================================================================
# Test utilities
# ============================================================================

@pytest.fixture
def assert_json_structure():
    """
    Fixture providing a JSON structure validation function.
    """
    def _assert_structure(data: Dict[str, Any], expected_keys: list):
        """Assert that a dictionary has the expected keys."""
        missing = set(expected_keys) - set(data.keys())
        assert not missing, f"Missing expected keys: {missing}"
    return _assert_structure
```

### 3.4 Module-Specific Conftest Files

**`tests/unit/core_engine/conftest.py`** (MIGRATE EXISTING)

```python
"""
Fixtures for core_engine unit tests.
"""

import pytest
from unittest.mock import Mock, MagicMock
import tempfile
import os
from pathlib import Path


@pytest.fixture
def sample_pe_bytes():
    """Generate minimal valid PE file bytes."""
    pe_data = bytearray(1024)
    pe_data[0:2] = b'MZ'
    pe_data[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    pe_data[0x80:0x84] = b'PE\x00\x00'
    pe_data[0x84:0x86] = (0x014c).to_bytes(2, 'little')
    pe_data[0x86:0x88] = (1).to_bytes(2, 'little')
    pe_data[0x98:0x9a] = (0x010b).to_bytes(2, 'little')
    return bytes(pe_data)


@pytest.fixture
def sample_pe_file(temp_dir, sample_pe_bytes):
    """Create a temporary PE file."""
    pe_path = temp_dir / "test_sample.exe"
    pe_path.write_bytes(sample_pe_bytes)
    return pe_path


@pytest.fixture
def mock_config_manager():
    """Create a mock ConfigurationManager with default values."""
    mock = Mock()
    # (Same as existing in tests/core_engine/conftest.py)
    return mock
```

---

## 4. Test Data Management

### 4.1 Test Sample Repository

**Location:** `tests/fixtures/samples/`

**Structure:**
```
samples/
├── README.md               # Provenance and checksums
├── pe/
│   ├── simple_pe32.exe     # Minimal PE32 (512 bytes)
│   ├── simple_pe64.exe     # Minimal PE64 (512 bytes)
│   ├── packed_upx.exe      # UPX packed sample (2 KB)
│   ├── corrupted.exe       # Invalid PE (broken headers)
│   └── large_sample.exe    # Large PE (10 MB, truncated)
│
├── images/
│   ├── clean_100x100.jpg   # Clean JPEG (5 KB)
│   ├── clean_100x100.png   # Clean PNG (5 KB)
│   ├── lsb_embedded.png    # PNG with LSB data (10 KB)
│   ├── jpeg_appended.jpg   # JPEG with appended data (8 KB)
│   └── corrupt.jpg         # Corrupted JPEG
│
├── polyglot/
│   ├── jpeg_pe.jpg         # JPEG/PE polyglot (10 KB)
│   ├── zip_pe.zip          # ZIP with embedded PE (15 KB)
│   ├── pdf_pe.pdf          # PDF/PE polyglot (20 KB)
│   └── nested_archive.zip  # ZIP containing ZIP with PE (12 KB)
│
├── encrypted/
│   ├── xor_encrypted.bin   # XOR (key=0xAB, 1 KB)
│   ├── aes_cbc.bin         # AES-128-CBC (2 KB)
│   ├── rc4_encrypted.bin   # RC4 (1 KB)
│   └── multi_layer.bin     # XOR → AES → RC4 (3 KB)
│
└── malicious/              # SYNTHETIC ONLY
    ├── keyplug_synthetic.exe    # Synthetic KeyPlug features
    ├── packed_synthetic.exe     # Synthetic packed malware
    └── dropper_synthetic.dll    # Synthetic dropper
```

### 4.2 Test Data Generation Scripts

**Create `tests/fixtures/generate_samples.py`:**

```python
"""
Generate synthetic test samples for KP14 testing.

This script creates safe, synthetic test files that mimic malware
characteristics without containing actual malicious code.
"""

import os
from pathlib import Path
import struct


def generate_simple_pe32(output_path: Path):
    """Generate a minimal valid PE32 executable."""
    pe_data = bytearray(1024)

    # DOS header
    pe_data[0:2] = b'MZ'
    pe_data[0x3c:0x40] = struct.pack('<I', 0x80)

    # PE signature
    pe_data[0x80:0x84] = b'PE\x00\x00'

    # COFF header
    pe_data[0x84:0x86] = struct.pack('<H', 0x014c)  # i386
    pe_data[0x86:0x88] = struct.pack('<H', 1)       # 1 section

    # Optional header
    pe_data[0x98:0x9a] = struct.pack('<H', 0x010b)  # PE32

    output_path.write_bytes(bytes(pe_data))
    print(f"Generated: {output_path}")


def generate_lsb_embedded_png(output_path: Path):
    """Generate PNG with LSB steganography."""
    # Minimal PNG structure with embedded data in LSB
    png_signature = b'\x89PNG\r\n\x1a\n'

    # IHDR chunk (100x100, 8-bit RGB)
    ihdr = b'IHDR' + struct.pack('>IIBBBBB', 100, 100, 8, 2, 0, 0, 0)
    ihdr_crc = 0  # Simplified CRC

    png_data = png_signature
    png_data += struct.pack('>I', 13) + ihdr + struct.pack('>I', ihdr_crc)

    # IDAT chunk with LSB data
    idat_data = os.urandom(500)  # Random pixel data with LSB embedding
    png_data += struct.pack('>I', len(idat_data)) + b'IDAT' + idat_data
    png_data += struct.pack('>I', 0)  # CRC

    # IEND chunk
    png_data += struct.pack('>I', 0) + b'IEND' + struct.pack('>I', 0)

    output_path.write_bytes(png_data)
    print(f"Generated: {output_path}")


def generate_xor_encrypted(output_path: Path, key: int = 0xAB):
    """Generate XOR-encrypted PE."""
    pe_bytes = generate_simple_pe32_bytes()
    encrypted = bytes([b ^ key for b in pe_bytes])
    output_path.write_bytes(encrypted)
    print(f"Generated: {output_path} (XOR key: {hex(key)})")


def main():
    """Generate all test samples."""
    samples_dir = Path(__file__).parent / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    # Generate PE samples
    (samples_dir / "pe").mkdir(exist_ok=True)
    generate_simple_pe32(samples_dir / "pe" / "simple_pe32.exe")

    # Generate image samples
    (samples_dir / "images").mkdir(exist_ok=True)
    generate_lsb_embedded_png(samples_dir / "images" / "lsb_embedded.png")

    # Generate encrypted samples
    (samples_dir / "encrypted").mkdir(exist_ok=True)
    generate_xor_encrypted(samples_dir / "encrypted" / "xor_encrypted.bin")

    print("\nAll test samples generated successfully!")
    print("Location: tests/fixtures/samples/")


if __name__ == "__main__":
    main()
```

### 4.3 Test Data Documentation

**Create `tests/fixtures/samples/README.md`:**

```markdown
# KP14 Test Samples

This directory contains synthetic test files for the KP14 test suite.

## Provenance

All samples in this directory are:
- **Synthetic:** Created by `generate_samples.py`
- **Safe:** Contain no malicious code
- **Deterministic:** Generated with fixed seeds for reproducibility

## Checksums

| File | MD5 | Size |
|------|-----|------|
| pe/simple_pe32.exe | abc123... | 1024 bytes |
| images/lsb_embedded.png | def456... | 10240 bytes |

## Usage in Tests

```python
from pathlib import Path

@pytest.fixture
def simple_pe_sample(samples_dir):
    return samples_dir / "pe" / "simple_pe32.exe"

def test_pe_analysis(simple_pe_sample):
    result = analyze_pe(simple_pe_sample)
    assert result['is_valid']
```

## Regeneration

To regenerate all samples:
```bash
python tests/fixtures/generate_samples.py
```
```

---

## 5. Test Implementation Plan

### 5.1 Phase 1: Foundation (Weeks 1-2)

**Priority:** CRITICAL

**Goals:**
1. Fix existing test infrastructure
2. Implement pytest configuration
3. Create test data repository
4. Migrate existing tests to new structure

**Tasks:**

**Week 1:**
- [ ] Fix import errors in security tests (create missing `security_utils.py`)
- [ ] Update `requirements.txt` with test dependencies (pytest, pytest-cov, pytest-timeout)
- [ ] Add pytest configuration to `pyproject.toml`
- [ ] Create root `tests/conftest.py`
- [ ] Generate test samples (`generate_samples.py`)
- [ ] Document test data in `tests/fixtures/samples/README.md`

**Week 2:**
- [ ] Migrate `tests/security/` tests to use new fixtures
- [ ] Migrate `stego-analyzer/tests/` to `tests/unit/stego_analyzer/`
- [ ] Create module-specific conftest files
- [ ] Set up coverage reporting
- [ ] Verify all existing tests pass
- [ ] Create test execution scripts

**Deliverables:**
- Working test infrastructure
- All existing tests passing
- Coverage baseline report

### 5.2 Phase 2: Core Engine Tests (Weeks 3-4)

**Priority:** CRITICAL

**Coverage Target:** 85% for core_engine

**Modules to Test:**
1. `configuration_manager.py` (15 tests)
2. `error_handler.py` (20 tests)
3. `file_validator.py` (15 tests)
4. `logging_config.py` (10 tests)
5. `pipeline_manager.py` (25 tests)
6. `secure_subprocess.py` (15 tests)
7. `security_utils.py` (20 tests) [FIX EXISTING]

**Test Categories:**
- Unit tests for each module
- Integration tests for pipeline manager
- Error handling tests
- Configuration validation tests

**Example Test File:** `tests/unit/core_engine/test_configuration_manager.py`

```python
"""
Unit tests for ConfigurationManager.

Tests configuration loading, validation, and error handling.
"""

import pytest
from pathlib import Path
from core_engine.configuration_manager import ConfigurationManager
from core_engine.error_handler import ConfigurationError


@pytest.mark.unit
class TestConfigurationManager:
    """Test suite for ConfigurationManager."""

    def test_load_valid_config(self, minimal_config):
        """Test loading a valid configuration file."""
        config = ConfigurationManager(minimal_config)
        assert config.get('general', 'log_level') == 'DEBUG'
        assert config.getboolean('general', 'verbose') is True

    def test_load_missing_config(self, temp_dir):
        """Test handling of missing configuration file."""
        with pytest.raises(ConfigurationError, match="not found"):
            ConfigurationManager(temp_dir / "nonexistent.ini")

    def test_invalid_log_level(self, temp_dir):
        """Test validation of invalid log level."""
        invalid_config = temp_dir / "invalid.ini"
        invalid_config.write_text("[general]\nlog_level = INVALID")

        with pytest.raises(ConfigurationError, match="Invalid log level"):
            ConfigurationManager(invalid_config)

    # ... 12 more tests ...
```

**Deliverables:**
- 120 core_engine unit tests
- 85%+ coverage for core_engine
- Integration tests for pipeline manager

### 5.3 Phase 3: Analysis Modules (Weeks 5-7)

**Priority:** HIGH

**Coverage Target:** 75% for stego-analyzer/analysis

**Modules to Test:**
- `keyplug_extractor.py` (20 tests)
- `ml_malware_analyzer.py` (25 tests)
- `behavioral_analyzer.py` (20 tests)
- `code_intent_classifier.py` (15 tests)
- Hash detector utils (15 tests)
- String decoder utils (15 tests)
- +10 more analysis modules (70 tests)

**Test Categories:**
- Algorithm correctness
- Edge case handling
- Performance validation
- Error recovery

**Deliverables:**
- 180 analysis module tests
- 75%+ coverage for analysis modules
- Performance benchmarks

### 5.4 Phase 4: Intelligence & Exporters (Weeks 8-9)

**Priority:** HIGH

**Coverage Target:** 80% for intelligence, 70% for exporters

**Modules to Test:**

**Intelligence:**
- `c2_extractor.py` (15 tests)
- `threat_scorer.py` (15 tests)
- `yara_generator.py` (12 tests)
- `sigma_generator.py` (12 tests)
- `stix_exporter.py` (10 tests)
- `misp_exporter.py` (10 tests)

**Exporters:**
- `json_exporter.py` (8 tests)
- `csv_exporter.py` (8 tests)
- `stix_exporter.py` (8 tests)
- `misp_exporter.py` (8 tests)
- `rule_exporter.py` (8 tests)

**Deliverables:**
- 114 intelligence/exporter tests
- 80%+ coverage for intelligence
- 70%+ coverage for exporters
- Format validation tests

### 5.5 Phase 5: Integration & E2E (Weeks 10-11)

**Priority:** HIGH

**Test Types:**

**Integration Tests (50 tests):**
- Extraction pipeline integration
- Decryption chain integration
- Static analysis workflow
- Intelligence workflow
- Export chain integration
- Recursive analysis
- Hardware acceleration

**E2E Tests (15 tests):**
- Full pipeline scenarios
- Batch analysis
- CLI interface
- TUI interface
- API server
- Docker deployment

**Example E2E Test:**

```python
"""
End-to-end test for full analysis pipeline.
"""

import pytest
from pathlib import Path
from main import run_analysis


@pytest.mark.e2e
@pytest.mark.slow
def test_full_pipeline_simple_pe(samples_dir, test_output_dir, minimal_config):
    """
    Test complete analysis pipeline with simple PE.

    Validates:
    - File loading
    - Static analysis
    - Report generation
    - Output files created
    """
    sample_file = samples_dir / "pe" / "simple_pe32.exe"

    # Run full analysis
    result = run_analysis(
        file_path=sample_file,
        config_path=minimal_config,
        output_dir=test_output_dir
    )

    # Verify result structure
    assert result['status'] == 'success'
    assert result['file_type'] == 'pe'
    assert 'static_pe_analysis' in result
    assert result['static_pe_analysis']['pe_info']['is_valid']

    # Verify output files
    json_report = test_output_dir / "simple_pe32_report.json"
    assert json_report.exists()
    assert json_report.stat().st_size > 0
```

**Deliverables:**
- 50 integration tests
- 15 E2E tests
- Full pipeline validation
- Docker deployment tests

### 5.6 Phase 6: Performance & Security (Week 12)

**Priority:** MEDIUM

**Performance Tests (15 tests):**
- Crypto algorithm benchmarks
- Image analysis benchmarks
- Memory usage validation
- NPU/GPU acceleration validation
- Batch scalability

**Security Tests (10 tests):**
- Fuzzing input validation
- Path traversal prevention
- Command injection prevention
- DoS prevention
- Cryptographic security

**Deliverables:**
- 15 performance benchmarks
- 10 security tests
- Performance regression detection
- Security regression prevention

---

## 6. Quality Gates & CI/CD Integration

### 6.1 Quality Gates

**Pre-Commit Checks:**
```bash
# Run before every commit
pytest tests/unit/ -v --cov --cov-fail-under=80
black --check .
pylint core_engine/ stego-analyzer/ intelligence/ exporters/
mypy core_engine/ --ignore-missing-imports
```

**Pre-Merge Checks:**
```bash
# Run before merging to main
pytest tests/ -v --cov --cov-fail-under=80
pytest tests/integration/ -v
pytest tests/e2e/ -v --maxfail=1
pytest tests/security/ -v
```

**Pre-Release Checks:**
```bash
# Run before releasing
pytest tests/ -v --cov --cov-fail-under=80
pytest tests/performance/ -v
pytest tests/regression/ -v
bandit -r core_engine/ stego-analyzer/ intelligence/
safety check
```

### 6.2 GitHub Actions Workflow

**Create `.github/workflows/tests.yml`:**

```yaml
name: KP14 Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-timeout

      - name: Run unit tests
        run: |
          pytest tests/unit/ -v --cov --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          flags: unittests

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov

      - name: Run integration tests
        run: |
          pytest tests/integration/ -v --cov --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          flags: integration

  security-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest bandit safety

      - name: Run security tests
        run: |
          pytest tests/security/ -v
          bandit -r core_engine/ stego-analyzer/ intelligence/
          safety check --json
```

### 6.3 GitLab CI/CD (.gitlab-ci.yml)

**Add test stages to existing `.gitlab-ci.yml`:**

```yaml
stages:
  - test
  - security
  - deploy

unit-tests:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install pytest pytest-cov
    - pytest tests/unit/ -v --cov --cov-report=term --cov-report=html
  artifacts:
    paths:
      - htmlcov/
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
  coverage: '/TOTAL.+ (\d+%)/'

integration-tests:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install pytest pytest-cov
    - pytest tests/integration/ -v --cov
  needs: [unit-tests]

e2e-tests:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install pytest
    - pytest tests/e2e/ -v
  needs: [integration-tests]
  only:
    - main
    - merge_requests

security-scan:
  stage: security
  image: python:3.11
  script:
    - pip install pytest bandit safety
    - pytest tests/security/ -v
    - bandit -r core_engine/ stego-analyzer/ -f json -o bandit_report.json
    - safety check --json > safety_report.json
  artifacts:
    paths:
      - bandit_report.json
      - safety_report.json
  allow_failure: false
```

---

## 7. Test Execution Guide

### 7.1 Run All Tests

```bash
# Run entire test suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov --cov-report=html

# Parallel execution (faster)
pytest tests/ -n auto
```

### 7.2 Run Specific Test Categories

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# E2E tests (slow)
pytest tests/e2e/ -v

# Performance benchmarks
pytest tests/performance/ -v --benchmark-only

# Security tests
pytest tests/security/ -v
```

### 7.3 Run Tests by Marker

```bash
# Fast tests only
pytest -m "unit" -v

# Tests requiring hardware
pytest -m "requires_npu" -v

# Slow tests
pytest -m "slow" -v --maxfail=1
```

### 7.4 Coverage Analysis

```bash
# Generate coverage report
pytest tests/ --cov --cov-report=html

# View coverage in browser
xdg-open htmlcov/index.html

# Coverage for specific module
pytest tests/unit/core_engine/ --cov=core_engine --cov-report=term-missing

# Fail if coverage < 80%
pytest tests/ --cov --cov-fail-under=80
```

### 7.5 Debugging Tests

```bash
# Run with verbose output
pytest tests/ -vv

# Stop on first failure
pytest tests/ -x

# Drop into debugger on failure
pytest tests/ --pdb

# Show print statements
pytest tests/ -s

# Run specific test
pytest tests/unit/core_engine/test_configuration_manager.py::TestConfigurationManager::test_load_valid_config -v
```

---

## 8. Maintenance & Best Practices

### 8.1 Test Maintenance Guidelines

1. **One Assertion Per Test:**
   - Each test should verify one specific behavior
   - Use subtests for related variations

2. **Clear Test Names:**
   ```python
   def test_configuration_manager_rejects_invalid_log_level():
       # Clear intent from name
       pass
   ```

3. **AAA Pattern:**
   ```python
   def test_example():
       # Arrange - Set up test conditions
       config = create_test_config()

       # Act - Execute the behavior
       result = process_config(config)

       # Assert - Verify the outcome
       assert result.is_valid
   ```

4. **Use Fixtures Over Setup/Teardown:**
   ```python
   @pytest.fixture
   def temp_file():
       path = create_temp_file()
       yield path
       cleanup(path)
   ```

5. **Mock External Dependencies:**
   ```python
   def test_with_mock(mocker):
       mock_api = mocker.patch('module.external_api')
       mock_api.return_value = "expected"
       # Test internal logic
   ```

### 8.2 Test Documentation

1. **Docstrings for Test Files:**
   ```python
   """
   Unit tests for ConfigurationManager.

   Tests configuration loading, validation, and error handling.
   Covers edge cases: missing files, invalid values, type errors.
   """
   ```

2. **Docstrings for Test Functions:**
   ```python
   def test_load_missing_config():
       """
       Test that ConfigurationManager raises ConfigurationError
       when attempting to load a non-existent configuration file.
       """
   ```

3. **Comments for Complex Assertions:**
   ```python
   # Verify that the parser correctly identifies obfuscated strings
   # by checking entropy threshold (>4.5) and character distribution
   assert result.entropy > 4.5
   assert result.is_obfuscated
   ```

### 8.3 Continuous Improvement

1. **Monitor Coverage Trends:**
   - Track coverage per module over time
   - Identify modules dropping below targets
   - Add tests for newly added code

2. **Review Flaky Tests:**
   - Investigate tests that fail intermittently
   - Improve test isolation
   - Fix timing dependencies

3. **Update Test Data:**
   - Regenerate samples when algorithms change
   - Update checksums after regeneration
   - Document sample provenance

4. **Performance Regression Detection:**
   - Baseline performance metrics
   - Alert on significant slowdowns (>10%)
   - Profile slow tests

---

## 9. Success Metrics

### 9.1 Coverage Targets

| Module | Current | Target | Status |
|--------|---------|--------|--------|
| core_engine | 0% | 85% | NOT STARTED |
| stego-analyzer/analysis | 0% | 75% | NOT STARTED |
| intelligence | 0% | 80% | NOT STARTED |
| exporters | 0% | 70% | NOT STARTED |
| **Overall** | **~15%** | **80%** | IN PROGRESS |

### 9.2 Test Metrics

| Metric | Current | Target | Notes |
|--------|---------|--------|-------|
| Total Tests | 30 | 440-580 | 15× increase |
| Unit Tests | 30 | 300-400 | Core testing |
| Integration Tests | 0 | 50-75 | Module interactions |
| E2E Tests | 0 | 10-15 | Full workflows |
| Test Execution Time | Unknown | <5 min | Fast feedback |
| Flaky Tests | Unknown | 0 | Zero tolerance |
| Test Pass Rate | Unknown | 100% | Zero failing tests |

### 9.3 Quality Gates

**Merge to Main:**
- ✅ All tests pass (100%)
- ✅ Coverage ≥ 80%
- ✅ No new security vulnerabilities
- ✅ Performance within 10% baseline
- ✅ Code review approved

**Release:**
- ✅ All tests pass (100%)
- ✅ Coverage ≥ 80%
- ✅ E2E tests pass
- ✅ Security scan clean (Bandit, Safety)
- ✅ Performance benchmarks meet SLA
- ✅ Documentation updated

---

## 10. Implementation Roadmap

### Timeline: 12 Weeks

**Weeks 1-2: Foundation**
- Fix existing tests
- Set up pytest infrastructure
- Generate test data
- Baseline coverage report

**Weeks 3-4: Core Engine (CRITICAL)**
- 120 core_engine tests
- 85%+ coverage
- Integration tests for pipeline

**Weeks 5-7: Analysis Modules (HIGH)**
- 180 analysis module tests
- 75%+ coverage
- Performance benchmarks

**Weeks 8-9: Intelligence & Exporters (HIGH)**
- 114 intelligence/exporter tests
- 80%/70% coverage
- Format validation

**Weeks 10-11: Integration & E2E (HIGH)**
- 50 integration tests
- 15 E2E tests
- Full pipeline validation

**Week 12: Performance & Security (MEDIUM)**
- 15 performance benchmarks
- 10 security tests
- CI/CD integration

---

## 11. Dependencies & Blockers

### 11.1 Required Dependencies

**Add to `requirements.txt`:**
```
pytest>=8.0.0
pytest-cov>=4.1.0
pytest-timeout>=2.2.0
pytest-mock>=3.12.0
pytest-xdist>=3.5.0  # Parallel testing
pytest-benchmark>=4.0.0  # Performance benchmarks
hypothesis>=6.92.0  # Property-based testing
```

### 11.2 Known Blockers

1. **Missing Module: `core_engine.security_utils`**
   - **Impact:** Security tests cannot run
   - **Resolution:** Create module or fix imports
   - **Priority:** CRITICAL

2. **Missing Dependency: `jpegio`**
   - **Impact:** F5/JSTEG tests cannot run
   - **Resolution:** Add to requirements.txt
   - **Priority:** HIGH

3. **Test Sample Generation**
   - **Impact:** Cannot run tests without samples
   - **Resolution:** Implement `generate_samples.py`
   - **Priority:** CRITICAL

4. **Import Path Issues**
   - **Impact:** Tests fail with ModuleNotFoundError
   - **Resolution:** Fix sys.path in conftest.py
   - **Priority:** CRITICAL

---

## 12. Handoff to Implementation Teams

### 12.1 TESTBED Agent Responsibilities

**Scope:** Implement actual test code

**Tasks:**
1. Create all test files in `tests/unit/`, `tests/integration/`, `tests/e2e/`
2. Write test functions following AAA pattern
3. Use fixtures from conftest.py files
4. Implement mocks for external dependencies
5. Ensure all tests pass locally before committing
6. Document test assumptions and edge cases

**Deliverables:**
- 440-580 test functions across all categories
- 80%+ coverage as verified by pytest-cov
- All tests passing with `pytest tests/ -v`

### 12.2 PYTHON-INTERNAL Agent Responsibilities

**Scope:** Fix import errors and infrastructure issues

**Tasks:**
1. Fix import errors in existing security tests
2. Create missing `core_engine.security_utils` module
3. Update `requirements.txt` with test dependencies
4. Fix path resolution in test files
5. Refactor sys.path manipulation to use proper imports
6. Ensure all modules are importable from tests

**Deliverables:**
- All import errors resolved
- All existing tests passing
- Clean module structure

### 12.3 Coordination

**Communication:**
- Daily standup on test progress
- Shared coverage dashboard
- Blocked issues logged in GitHub/GitLab

**Review Process:**
- All test code reviewed before merge
- Coverage checked on every PR
- Flaky tests investigated immediately

---

## Appendix A: Example Test Files

### A.1 Unit Test Example

**File:** `tests/unit/core_engine/test_file_validator.py`

```python
"""
Unit tests for FileValidator module.

Tests file validation, magic byte detection, and size limits.
"""

import pytest
from pathlib import Path
from core_engine.file_validator import FileValidator
from core_engine.error_handler import FileValidationError


@pytest.mark.unit
class TestFileValidator:
    """Test suite for FileValidator."""

    def test_validate_pe_file(self, sample_pe_file):
        """Test validation of a valid PE file."""
        validator = FileValidator()
        result = validator.validate(sample_pe_file)

        assert result.is_valid
        assert result.file_type == "pe"
        assert result.size > 0

    def test_reject_corrupted_file(self, corrupted_pe_file):
        """Test rejection of corrupted PE file."""
        validator = FileValidator()

        with pytest.raises(FileValidationError, match="Invalid PE header"):
            validator.validate(corrupted_pe_file)

    def test_reject_oversized_file(self, large_file):
        """Test rejection of file exceeding size limit."""
        validator = FileValidator(max_size_mb=5)

        with pytest.raises(FileValidationError, match="exceeds maximum size"):
            validator.validate(large_file)

    def test_detect_file_type_from_magic_bytes(self, file_type_samples):
        """Test file type detection from magic bytes."""
        validator = FileValidator()

        assert validator.detect_type(file_type_samples['pe']) == "pe"
        assert validator.detect_type(file_type_samples['zip']) == "zip"
        assert validator.detect_type(file_type_samples['jpeg']) == "jpeg"
        assert validator.detect_type(file_type_samples['png']) == "png"
```

### A.2 Integration Test Example

**File:** `tests/integration/test_extraction_pipeline.py`

```python
"""
Integration tests for extraction pipeline.

Tests polyglot detection → extraction → recursive analysis flow.
"""

import pytest
from pathlib import Path
from core_engine.pipeline_manager import PipelineManager
from stego-analyzer.extraction import PolyglotAnalyzer, SteganographyAnalyzer


@pytest.mark.integration
class TestExtractionPipeline:
    """Test extraction pipeline integration."""

    def test_extract_pe_from_jpeg(self, samples_dir, minimal_config):
        """
        Test extraction of PE from JPEG polyglot.

        Verifies:
        1. JPEG recognized as carrier
        2. Appended PE detected
        3. PE extracted to temp file
        4. Recursive analysis triggered
        """
        jpeg_pe_sample = samples_dir / "polyglot" / "jpeg_pe.jpg"

        pipeline = PipelineManager(minimal_config)
        result = pipeline.run_extraction(jpeg_pe_sample)

        # Verify detection
        assert result['polyglot_detected']
        assert result['carrier_type'] == "jpeg"

        # Verify extraction
        assert len(result['extracted_payloads']) == 1
        payload = result['extracted_payloads'][0]
        assert payload['type'] == "pe"
        assert Path(payload['extracted_path']).exists()

        # Verify recursive analysis
        assert 'recursive_analysis' in payload
        assert payload['recursive_analysis']['static_pe_analysis']['pe_info']['is_valid']
```

### A.3 E2E Test Example

**File:** `tests/e2e/test_full_pipeline.py`

```python
"""
End-to-end tests for complete analysis workflows.
"""

import pytest
import json
from pathlib import Path
from main import run_analysis


@pytest.mark.e2e
@pytest.mark.slow
class TestFullPipeline:
    """End-to-end tests for KP14 platform."""

    def test_analyze_simple_pe_full_workflow(
        self, samples_dir, test_output_dir, minimal_config
    ):
        """
        Complete workflow: PE sample → analysis → report generation.

        Verifies:
        - File validation
        - Static analysis (PE, code, obfuscation)
        - Intelligence extraction
        - Report generation (JSON, HTML)
        - Output file structure
        """
        sample_file = samples_dir / "pe" / "simple_pe32.exe"

        # Run full analysis
        result = run_analysis(
            file_path=sample_file,
            config_path=minimal_config,
            output_dir=test_output_dir,
            formats=["json", "html"]
        )

        # Verify success
        assert result['status'] == 'success'
        assert result['errors'] == []

        # Verify analysis completeness
        assert 'static_pe_analysis' in result
        assert 'code_analysis' in result
        assert 'obfuscation_details' in result
        assert 'intelligence' in result

        # Verify PE info
        pe_info = result['static_pe_analysis']['pe_info']
        assert pe_info['is_valid']
        assert pe_info['architecture'] in ['x86', 'x64']
        assert len(pe_info['sections']) > 0

        # Verify intelligence
        intel = result['intelligence']
        assert 'threat_score' in intel
        assert 0 <= intel['threat_score'] <= 100

        # Verify output files
        json_report = test_output_dir / "simple_pe32_report.json"
        html_report = test_output_dir / "simple_pe32_report.html"

        assert json_report.exists()
        assert html_report.exists()

        # Verify JSON structure
        with open(json_report) as f:
            report_data = json.load(f)
            assert report_data['file_path'] == str(sample_file)
            assert 'static_pe_analysis' in report_data
```

---

## Appendix B: Pytest Quick Reference

### Running Tests

```bash
# All tests
pytest

# Specific directory
pytest tests/unit/

# Specific file
pytest tests/unit/core_engine/test_file_validator.py

# Specific test
pytest tests/unit/core_engine/test_file_validator.py::TestFileValidator::test_validate_pe_file

# With markers
pytest -m unit
pytest -m "unit and not slow"

# With coverage
pytest --cov=core_engine --cov-report=html

# Parallel execution
pytest -n auto

# Stop on first failure
pytest -x

# Verbose output
pytest -vv

# Show print statements
pytest -s
```

### Common Markers

```python
@pytest.mark.unit           # Unit test
@pytest.mark.integration    # Integration test
@pytest.mark.e2e            # End-to-end test
@pytest.mark.slow           # Test takes >1s
@pytest.mark.skip           # Skip this test
@pytest.mark.skipif(condition, reason="...")  # Conditional skip
@pytest.mark.parametrize("input,expected", [...])  # Parameterized test
```

### Fixture Scopes

```python
@pytest.fixture(scope="function")  # Per test (default)
@pytest.fixture(scope="class")     # Per test class
@pytest.fixture(scope="module")    # Per test file
@pytest.fixture(scope="session")   # Once per session
```

---

## Appendix C: Coverage Analysis Tools

### Generate Coverage Report

```bash
# HTML report (most useful)
pytest --cov=core_engine --cov-report=html
xdg-open htmlcov/index.html

# Terminal report with missing lines
pytest --cov=core_engine --cov-report=term-missing

# JSON report (for CI/CD)
pytest --cov=core_engine --cov-report=json:.coverage.json

# XML report (for tools like Codecov)
pytest --cov=core_engine --cov-report=xml:coverage.xml
```

### Analyze Uncovered Code

```bash
# Show lines not covered
coverage report --show-missing

# Annotate source code with coverage
coverage annotate

# Detailed HTML breakdown
coverage html
```

---

## Document Control

**Version:** 2.0
**Last Updated:** 2025-10-02
**Author:** QADIRECTOR Agent
**Reviewers:** TESTBED Agent, PYTHON-INTERNAL Agent
**Status:** APPROVED FOR IMPLEMENTATION

**Change Log:**
- 2025-10-02: Initial comprehensive strategy (v2.0)
- Assessment of 24 existing test files
- 161 source files analyzed (~45K LOC)
- 80%+ coverage target defined
- 12-week implementation roadmap

**Next Review:** After Phase 1 completion (Week 2)
