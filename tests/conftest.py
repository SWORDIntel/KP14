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
    config_content = f"""[general]
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
    config.addinivalue_line(
        "markers", "performance: Performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "security: Security tests"
    )
    config.addinivalue_line(
        "markers", "regression: Regression tests for known bugs"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take >1s to run"
    )
    config.addinivalue_line(
        "markers", "requires_gpu: Tests requiring GPU hardware"
    )
    config.addinivalue_line(
        "markers", "requires_npu: Tests requiring NPU hardware"
    )
    config.addinivalue_line(
        "markers", "requires_samples: Tests requiring real malware samples"
    )
    config.addinivalue_line(
        "markers", "network: Tests requiring network access"
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
