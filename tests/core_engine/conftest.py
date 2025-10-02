"""
Pytest configuration and shared fixtures for core_engine tests.

This module provides common fixtures for testing core engine components:
- Mock configuration managers
- Temporary files and directories
- Mock analyzers
- Test data generators
"""

import pytest
import tempfile
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, Mock
import configparser


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)


@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for log files."""
    temp_path = tempfile.mkdtemp(prefix="test_logs_")
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)


@pytest.fixture
def sample_pe_bytes():
    """Generate minimal valid PE file bytes."""
    # Minimal PE header structure
    pe_data = bytearray(1024)

    # DOS header
    pe_data[0:2] = b'MZ'  # e_magic
    pe_data[0x3c:0x40] = (0x80).to_bytes(4, 'little')  # e_lfanew (PE header offset)

    # PE signature at offset 0x80
    pe_data[0x80:0x84] = b'PE\x00\x00'

    # COFF header
    pe_data[0x84:0x86] = (0x014c).to_bytes(2, 'little')  # Machine (i386)
    pe_data[0x86:0x88] = (1).to_bytes(2, 'little')  # Number of sections

    # Optional header
    pe_data[0x98:0x9a] = (0x010b).to_bytes(2, 'little')  # Magic (PE32)

    return bytes(pe_data)


@pytest.fixture
def sample_pe_file(temp_dir, sample_pe_bytes):
    """Create a temporary PE file."""
    pe_path = os.path.join(temp_dir, "test_sample.exe")
    with open(pe_path, 'wb') as f:
        f.write(sample_pe_bytes)
    return pe_path


@pytest.fixture
def corrupted_pe_file(temp_dir):
    """Create a corrupted PE file (wrong magic bytes)."""
    pe_path = os.path.join(temp_dir, "corrupted.exe")
    with open(pe_path, 'wb') as f:
        f.write(b'ZM' + b'\x00' * 1022)  # Wrong magic bytes
    return pe_path


@pytest.fixture
def large_file(temp_dir):
    """Create a file that exceeds size limits."""
    large_path = os.path.join(temp_dir, "large_file.bin")
    # Create a 10MB file
    with open(large_path, 'wb') as f:
        f.write(b'\x00' * (10 * 1024 * 1024))
    return large_path


@pytest.fixture
def test_config_content():
    """Sample configuration file content."""
    return """
[general]
project_root = .
output_dir = test_output
log_level = DEBUG
verbose = True

[paths]
log_dir_name = test_logs
extracted_dir_name = test_extracted
graphs_dir_name = test_graphs
models_dir_name = test_models

[pe_analyzer]
enabled = True
max_file_size_mb = 50
scan_on_import = False

[code_analyzer]
enabled = True
max_recursion_depth = 5
analyze_libraries = False

[obfuscation_analyzer]
enabled = True
string_entropy_threshold = 4.5
max_suspicious_loops = 5
"""


@pytest.fixture
def test_config_file(temp_dir, test_config_content):
    """Create a temporary test configuration file."""
    config_path = os.path.join(temp_dir, "test_settings.ini")
    with open(config_path, 'w') as f:
        f.write(test_config_content)
    return config_path


@pytest.fixture
def invalid_config_file(temp_dir):
    """Create an invalid configuration file."""
    config_path = os.path.join(temp_dir, "invalid_settings.ini")
    with open(config_path, 'w') as f:
        f.write("[general]\nlog_level = INVALID_LEVEL\n")
    return config_path


@pytest.fixture
def mock_config_manager():
    """Create a mock ConfigurationManager."""
    mock = Mock()

    # Default configuration values
    config_data = {
        'general': {
            'project_root': '/tmp/test',
            'output_dir': '/tmp/test/output',
            'log_level': 'INFO',
            'verbose': True
        },
        'paths': {
            'log_dir': '/tmp/test/logs',
            'extracted_dir': '/tmp/test/extracted',
            'graphs_dir': '/tmp/test/graphs',
            'models_dir': '/tmp/test/models'
        },
        'pe_analyzer': {
            'enabled': True,
            'max_file_size_mb': 100
        },
        'code_analyzer': {
            'enabled': True,
            'max_recursion_depth': 10
        },
        'obfuscation_analyzer': {
            'enabled': True,
            'string_entropy_threshold': 4.5
        }
    }

    # Mock methods
    def get_side_effect(section, option, fallback=None):
        return config_data.get(section, {}).get(option, fallback)

    def getboolean_side_effect(section, option, fallback=None):
        val = config_data.get(section, {}).get(option, fallback)
        if isinstance(val, bool):
            return val
        return str(val).lower() in ('true', '1', 'yes')

    def getint_side_effect(section, option, fallback=None):
        val = config_data.get(section, {}).get(option, fallback)
        return int(val) if val is not None else fallback

    def getfloat_side_effect(section, option, fallback=None):
        val = config_data.get(section, {}).get(option, fallback)
        return float(val) if val is not None else fallback

    def get_section_side_effect(section, fallback=None):
        return config_data.get(section, fallback)

    mock.get.side_effect = get_side_effect
    mock.getboolean.side_effect = getboolean_side_effect
    mock.getint.side_effect = getint_side_effect
    mock.getfloat.side_effect = getfloat_side_effect
    mock.get_section.side_effect = get_section_side_effect

    return mock


@pytest.fixture
def mock_pe_analyzer():
    """Create a mock PEAnalyzer."""
    mock = Mock()
    mock.get_analysis_summary.return_value = {
        "file_type": "PE32",
        "architecture": "x86",
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x2000,
                "pointer_to_raw_data": 0x400,
                "size_of_raw_data": 0x2000,
                "characteristics_flags": ["MEM_READ", "MEM_EXECUTE"]
            }
        ],
        "imports": ["kernel32.dll", "user32.dll"],
        "exports": []
    }
    return mock


@pytest.fixture
def mock_code_analyzer():
    """Create a mock CodeAnalyzer."""
    mock = Mock()
    mock.get_analysis_summary.return_value = {
        "instructions_count": 100,
        "functions_detected": 5,
        "suspicious_patterns": []
    }
    return mock


@pytest.fixture
def mock_obfuscation_analyzer():
    """Create a mock ObfuscationAnalyzer."""
    mock = Mock()
    mock.analyze_obfuscation.return_value = {
        "entropy": 4.2,
        "obfuscation_detected": False,
        "techniques": []
    }
    return mock


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    mock = Mock()
    mock.debug = Mock()
    mock.info = Mock()
    mock.warning = Mock()
    mock.error = Mock()
    mock.critical = Mock()
    return mock


@pytest.fixture
def entropy_test_data():
    """Provide test data for entropy calculations."""
    return {
        'low_entropy': b'A' * 1000,  # All same byte
        'medium_entropy': b'ABCD' * 250,  # Repeating pattern
        'high_entropy': os.urandom(1000),  # Random data
        'mixed_entropy': b'A' * 500 + os.urandom(500)  # Mixed
    }


@pytest.fixture
def suspicious_payload_data():
    """Provide test data with suspicious patterns."""
    return {
        'nop_sled': b'\x90' * 100,  # NOP sled
        'int3_padding': b'\xcc' * 50,  # INT3 padding
        'cmd_exe': b'Some data here cmd.exe and more data',
        'powershell': b'powershell -enc base64data',
        'clean': b'This is completely normal text data'
    }


@pytest.fixture
def file_type_samples(temp_dir):
    """Create sample files of different types."""
    samples = {}

    # PE file
    pe_path = os.path.join(temp_dir, "sample.exe")
    with open(pe_path, 'wb') as f:
        f.write(b'MZ' + b'\x00' * 100)
    samples['pe'] = pe_path

    # ZIP file
    zip_path = os.path.join(temp_dir, "sample.zip")
    with open(zip_path, 'wb') as f:
        f.write(b'PK\x03\x04' + b'\x00' * 100)
    samples['zip'] = zip_path

    # JPEG file
    jpg_path = os.path.join(temp_dir, "sample.jpg")
    with open(jpg_path, 'wb') as f:
        f.write(b'\xff\xd8\xff' + b'\x00' * 100)
    samples['jpeg'] = jpg_path

    # PNG file
    png_path = os.path.join(temp_dir, "sample.png")
    with open(png_path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
    samples['png'] = png_path

    # Unknown file
    unk_path = os.path.join(temp_dir, "sample.dat")
    with open(unk_path, 'wb') as f:
        f.write(b'XYZA' + b'\x00' * 100)
    samples['unknown'] = unk_path

    return samples


@pytest.fixture(autouse=True)
def cleanup_test_artifacts():
    """Automatically cleanup test artifacts after each test."""
    yield
    # Cleanup is handled by individual fixtures
    pass


@pytest.fixture
def mock_retry_exceptions():
    """Provide exception types for retry testing."""
    from core_engine.error_handler import NetworkError, ResourceExhaustionError
    return (NetworkError, ResourceExhaustionError)
