"""
Integration test fixtures and configuration for KP14.

Provides fixtures for:
- Test sample generation
- Integration test configuration
- End-to-end pipeline setup
- Docker integration
- Hardware acceleration testing
"""

import pytest
import os
import sys
import tempfile
import shutil
import struct
import zipfile
import json
from pathlib import Path
from typing import Dict, Any, Generator
from PIL import Image
import numpy as np

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core_engine.configuration_manager import ConfigurationManager
from core_engine.pipeline_manager import PipelineManager


# ============================================================================
# Session-scoped fixtures
# ============================================================================

@pytest.fixture(scope="session")
def integration_fixtures_dir() -> Path:
    """Return the integration test fixtures directory."""
    return PROJECT_ROOT / "tests" / "integration" / "fixtures"


@pytest.fixture(scope="session")
def integration_samples_dir(integration_fixtures_dir: Path) -> Path:
    """Return the integration test samples directory."""
    samples_dir = integration_fixtures_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    return samples_dir


# ============================================================================
# Test sample generation fixtures
# ============================================================================

@pytest.fixture(scope="session")
def valid_pe32_sample(integration_samples_dir: Path) -> Path:
    """
    Generate a minimal valid PE32 executable for testing.

    Returns a simple "Hello World" style PE that exits immediately.
    """
    pe_path = integration_samples_dir / "valid_pe32.exe"

    if pe_path.exists():
        return pe_path

    # Minimal PE32 structure (DOS header + PE header + one section)
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'  # DOS signature
    dos_header[60:64] = struct.pack('<I', 64)  # PE header offset

    # PE signature
    pe_sig = b'PE\x00\x00'

    # COFF header (IMAGE_FILE_HEADER)
    coff_header = struct.pack(
        '<HHIIIHH',
        0x014c,  # Machine (i386)
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        224,     # SizeOfOptionalHeader
        0x0102   # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    )

    # Optional header (simplified PE32)
    optional_header = struct.pack(
        '<HBB',
        0x010b,  # Magic (PE32)
        0x0e,    # MajorLinkerVersion
        0x00     # MinorLinkerVersion
    )
    optional_header += b'\x00' * 220  # Pad to 224 bytes

    # Section header (.text section)
    section_header = bytearray(40)
    section_header[0:6] = b'.text\x00'  # Name
    struct.pack_into('<I', section_header, 8, 0x1000)   # VirtualSize
    struct.pack_into('<I', section_header, 12, 0x1000)  # VirtualAddress
    struct.pack_into('<I', section_header, 16, 0x200)   # SizeOfRawData
    struct.pack_into('<I', section_header, 20, 0x200)   # PointerToRawData
    struct.pack_into('<I', section_header, 36, 0x60000020)  # Characteristics

    # Simple machine code that exits (x86: xor eax,eax; ret)
    code_section = b'\x31\xC0\xC3' + b'\x00' * (0x200 - 3)

    # Write PE file
    with open(pe_path, 'wb') as f:
        f.write(dos_header)
        f.write(pe_sig)
        f.write(coff_header)
        f.write(optional_header)
        f.write(section_header)
        f.write(code_section)

    return pe_path


@pytest.fixture(scope="session")
def polyglot_zip_pe_sample(integration_samples_dir: Path, valid_pe32_sample: Path) -> Path:
    """
    Generate a polyglot ZIP file with embedded PE.

    Creates a valid ZIP containing a PE executable.
    """
    polyglot_path = integration_samples_dir / "polyglot_zip_pe.zip"

    if polyglot_path.exists():
        return polyglot_path

    with zipfile.ZipFile(polyglot_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(valid_pe32_sample, arcname="embedded.exe")
        # Add a text file for good measure
        zf.writestr("readme.txt", "This is a test polyglot sample")

    return polyglot_path


@pytest.fixture(scope="session")
def stego_lsb_image_sample(integration_samples_dir: Path) -> Path:
    """
    Generate an image with LSB steganography containing hidden data.

    Creates a PNG with a hidden message in the least significant bits.
    """
    stego_path = integration_samples_dir / "stego_lsb_image.png"

    if stego_path.exists():
        return stego_path

    # Create a simple test image (100x100 RGB)
    width, height = 100, 100
    img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)

    # Embed a simple message in LSB
    secret_message = b"HIDDEN_PAYLOAD_TEST"

    # Convert message to bits
    message_bits = []
    for byte in secret_message:
        for i in range(8):
            message_bits.append((byte >> (7 - i)) & 1)

    # Embed in red channel LSB
    flat_img = img_array.flatten()
    for i, bit in enumerate(message_bits):
        if i >= len(flat_img):
            break
        flat_img[i] = (flat_img[i] & 0xFE) | bit

    img_array = flat_img.reshape((height, width, 3))

    # Save as PNG
    img = Image.fromarray(img_array, 'RGB')
    img.save(stego_path, 'PNG')

    return stego_path


@pytest.fixture(scope="session")
def c2_embedded_sample(integration_samples_dir: Path, valid_pe32_sample: Path) -> Path:
    """
    Generate a PE with embedded C2 indicators (strings).

    Creates a PE with suspicious strings that look like C2 infrastructure.
    """
    c2_path = integration_samples_dir / "c2_embedded_sample.exe"

    if c2_path.exists():
        return c2_path

    # Copy the base PE
    shutil.copy(valid_pe32_sample, c2_path)

    # Append C2 indicators to the end of the file
    c2_indicators = [
        b"http://malicious-c2.example.com/callback\x00",
        b"https://192.168.1.100:8443/upload\x00",
        b"POST /api/exfil HTTP/1.1\x00",
        b"User-Agent: MalwareBot/1.0\x00",
        b"Authorization: Bearer eyJhbGc...\x00",
    ]

    with open(c2_path, 'ab') as f:
        for indicator in c2_indicators:
            f.write(indicator)

    return c2_path


@pytest.fixture(scope="session")
def corrupted_pe_sample(integration_samples_dir: Path) -> Path:
    """
    Generate a corrupted PE file for error handling tests.

    Creates a file with PE header but corrupted structure.
    """
    corrupted_path = integration_samples_dir / "corrupted_pe.exe"

    if corrupted_path.exists():
        return corrupted_path

    # Create file with MZ header but corrupted data
    with open(corrupted_path, 'wb') as f:
        f.write(b'MZ')  # DOS signature
        f.write(b'\x00' * 100)  # Some zeros
        f.write(b'CORRUPTED_DATA' * 50)  # Random data

    return corrupted_path


@pytest.fixture(scope="session")
def nested_polyglot_sample(
    integration_samples_dir: Path,
    stego_lsb_image_sample: Path,
    valid_pe32_sample: Path
) -> Path:
    """
    Generate a nested polyglot: ZIP -> JPEG (with stego) -> embedded data.

    Creates a 3-level nested structure for recursive analysis testing.
    """
    nested_path = integration_samples_dir / "nested_polyglot.zip"

    if nested_path.exists():
        return nested_path

    # Create intermediate ZIP with the stego image
    with zipfile.ZipFile(nested_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add the stego image
        zf.write(stego_lsb_image_sample, arcname="image.png")
        # Add a nested archive
        inner_zip = integration_samples_dir / "inner.zip"
        with zipfile.ZipFile(inner_zip, 'w') as inner_zf:
            inner_zf.write(valid_pe32_sample, arcname="payload.exe")
        zf.write(inner_zip, arcname="archive.zip")
        inner_zip.unlink()  # Clean up temporary file

    return nested_path


@pytest.fixture(scope="session")
def batch_test_samples(
    integration_samples_dir: Path,
    valid_pe32_sample: Path,
    c2_embedded_sample: Path,
    corrupted_pe_sample: Path
) -> Path:
    """
    Generate a batch of test samples for batch processing tests.

    Creates a directory with 10 mixed test samples.
    """
    batch_dir = integration_samples_dir / "batch_samples"
    batch_dir.mkdir(exist_ok=True)

    # Copy existing samples
    shutil.copy(valid_pe32_sample, batch_dir / "sample_01.exe")
    shutil.copy(c2_embedded_sample, batch_dir / "sample_02.exe")
    shutil.copy(corrupted_pe_sample, batch_dir / "sample_03.exe")

    # Generate additional samples by copying and modifying
    for i in range(4, 11):
        sample_path = batch_dir / f"sample_{i:02d}.exe"
        shutil.copy(valid_pe32_sample, sample_path)
        # Append unique identifier
        with open(sample_path, 'ab') as f:
            f.write(f"SAMPLE_{i}\x00".encode())

    return batch_dir


# ============================================================================
# Integration configuration fixtures
# ============================================================================

@pytest.fixture
def integration_config(tmp_path: Path) -> Path:
    """
    Create an integration test configuration file.

    Returns path to a test-specific settings.ini file.
    """
    config_path = tmp_path / "integration_settings.ini"

    config_content = f"""[general]
project_root = {tmp_path}
output_dir = {tmp_path / 'output'}
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
deep_scan = True

[code_analyzer]
enabled = True
use_radare2 = False
use_capstone = True

[obfuscation_analyzer]
enabled = True
entropy_threshold = 6.5

[polyglot_analyzer]
enabled = True
max_depth = 3
extract_embedded = True

[steganography_analyzer]
enabled = True
check_lsb = True
check_metadata = True

[crypto_analyzer]
enabled = True
try_common_keys = True

[c2_extraction]
enabled = True
extract_urls = True
extract_ips = True

[hardware_acceleration]
enabled = False
prefer_device = CPU
"""

    config_path.write_text(config_content)
    return config_path


@pytest.fixture
def integration_pipeline(integration_config: Path) -> PipelineManager:
    """
    Create a configured pipeline manager for integration tests.

    Returns a PipelineManager instance ready for testing.
    """
    config_manager = ConfigurationManager(str(integration_config))
    pipeline = PipelineManager(config_manager)
    return pipeline


@pytest.fixture
def integration_output_dir(tmp_path: Path) -> Path:
    """
    Create a temporary output directory for integration test results.

    Automatically cleaned up after test completion.
    """
    output_dir = tmp_path / "integration_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# ============================================================================
# Validation helper fixtures
# ============================================================================

@pytest.fixture
def validate_analysis_report():
    """
    Fixture providing analysis report validation function.

    Validates that an analysis report has the expected structure.
    """
    def _validate(report: Dict[str, Any], expected_keys: list = None) -> bool:
        """
        Validate analysis report structure.

        Args:
            report: Analysis report dictionary
            expected_keys: Optional list of required keys

        Returns:
            True if valid, raises AssertionError otherwise
        """
        # Basic structure
        assert isinstance(report, dict), "Report must be a dictionary"
        assert "file_path" in report, "Report must contain file_path"

        # Check expected keys if provided
        if expected_keys:
            for key in expected_keys:
                assert key in report, f"Report missing expected key: {key}"

        # Validate common sections
        if "static_pe_analysis" in report:
            pe_analysis = report["static_pe_analysis"]
            assert isinstance(pe_analysis, dict), "PE analysis must be dict"
            assert "pe_info" in pe_analysis, "PE analysis must contain pe_info"

        if "code_analysis" in report:
            code_analysis = report["code_analysis"]
            assert isinstance(code_analysis, dict), "Code analysis must be dict"

        if "obfuscation_details" in report:
            obf_details = report["obfuscation_details"]
            assert isinstance(obf_details, dict), "Obfuscation details must be dict"

        return True

    return _validate


@pytest.fixture
def validate_json_serializable():
    """
    Fixture to validate that an object is JSON serializable.
    """
    def _validate(obj: Any) -> bool:
        """
        Validate object is JSON serializable.

        Args:
            obj: Object to validate

        Returns:
            True if serializable, raises exception otherwise
        """
        try:
            json.dumps(obj, default=str)
            return True
        except Exception as e:
            raise AssertionError(f"Object not JSON serializable: {e}")

    return _validate


# ============================================================================
# Docker integration fixtures
# ============================================================================

@pytest.fixture
def docker_available() -> bool:
    """
    Check if Docker is available on the system.

    Returns:
        True if docker command is available
    """
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture
def docker_image_name() -> str:
    """Return the Docker image name for testing."""
    return "kp14-test:latest"


# ============================================================================
# Hardware acceleration fixtures
# ============================================================================

@pytest.fixture(scope="session")
def has_openvino() -> bool:
    """Check if OpenVINO is available."""
    try:
        import openvino
        return True
    except ImportError:
        return False


@pytest.fixture(scope="session")
def available_devices(has_openvino: bool) -> list:
    """
    Get list of available OpenVINO devices.

    Returns:
        List of device names (e.g., ['CPU', 'GPU', 'NPU'])
    """
    if not has_openvino:
        return ['CPU']  # Always have CPU

    try:
        import openvino as ov
        core = ov.Core()
        return core.available_devices
    except Exception:
        return ['CPU']


# ============================================================================
# Performance measurement fixtures
# ============================================================================

@pytest.fixture
def performance_tracker():
    """
    Fixture for tracking test performance metrics.

    Returns a context manager that tracks execution time.
    """
    import time
    from contextlib import contextmanager

    @contextmanager
    def _track(operation_name: str):
        """Track operation execution time."""
        start = time.time()
        metrics = {"operation": operation_name, "start_time": start}

        try:
            yield metrics
        finally:
            end = time.time()
            metrics["end_time"] = end
            metrics["duration_seconds"] = end - start
            print(f"\n[PERF] {operation_name}: {metrics['duration_seconds']:.3f}s")

    return _track
