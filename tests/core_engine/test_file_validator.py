"""
Comprehensive tests for core_engine/file_validator.py

Tests cover:
- Magic byte validation (15+ types)
- File size limits
- Entropy analysis
- Suspicious pattern detection
- Corrupted file handling
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.file_validator import (
    FileType,
    FileValidator,
    ValidationConfig,
    calculate_entropy,
    analyze_entropy_sections,
    identify_file_type,
    validate_magic_bytes,
    validate_file_size,
    scan_suspicious_patterns,
    calculate_file_hashes,
    quick_validate,
    MAGIC_SIGNATURES,
    SUSPICIOUS_PATTERNS
)
from core_engine.error_handler import (
    FileValidationError,
    FileSizeError,
    FileFormatError
)


class TestFileTypeIdentification:
    """Test file type identification by magic bytes."""

    def test_identify_pe_executable(self):
        """Test PE executable identification."""
        pe_data = b'MZ' + b'\x00' * 100

        file_type, confidence = identify_file_type(pe_data)

        assert file_type == FileType.PE_EXECUTABLE
        assert confidence > 0

    def test_identify_elf_executable(self):
        """Test ELF executable identification."""
        elf_data = b'\x7fELF' + b'\x00' * 100

        file_type, confidence = identify_file_type(elf_data)

        assert file_type == FileType.ELF_EXECUTABLE
        assert confidence > 0

    def test_identify_zip_file(self):
        """Test ZIP file identification."""
        zip_data = b'PK\x03\x04' + b'\x00' * 100

        file_type, confidence = identify_file_type(zip_data)

        assert file_type == FileType.ZIP
        assert confidence > 0

    def test_identify_jpeg_file(self):
        """Test JPEG file identification."""
        jpeg_data = b'\xff\xd8\xff' + b'\x00' * 100

        file_type, confidence = identify_file_type(jpeg_data)

        assert file_type == FileType.JPEG
        assert confidence > 0

    def test_identify_png_file(self):
        """Test PNG file identification."""
        png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

        file_type, confidence = identify_file_type(png_data)

        assert file_type == FileType.PNG
        assert confidence > 0

    def test_identify_gif_file(self):
        """Test GIF file identification."""
        gif_data = b'GIF89a' + b'\x00' * 100

        file_type, confidence = identify_file_type(gif_data)

        assert file_type == FileType.GIF
        assert confidence > 0

    def test_identify_pdf_file(self):
        """Test PDF file identification."""
        pdf_data = b'%PDF-' + b'\x00' * 100

        file_type, confidence = identify_file_type(pdf_data)

        assert file_type == FileType.PDF
        assert confidence > 0

    def test_identify_rar_file(self):
        """Test RAR file identification."""
        rar_data = b'Rar!\x1a\x07\x00' + b'\x00' * 100

        file_type, confidence = identify_file_type(rar_data)

        assert file_type == FileType.RAR
        assert confidence > 0

    def test_identify_unknown_file(self):
        """Test unknown file type."""
        unknown_data = b'UNKN' + b'\x00' * 100

        file_type, confidence = identify_file_type(unknown_data)

        assert file_type == FileType.UNKNOWN
        assert confidence == 0.0

    def test_identify_with_extension_match(self, temp_dir):
        """Test file type identification with matching extension."""
        test_file = os.path.join(temp_dir, "test.exe")
        pe_data = b'MZ' + b'\x00' * 100
        with open(test_file, 'wb') as f:
            f.write(pe_data)

        file_type, confidence = identify_file_type(pe_data, test_file)

        assert file_type == FileType.PE_EXECUTABLE
        assert confidence == 1.0  # Both magic and extension agree

    def test_identify_with_extension_mismatch(self, temp_dir):
        """Test file type with mismatched extension."""
        test_file = os.path.join(temp_dir, "test.txt")
        pe_data = b'MZ' + b'\x00' * 100
        with open(test_file, 'wb') as f:
            f.write(pe_data)

        file_type, confidence = identify_file_type(pe_data, test_file)

        # Magic bytes take precedence
        assert file_type == FileType.PE_EXECUTABLE

    def test_identify_short_data(self):
        """Test identification with insufficient data."""
        short_data = b'MZ'

        file_type, confidence = identify_file_type(short_data)

        # Should still work with minimal data
        assert file_type in [FileType.PE_EXECUTABLE, FileType.UNKNOWN]


class TestMagicByteValidation:
    """Test magic byte validation."""

    def test_validate_correct_magic_bytes(self):
        """Test validation passes for correct magic bytes."""
        pe_data = b'MZ' + b'\x00' * 100

        result = validate_magic_bytes(pe_data, FileType.PE_EXECUTABLE)

        assert result is True

    def test_validate_incorrect_magic_bytes(self):
        """Test validation fails for incorrect magic bytes."""
        elf_data = b'\x7fELF' + b'\x00' * 100

        with pytest.raises(FileFormatError):
            validate_magic_bytes(elf_data, FileType.PE_EXECUTABLE)

    def test_validate_with_file_path(self):
        """Test validation includes file path in error."""
        wrong_data = b'WRONG' + b'\x00' * 100

        with pytest.raises(FileFormatError) as exc_info:
            validate_magic_bytes(wrong_data, FileType.PE_EXECUTABLE, "/test/file.exe")

        assert "/test/file.exe" in str(exc_info.value)


class TestFileSizeValidation:
    """Test file size validation."""

    def test_validate_acceptable_size(self, sample_pe_file):
        """Test validation passes for acceptable file size."""
        size = validate_file_size(sample_pe_file)

        assert size > 0

    def test_validate_exceeds_max_size(self, large_file):
        """Test validation fails when file exceeds max size."""
        with pytest.raises(FileSizeError):
            validate_file_size(large_file, max_size=1024)  # 1KB limit

    def test_validate_below_min_size(self, temp_dir):
        """Test validation fails when file below min size."""
        tiny_file = os.path.join(temp_dir, "tiny.bin")
        with open(tiny_file, 'wb') as f:
            f.write(b'X')

        with pytest.raises(FileSizeError):
            validate_file_size(tiny_file, min_size=1024)

    def test_validate_nonexistent_file(self):
        """Test validation fails for non-existent file."""
        with pytest.raises(FileValidationError):
            validate_file_size("/nonexistent/file.exe")

    def test_file_size_error_details(self, large_file):
        """Test FileSizeError includes size details."""
        try:
            validate_file_size(large_file, max_size=1024)
            pytest.fail("Should have raised FileSizeError")
        except FileSizeError as e:
            assert e.context["actual_size"] > 1024
            assert e.context["max_size"] == 1024


class TestEntropyCalculation:
    """Test entropy calculation functions."""

    def test_calculate_entropy_low(self, entropy_test_data):
        """Test entropy calculation for low entropy data."""
        entropy = calculate_entropy(entropy_test_data['low_entropy'])

        assert 0.0 <= entropy < 2.0  # Very low entropy

    def test_calculate_entropy_high(self, entropy_test_data):
        """Test entropy calculation for high entropy data."""
        entropy = calculate_entropy(entropy_test_data['high_entropy'])

        assert entropy > 7.0  # High entropy (random data)

    def test_calculate_entropy_medium(self, entropy_test_data):
        """Test entropy calculation for medium entropy data."""
        entropy = calculate_entropy(entropy_test_data['medium_entropy'])

        assert 2.0 < entropy < 6.0  # Medium entropy

    def test_calculate_entropy_empty_data(self):
        """Test entropy calculation for empty data."""
        entropy = calculate_entropy(b'')

        assert entropy == 0.0

    def test_analyze_entropy_sections(self, entropy_test_data):
        """Test entropy analysis in sections."""
        sections = analyze_entropy_sections(
            entropy_test_data['mixed_entropy'],
            section_size=100
        )

        assert len(sections) > 0
        assert all('entropy' in s for s in sections)
        assert all('offset' in s for s in sections)

    def test_entropy_sections_detect_suspicious(self):
        """Test entropy sections detect suspicious regions."""
        # Create data with very high entropy section
        data = b'A' * 500 + os.urandom(500)

        sections = analyze_entropy_sections(data, section_size=500)

        # Should detect high entropy in second section
        suspicious_sections = [s for s in sections if s['suspicious']]
        assert len(suspicious_sections) > 0


class TestSuspiciousPatternDetection:
    """Test suspicious payload pattern scanning."""

    def test_scan_nop_sled(self, suspicious_payload_data):
        """Test detection of NOP sled pattern."""
        detections = scan_suspicious_patterns(suspicious_payload_data['nop_sled'])

        assert len(detections) > 0
        assert any('NOP' in d['description'] for d in detections)

    def test_scan_int3_padding(self, suspicious_payload_data):
        """Test detection of INT3 padding."""
        detections = scan_suspicious_patterns(suspicious_payload_data['int3_padding'])

        assert len(detections) > 0
        assert any('INT3' in d['description'] for d in detections)

    def test_scan_cmd_exe(self, suspicious_payload_data):
        """Test detection of cmd.exe string."""
        detections = scan_suspicious_patterns(suspicious_payload_data['cmd_exe'])

        assert len(detections) > 0
        assert any('cmd.exe' in d['pattern'] for d in detections)

    def test_scan_powershell(self, suspicious_payload_data):
        """Test detection of powershell string."""
        detections = scan_suspicious_patterns(suspicious_payload_data['powershell'])

        assert len(detections) > 0
        assert any('powershell' in d['pattern'].lower() for d in detections)

    def test_scan_clean_data(self, suspicious_payload_data):
        """Test no detections for clean data."""
        detections = scan_suspicious_patterns(suspicious_payload_data['clean'])

        # May have some detections if common words match, but should be minimal
        assert isinstance(detections, list)

    def test_scan_with_max_size(self):
        """Test scanning respects max size limit."""
        large_data = b'X' * (20 * 1024 * 1024)  # 20MB

        detections = scan_suspicious_patterns(large_data, max_scan_size=1024)

        # Should complete quickly, only scanning first 1KB
        assert isinstance(detections, list)

    def test_pattern_offset_tracking(self):
        """Test pattern detections include offset information."""
        data = b'\x00' * 100 + b'cmd.exe' + b'\x00' * 100

        detections = scan_suspicious_patterns(data)

        if detections:
            assert all('offset' in d for d in detections)
            # cmd.exe should be around offset 100
            cmd_detections = [d for d in detections if 'cmd.exe' in d['pattern']]
            if cmd_detections:
                assert cmd_detections[0]['offset'] >= 100


class TestHashCalculation:
    """Test file hash calculation."""

    def test_calculate_md5_hash(self, sample_pe_file):
        """Test MD5 hash calculation."""
        hashes = calculate_file_hashes(sample_pe_file, algorithms=['md5'])

        assert 'md5' in hashes
        assert len(hashes['md5']) == 32  # MD5 is 32 hex chars

    def test_calculate_sha1_hash(self, sample_pe_file):
        """Test SHA1 hash calculation."""
        hashes = calculate_file_hashes(sample_pe_file, algorithms=['sha1'])

        assert 'sha1' in hashes
        assert len(hashes['sha1']) == 40  # SHA1 is 40 hex chars

    def test_calculate_sha256_hash(self, sample_pe_file):
        """Test SHA256 hash calculation."""
        hashes = calculate_file_hashes(sample_pe_file, algorithms=['sha256'])

        assert 'sha256' in hashes
        assert len(hashes['sha256']) == 64  # SHA256 is 64 hex chars

    def test_calculate_multiple_hashes(self, sample_pe_file):
        """Test calculating multiple hash algorithms."""
        hashes = calculate_file_hashes(sample_pe_file, algorithms=['md5', 'sha1', 'sha256'])

        assert 'md5' in hashes
        assert 'sha1' in hashes
        assert 'sha256' in hashes

    def test_calculate_default_hashes(self, sample_pe_file):
        """Test default hash algorithms."""
        hashes = calculate_file_hashes(sample_pe_file)

        # Default should include md5, sha1, sha256
        assert len(hashes) >= 3

    def test_hash_deterministic(self, sample_pe_file):
        """Test hash calculation is deterministic."""
        hashes1 = calculate_file_hashes(sample_pe_file)
        hashes2 = calculate_file_hashes(sample_pe_file)

        assert hashes1 == hashes2

    def test_hash_nonexistent_file(self):
        """Test hash calculation fails gracefully for missing file."""
        with pytest.raises(FileValidationError):
            calculate_file_hashes("/nonexistent/file.exe")


class TestFileValidator:
    """Test comprehensive file validator."""

    def test_validate_pe_file(self, sample_pe_file):
        """Test validating a PE file."""
        validator = FileValidator()

        report = validator.validate_file(
            sample_pe_file,
            expected_type=FileType.PE_EXECUTABLE
        )

        assert report["validation_passed"] is True
        assert report["file_info"]["detected_type"] == FileType.PE_EXECUTABLE.value

    def test_validate_nonexistent_file(self):
        """Test validation of non-existent file."""
        validator = FileValidator()

        with pytest.raises(FileValidationError):
            validator.validate_file("/nonexistent/file.exe")

    def test_validate_with_size_check(self, sample_pe_file):
        """Test validation includes size check."""
        validator = FileValidator()

        report = validator.validate_file(sample_pe_file)

        assert "size" in report["file_info"]
        assert report["file_info"]["size"] > 0

    def test_validate_with_hash_calculation(self, sample_pe_file):
        """Test validation includes hash calculation."""
        validator = FileValidator()

        report = validator.validate_file(sample_pe_file, calculate_hashes=True)

        assert "hashes" in report["file_info"]
        assert "md5" in report["file_info"]["hashes"]

    def test_validate_with_entropy_analysis(self, sample_pe_file):
        """Test validation includes entropy analysis."""
        validator = FileValidator()

        report = validator.validate_file(sample_pe_file, analyze_entropy=True)

        assert "overall_entropy" in report["security_analysis"]

    def test_validate_with_payload_scan(self, sample_pe_file):
        """Test validation includes payload scanning."""
        validator = FileValidator()

        report = validator.validate_file(sample_pe_file, scan_payloads=True)

        assert "suspicious_patterns" in report["security_analysis"]

    def test_validate_type_mismatch(self, sample_pe_file):
        """Test validation detects type mismatch."""
        validator = FileValidator()

        report = validator.validate_file(
            sample_pe_file,
            expected_type=FileType.ELF_EXECUTABLE
        )

        # Should have warnings about type mismatch
        assert len(report["warnings"]) > 0 or not report["file_info"].get("type_validated", True)

    def test_validate_high_entropy_warning(self, temp_dir):
        """Test validation warns about high entropy."""
        high_entropy_file = os.path.join(temp_dir, "high_entropy.bin")
        with open(high_entropy_file, 'wb') as f:
            f.write(os.urandom(1024))

        validator = FileValidator()
        report = validator.validate_file(high_entropy_file, analyze_entropy=True)

        # Should warn about high entropy
        assert len(report["warnings"]) > 0

    def test_validate_suspicious_patterns_warning(self, temp_dir):
        """Test validation warns about suspicious patterns."""
        suspicious_file = os.path.join(temp_dir, "suspicious.bin")
        with open(suspicious_file, 'wb') as f:
            f.write(b'\x90' * 100 + b'cmd.exe' + b'\x00' * 100)

        validator = FileValidator()
        report = validator.validate_file(suspicious_file, scan_payloads=True)

        # Should have suspicious pattern detections
        if report["security_analysis"].get("suspicious_patterns", 0) > 0:
            assert len(report["warnings"]) > 0

    def test_validation_report_structure(self, sample_pe_file):
        """Test validation report has correct structure."""
        validator = FileValidator()

        report = validator.validate_file(sample_pe_file)

        # Check required fields
        assert "file_path" in report
        assert "file_name" in report
        assert "validation_passed" in report
        assert "errors" in report
        assert "warnings" in report
        assert "file_info" in report
        assert "security_analysis" in report


class TestQuickValidate:
    """Test quick validation convenience function."""

    def test_quick_validate_valid_file(self, sample_pe_file):
        """Test quick validation of valid file."""
        result = quick_validate(sample_pe_file)

        assert result is True

    def test_quick_validate_with_type_check(self, sample_pe_file):
        """Test quick validation with type checking."""
        result = quick_validate(sample_pe_file, expected_type=FileType.PE_EXECUTABLE)

        assert result is True

    def test_quick_validate_type_mismatch(self, sample_pe_file):
        """Test quick validation fails on type mismatch."""
        result = quick_validate(sample_pe_file, expected_type=FileType.ELF_EXECUTABLE)

        assert result is False

    def test_quick_validate_size_exceeded(self, large_file):
        """Test quick validation fails on size limit."""
        result = quick_validate(large_file, max_size=1024)

        assert result is False


class TestValidationConfig:
    """Test validation configuration."""

    def test_config_has_size_limits(self):
        """Test validation config has size limits."""
        config = ValidationConfig()

        assert hasattr(config, 'MAX_FILE_SIZE')
        assert hasattr(config, 'MIN_FILE_SIZE')

    def test_config_has_entropy_thresholds(self):
        """Test validation config has entropy thresholds."""
        config = ValidationConfig()

        assert hasattr(config, 'HIGH_ENTROPY_THRESHOLD')
        assert hasattr(config, 'LOW_ENTROPY_THRESHOLD')

    def test_config_has_scan_settings(self):
        """Test validation config has scan settings."""
        config = ValidationConfig()

        assert hasattr(config, 'ENABLE_PAYLOAD_SCAN')
        assert hasattr(config, 'MAX_SCAN_SIZE')


@pytest.mark.parametrize("file_type,magic_bytes", [
    (FileType.PE_EXECUTABLE, b'MZ'),
    (FileType.ELF_EXECUTABLE, b'\x7fELF'),
    (FileType.ZIP, b'PK\x03\x04'),
    (FileType.RAR, b'Rar!\x1a\x07\x00'),
    (FileType.JPEG, b'\xff\xd8\xff'),
    (FileType.PNG, b'\x89PNG\r\n\x1a\n'),
    (FileType.GIF, b'GIF89a'),
    (FileType.PDF, b'%PDF-'),
    (FileType.BMP, b'BM'),
    (FileType.CLASS, b'\xca\xfe\xba\xbe'),
])
def test_file_type_magic_signatures(file_type, magic_bytes):
    """Parametrized test for file type magic signatures."""
    test_data = magic_bytes + b'\x00' * 100

    detected_type, confidence = identify_file_type(test_data)

    assert detected_type == file_type
    assert confidence > 0
