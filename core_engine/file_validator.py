"""
File Validation Module for KP14 Analysis Framework

This module provides:
- Magic byte checking for file type identification
- File size validation (DoS prevention)
- Format validation and corruption detection
- Suspicious payload detection
- Entropy analysis for anomaly detection
- Hash verification and integrity checking

Author: KP14 Development Team
Version: 1.0.0
"""

import hashlib
import math
import os
import mimetypes
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Set
from collections import Counter
from enum import Enum

# Import error classes from error_handler
from .error_handler import (
    FileValidationError,
    FileSizeError,
    FileFormatError,
    SuspiciousPayloadError
)


# ============================================================================
# File Type Magic Bytes Database
# ============================================================================

class FileType(Enum):
    """Enumeration of supported file types."""
    PE_EXECUTABLE = "pe_executable"
    ELF_EXECUTABLE = "elf_executable"
    MACH_O = "mach_o"
    ZIP = "zip"
    RAR = "rar"
    GZIP = "gzip"
    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    BMP = "bmp"
    PDF = "pdf"
    RTF = "rtf"
    OLE = "ole"  # MS Office (old format)
    OOXML = "ooxml"  # MS Office (new format)
    JAR = "jar"
    CLASS = "class"
    DEX = "dex"  # Android DEX
    APK = "apk"
    UNKNOWN = "unknown"


# Magic byte signatures for file types
MAGIC_SIGNATURES: Dict[FileType, List[bytes]] = {
    FileType.PE_EXECUTABLE: [b'MZ'],
    FileType.ELF_EXECUTABLE: [b'\x7fELF'],
    FileType.MACH_O: [
        b'\xfe\xed\xfa\xce',  # 32-bit
        b'\xfe\xed\xfa\xcf',  # 64-bit
        b'\xce\xfa\xed\xfe',  # 32-bit reverse
        b'\xcf\xfa\xed\xfe'   # 64-bit reverse
    ],
    FileType.ZIP: [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    FileType.RAR: [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00'],
    FileType.GZIP: [b'\x1f\x8b'],
    FileType.JPEG: [b'\xff\xd8\xff'],
    FileType.PNG: [b'\x89PNG\r\n\x1a\n'],
    FileType.GIF: [b'GIF87a', b'GIF89a'],
    FileType.BMP: [b'BM'],
    FileType.PDF: [b'%PDF-'],
    FileType.RTF: [b'{\\rtf'],
    FileType.OLE: [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    FileType.OOXML: [b'PK\x03\x04'],  # Same as ZIP, needs deeper inspection
    FileType.JAR: [b'PK\x03\x04'],    # Same as ZIP, needs deeper inspection
    FileType.CLASS: [b'\xca\xfe\xba\xbe'],
    FileType.DEX: [b'dex\n'],
    FileType.APK: [b'PK\x03\x04'],    # Same as ZIP, needs deeper inspection
}


# File extensions mapping
EXTENSION_MAP: Dict[str, FileType] = {
    '.exe': FileType.PE_EXECUTABLE,
    '.dll': FileType.PE_EXECUTABLE,
    '.sys': FileType.PE_EXECUTABLE,
    '.elf': FileType.ELF_EXECUTABLE,
    '.so': FileType.ELF_EXECUTABLE,
    '.zip': FileType.ZIP,
    '.rar': FileType.RAR,
    '.gz': FileType.GZIP,
    '.jpg': FileType.JPEG,
    '.jpeg': FileType.JPEG,
    '.png': FileType.PNG,
    '.gif': FileType.GIF,
    '.bmp': FileType.BMP,
    '.pdf': FileType.PDF,
    '.rtf': FileType.RTF,
    '.doc': FileType.OLE,
    '.xls': FileType.OLE,
    '.ppt': FileType.OLE,
    '.docx': FileType.OOXML,
    '.xlsx': FileType.OOXML,
    '.pptx': FileType.OOXML,
    '.jar': FileType.JAR,
    '.class': FileType.CLASS,
    '.dex': FileType.DEX,
    '.apk': FileType.APK,
}


# ============================================================================
# File Validation Configuration
# ============================================================================

class ValidationConfig:
    """Configuration for file validation."""

    # Size limits (in bytes)
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
    MIN_FILE_SIZE = 0  # No minimum by default

    # Entropy thresholds
    MIN_ENTROPY = 0.0
    MAX_ENTROPY = 8.0
    HIGH_ENTROPY_THRESHOLD = 7.5  # Suspicious if above
    LOW_ENTROPY_THRESHOLD = 1.0   # Suspicious if below

    # Suspicious patterns
    ENABLE_PAYLOAD_SCAN = True
    MAX_SCAN_SIZE = 10 * 1024 * 1024  # Only scan first 10 MB for patterns

    # Executable validation
    VALIDATE_PE_STRUCTURE = True
    VALIDATE_ELF_STRUCTURE = True

    # Archive validation
    MAX_ARCHIVE_DEPTH = 5  # Maximum nesting depth
    MAX_ARCHIVE_FILES = 1000  # Maximum files in archive


# ============================================================================
# Entropy Calculator
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Bytes to calculate entropy for

    Returns:
        Entropy value (0.0 to 8.0)
    """
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)

    # Calculate Shannon entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def analyze_entropy_sections(
    data: bytes,
    section_size: int = 1024
) -> List[Dict[str, Any]]:
    """
    Analyze entropy in sections of the file.

    Args:
        data: File data
        section_size: Size of each section to analyze

    Returns:
        List of entropy analysis results per section
    """
    results = []
    data_len = len(data)

    for offset in range(0, data_len, section_size):
        section = data[offset:offset + section_size]
        entropy = calculate_entropy(section)

        results.append({
            "offset": offset,
            "size": len(section),
            "entropy": entropy,
            "suspicious": entropy > ValidationConfig.HIGH_ENTROPY_THRESHOLD or
                         entropy < ValidationConfig.LOW_ENTROPY_THRESHOLD
        })

    return results


# ============================================================================
# Magic Byte Validation
# ============================================================================

def identify_file_type(
    data: bytes,
    file_path: Optional[str] = None
) -> Tuple[FileType, float]:
    """
    Identify file type using magic bytes and extension.

    Args:
        data: File data (at least first 16 bytes)
        file_path: Optional file path for extension check

    Returns:
        Tuple of (FileType, confidence)
        confidence: 0.0 to 1.0, where 1.0 is certain
    """
    if len(data) < 4:
        return FileType.UNKNOWN, 0.0

    # Check magic bytes
    magic_matches: List[Tuple[FileType, int]] = []

    for file_type, signatures in MAGIC_SIGNATURES.items():
        for signature in signatures:
            if data.startswith(signature):
                magic_matches.append((file_type, len(signature)))

    # Get best magic byte match (longest signature)
    magic_type = None
    magic_confidence = 0.0

    if magic_matches:
        magic_type, sig_len = max(magic_matches, key=lambda x: x[1])
        magic_confidence = min(1.0, sig_len / 8.0)  # Longer signature = higher confidence

    # Check file extension if path provided
    ext_type = None
    ext_confidence = 0.0

    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in EXTENSION_MAP:
            ext_type = EXTENSION_MAP[ext]
            ext_confidence = 0.7  # Extensions are less reliable

    # Combine results
    if magic_type and ext_type:
        if magic_type == ext_type:
            return magic_type, 1.0  # Both agree, high confidence
        else:
            # Mismatch - magic bytes take precedence
            return magic_type, magic_confidence
    elif magic_type:
        return magic_type, magic_confidence
    elif ext_type:
        return ext_type, ext_confidence
    else:
        return FileType.UNKNOWN, 0.0


def validate_magic_bytes(
    data: bytes,
    expected_type: FileType,
    file_path: Optional[str] = None
) -> bool:
    """
    Validate that file has correct magic bytes for expected type.

    Args:
        data: File data
        expected_type: Expected file type
        file_path: Optional file path for error messages

    Returns:
        True if valid

    Raises:
        FileFormatError: If magic bytes don't match expected type
    """
    detected_type, confidence = identify_file_type(data, file_path)

    if detected_type != expected_type:
        raise FileFormatError(
            file_path or "unknown",
            expected_format=expected_type.value,
            actual_format=detected_type.value,
            context={"confidence": confidence}
        )

    return True


# ============================================================================
# File Size Validation
# ============================================================================

def validate_file_size(
    file_path: str,
    max_size: Optional[int] = None,
    min_size: Optional[int] = None
) -> int:
    """
    Validate file size is within acceptable limits.

    Args:
        file_path: Path to file
        max_size: Maximum allowed size in bytes
        min_size: Minimum allowed size in bytes

    Returns:
        Actual file size in bytes

    Raises:
        FileSizeError: If file size is out of bounds
    """
    if not os.path.exists(file_path):
        raise FileValidationError(f"File not found", file_path)

    file_size = os.path.getsize(file_path)

    max_limit = max_size or ValidationConfig.MAX_FILE_SIZE
    min_limit = min_size or ValidationConfig.MIN_FILE_SIZE

    if file_size > max_limit:
        raise FileSizeError(
            file_path,
            actual_size=file_size,
            max_size=max_limit,
            context={"reason": "File exceeds maximum allowed size (DoS prevention)"}
        )

    if file_size < min_limit:
        raise FileSizeError(
            file_path,
            actual_size=file_size,
            max_size=min_limit,  # Using max_size field for min check
            context={"reason": "File is smaller than minimum required size"}
        )

    return file_size


# ============================================================================
# Suspicious Payload Detection
# ============================================================================

# Patterns that might indicate malicious content
SUSPICIOUS_PATTERNS = {
    # Shellcode patterns
    b'\x90\x90\x90\x90\x90\x90\x90\x90': 'NOP sled',
    b'\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc': 'INT3 padding',

    # Common exploit strings
    b'cmd.exe': 'Command execution',
    b'powershell': 'PowerShell execution',
    b'/bin/sh': 'Shell execution',
    b'/bin/bash': 'Bash execution',

    # Web shells
    b'eval(': 'Eval function',
    b'base64_decode': 'Base64 decode',
    b'system(': 'System call',
    b'exec(': 'Exec function',

    # Network indicators
    b'socket(': 'Socket creation',
    b'connect(': 'Network connection',
    b'bind(': 'Port binding',

    # Encryption/Obfuscation
    b'CryptDecrypt': 'Decryption',
    b'VirtualProtect': 'Memory protection change',
    b'VirtualAlloc': 'Memory allocation',
}


def scan_suspicious_patterns(
    data: bytes,
    max_scan_size: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Scan data for suspicious patterns.

    Args:
        data: File data to scan
        max_scan_size: Maximum amount of data to scan

    Returns:
        List of detected suspicious patterns
    """
    scan_size = min(len(data), max_scan_size or ValidationConfig.MAX_SCAN_SIZE)
    scan_data = data[:scan_size]

    detections = []

    for pattern, description in SUSPICIOUS_PATTERNS.items():
        offset = 0
        while True:
            offset = scan_data.find(pattern, offset)
            if offset == -1:
                break

            detections.append({
                "offset": offset,
                "pattern": pattern.decode('latin-1', errors='ignore'),
                "description": description,
                "severity": "medium"
            })

            offset += len(pattern)

    return detections


# ============================================================================
# Hash Calculation
# ============================================================================

def calculate_file_hashes(
    file_path: str,
    algorithms: Optional[List[str]] = None
) -> Dict[str, str]:
    """
    Calculate cryptographic hashes of file.

    Args:
        file_path: Path to file
        algorithms: List of hash algorithms (md5, sha1, sha256, sha512)

    Returns:
        Dictionary mapping algorithm names to hex digest strings
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']

    hashes = {}
    hash_objects = {}

    # Create hash objects
    for algo in algorithms:
        try:
            hash_objects[algo] = hashlib.new(algo)
        except ValueError:
            continue  # Skip unsupported algorithms

    # Read file and update hashes
    try:
        with open(file_path, 'rb') as f:
            chunk_size = 8192
            while chunk := f.read(chunk_size):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

        # Get hex digests
        for algo, hash_obj in hash_objects.items():
            hashes[algo] = hash_obj.hexdigest()

    except Exception as e:
        raise FileValidationError(
            f"Failed to calculate hashes: {str(e)}",
            file_path,
            original_exception=e
        )

    return hashes


# ============================================================================
# Comprehensive File Validator
# ============================================================================

class FileValidator:
    """
    Comprehensive file validation with multiple checks.
    """

    def __init__(
        self,
        config: Optional[ValidationConfig] = None,
        logger: Optional[Any] = None
    ):
        """
        Initialize file validator.

        Args:
            config: Validation configuration
            logger: Logger instance for logging validation results
        """
        self.config = config or ValidationConfig()
        self.logger = logger

    def validate_file(
        self,
        file_path: str,
        expected_type: Optional[FileType] = None,
        calculate_hashes: bool = True,
        scan_payloads: bool = True,
        analyze_entropy: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive file validation.

        Args:
            file_path: Path to file to validate
            expected_type: Expected file type (None to auto-detect)
            calculate_hashes: Whether to calculate file hashes
            scan_payloads: Whether to scan for suspicious payloads
            analyze_entropy: Whether to analyze entropy

        Returns:
            Validation report dictionary

        Raises:
            FileValidationError: If validation fails
        """
        if self.logger:
            self.logger.info(f"Validating file: {file_path}")

        report = self._create_validation_report(file_path)

        try:
            # Validate file existence and size
            self._validate_file_exists(file_path, report)
            self._validate_size(file_path, report)

            # Read file data
            full_data = self._read_file_data(file_path)
            header = full_data[:16]

            # Perform type validation
            self._validate_file_type(header, file_path, expected_type, report)

            # Optional validations
            if calculate_hashes:
                self._calculate_and_store_hashes(file_path, report)

            if analyze_entropy:
                self._analyze_entropy(full_data, report)

            if scan_payloads:
                self._scan_for_suspicious_patterns(full_data, report)

            # Finalize validation
            self._finalize_validation(file_path, report)

        except Exception as e:
            self._handle_validation_error(file_path, report, e)
            raise

        return report

    def _create_validation_report(self, file_path: str) -> Dict[str, Any]:
        """Create initial validation report structure."""
        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "validation_passed": False,
            "errors": [],
            "warnings": [],
            "file_info": {},
            "security_analysis": {}
        }

    def _validate_file_exists(self, file_path: str, report: Dict[str, Any]) -> None:
        """Validate that file exists."""
        if not os.path.exists(file_path):
            raise FileValidationError("File does not exist", file_path)

    def _validate_size(self, file_path: str, report: Dict[str, Any]) -> None:
        """Validate file size."""
        try:
            file_size = validate_file_size(file_path)
            report["file_info"]["size"] = file_size
        except FileSizeError as e:
            report["errors"].append(str(e))
            raise

    def _read_file_data(self, file_path: str) -> bytes:
        """Read complete file data."""
        with open(file_path, 'rb') as f:
            return f.read()

    def _validate_file_type(self, header: bytes, file_path: str, expected_type: Optional[FileType], report: Dict[str, Any]) -> None:
        """Validate and identify file type."""
        # Identify file type
        detected_type, confidence = identify_file_type(header, file_path)
        report["file_info"]["detected_type"] = detected_type.value
        report["file_info"]["type_confidence"] = confidence

        # Validate against expected type if provided
        if expected_type:
            self._validate_expected_type(header, expected_type, file_path, report)

    def _validate_expected_type(self, header: bytes, expected_type: FileType, file_path: str, report: Dict[str, Any]) -> None:
        """Validate file against expected type."""
        try:
            validate_magic_bytes(header, expected_type, file_path)
            report["file_info"]["type_validated"] = True
        except FileFormatError as e:
            report["errors"].append(str(e))
            report["file_info"]["type_validated"] = False
            report["warnings"].append("File type mismatch detected")

    def _calculate_and_store_hashes(self, file_path: str, report: Dict[str, Any]) -> None:
        """Calculate and store file hashes."""
        try:
            hashes = calculate_file_hashes(file_path)
            report["file_info"]["hashes"] = hashes
        except Exception as e:
            report["warnings"].append(f"Hash calculation failed: {str(e)}")

    def _analyze_entropy(self, full_data: bytes, report: Dict[str, Any]) -> None:
        """Analyze file entropy."""
        try:
            overall_entropy = calculate_entropy(full_data)
            report["security_analysis"]["overall_entropy"] = overall_entropy

            # Check entropy thresholds
            self._check_entropy_thresholds(overall_entropy, report)

            # Section entropy analysis
            sections = analyze_entropy_sections(full_data)
            suspicious_sections = [s for s in sections if s["suspicious"]]
            report["security_analysis"]["suspicious_sections"] = len(suspicious_sections)

        except Exception as e:
            report["warnings"].append(f"Entropy analysis failed: {str(e)}")

    def _check_entropy_thresholds(self, entropy: float, report: Dict[str, Any]) -> None:
        """Check if entropy is within acceptable thresholds."""
        if entropy > self.config.HIGH_ENTROPY_THRESHOLD:
            report["warnings"].append(
                f"High entropy detected ({entropy:.2f}): "
                "File may be encrypted or compressed"
            )
        elif entropy < self.config.LOW_ENTROPY_THRESHOLD:
            report["warnings"].append(
                f"Low entropy detected ({entropy:.2f}): "
                "File may be padded or contain repeating patterns"
            )

    def _scan_for_suspicious_patterns(self, full_data: bytes, report: Dict[str, Any]) -> None:
        """Scan file for suspicious patterns."""
        if not self.config.ENABLE_PAYLOAD_SCAN:
            return

        try:
            detections = scan_suspicious_patterns(full_data)
            report["security_analysis"]["suspicious_patterns"] = len(detections)
            report["security_analysis"]["pattern_details"] = detections[:10]  # Limit output

            if detections:
                report["warnings"].append(
                    f"Found {len(detections)} suspicious pattern(s) in file"
                )

        except Exception as e:
            report["warnings"].append(f"Payload scan failed: {str(e)}")

    def _finalize_validation(self, file_path: str, report: Dict[str, Any]) -> None:
        """Finalize validation and set status."""
        if not report["errors"]:
            report["validation_passed"] = True
            if self.logger:
                self.logger.info(f"File validation passed: {file_path}")
        else:
            if self.logger:
                self.logger.error(f"File validation failed: {file_path}")

    def _handle_validation_error(self, file_path: str, report: Dict[str, Any], error: Exception) -> None:
        """Handle validation error."""
        report["errors"].append(str(error))
        report["validation_passed"] = False
        if self.logger:
            self.logger.error(f"Validation error for {file_path}: {str(error)}")


# ============================================================================
# Convenience Functions
# ============================================================================

def quick_validate(
    file_path: str,
    expected_type: Optional[FileType] = None,
    max_size: Optional[int] = None
) -> bool:
    """
    Quick validation check (size + magic bytes only).

    Args:
        file_path: Path to file
        expected_type: Expected file type
        max_size: Maximum allowed file size

    Returns:
        True if valid, False otherwise
    """
    try:
        # Size check
        validate_file_size(file_path, max_size=max_size)

        # Type check if expected
        if expected_type:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            validate_magic_bytes(header, expected_type, file_path)

        return True

    except (FileValidationError, FileSizeError, FileFormatError):
        return False


if __name__ == "__main__":
    # Demonstration and testing
    print("=== KP14 File Validator Module - Testing ===\n")

    # Test 1: Create a test file
    test_file = "test_file.txt"
    with open(test_file, 'wb') as f:
        f.write(b"Test data with some entropy: " + os.urandom(100))

    # Test 2: File validation
    print("Test 1: Comprehensive File Validation")
    validator = FileValidator()
    try:
        report = validator.validate_file(test_file)
        import json
        print(json.dumps(report, indent=2))
    except Exception as e:
        print(f"Validation error: {e}")

    # Test 3: Entropy calculation
    print("\nTest 2: Entropy Analysis")
    test_data = b"AAAA" * 100  # Low entropy
    print(f"Low entropy data: {calculate_entropy(test_data):.2f}")

    test_data = os.urandom(400)  # High entropy
    print(f"High entropy data: {calculate_entropy(test_data):.2f}")

    # Test 4: File type detection
    print("\nTest 3: File Type Detection")
    pe_magic = b'MZ' + b'\x00' * 14
    file_type, confidence = identify_file_type(pe_magic)
    print(f"PE detection: {file_type.value} (confidence: {confidence})")

    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)

    print("\n=== All tests completed ===")
