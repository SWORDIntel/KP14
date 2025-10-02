"""
Security Utilities Module for KP14 Analysis Framework

This module provides comprehensive security hardening utilities:
- Path traversal prevention and validation
- Input sanitization for file paths and user data
- Command injection protection for subprocess calls
- File size limit enforcement
- Magic byte validation
- Secure temporary file handling
- Security-focused exception handling

Author: KP14 Security Team
Version: 1.0.0
Security Level: CRITICAL
"""

import os
import re
import tempfile
import hashlib
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import shutil

# Import error classes
from .error_handler import FileValidationError, SecurityError

# ============================================================================
# Configuration Constants
# ============================================================================

# Maximum file sizes (in bytes) to prevent DoS attacks
MAX_FILE_SIZE_DEFAULT = 500 * 1024 * 1024  # 500 MB
MAX_FILE_SIZE_LIMITS = {
    'pe': 200 * 1024 * 1024,      # 200 MB for PE files
    'image': 100 * 1024 * 1024,   # 100 MB for images
    'archive': 500 * 1024 * 1024,  # 500 MB for archives
    'document': 50 * 1024 * 1024,  # 50 MB for documents
}

# Allowed file extensions (whitelist approach)
ALLOWED_EXTENSIONS = {
    'executable': {'.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl'},
    'archive': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'},
    'image': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff'},
    'document': {'.pdf', '.rtf', '.doc', '.docx', '.xls', '.xlsx'},
    'other': {'.bin', '.dat', '.dex', '.apk', '.jar', '.class', '.elf', '.so'},
}

# Magic byte signatures for validation
MAGIC_BYTES = {
    'pe': [b'MZ'],
    'elf': [b'\x7fELF'],
    'zip': [b'PK\x03\x04', b'PK\x05\x06'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'jpeg': [b'\xff\xd8\xff'],
    'gif': [b'GIF87a', b'GIF89a'],
    'pdf': [b'%PDF-'],
}

# Blocked path patterns (blacklist for additional security)
BLOCKED_PATH_PATTERNS = [
    r'\.\.',           # Directory traversal
    r'[<>:"|?*]',     # Invalid filename characters (Windows)
    r'[\x00-\x1f]',   # Control characters
    r'^/etc/',         # System directories (Unix)
    r'^/proc/',
    r'^/sys/',
    r'^C:\\Windows\\', # System directories (Windows)
    r'^C:\\Program Files',
]

# Dangerous command patterns for subprocess protection
DANGEROUS_COMMAND_PATTERNS = [
    r';\s*rm\s+-rf',   # Destructive commands
    r'\|\s*sh',        # Command chaining
    r'&&\s*curl',      # Download and execute
    r'`.*`',           # Command substitution
    r'\$\(.*\)',       # Command substitution
    r'>\s*/dev/',      # Device access
]

# Logger
logger = logging.getLogger(__name__)


# ============================================================================
# Path Validation and Sanitization
# ============================================================================

class PathValidator:
    """
    Comprehensive path validation and sanitization.
    Prevents path traversal, validates file locations, and ensures security.
    """

    @staticmethod
    def is_safe_path(file_path: str, base_directory: Optional[str] = None) -> bool:
        """
        Check if a file path is safe and does not contain path traversal attempts.

        Args:
            file_path: Path to validate
            base_directory: Optional base directory to restrict access to

        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Normalize the path
            normalized_path = os.path.normpath(os.path.abspath(file_path))

            # Check for blocked patterns
            for pattern in BLOCKED_PATH_PATTERNS:
                if re.search(pattern, file_path, re.IGNORECASE):
                    logger.warning(f"Blocked path pattern detected: {pattern} in {file_path}")
                    return False

            # If base directory specified, ensure path is within it
            if base_directory:
                base_abs = os.path.normpath(os.path.abspath(base_directory))
                if not normalized_path.startswith(base_abs):
                    logger.warning(f"Path {normalized_path} is outside base directory {base_abs}")
                    return False

            # Additional checks for suspicious patterns
            if '..' in file_path:
                logger.warning(f"Path traversal attempt detected: {file_path}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating path {file_path}: {e}")
            return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename by removing dangerous characters.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename
        """
        # Remove path components
        filename = os.path.basename(filename)

        # Remove or replace dangerous characters
        sanitized = re.sub(r'[^\w\-\.]', '_', filename)

        # Prevent hidden files on Unix
        if sanitized.startswith('.'):
            sanitized = '_' + sanitized[1:]

        # Ensure reasonable length
        if len(sanitized) > 255:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:250] + ext

        return sanitized

    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = True,
                          allowed_base: Optional[str] = None) -> Tuple[bool, str]:
        """
        Comprehensive file path validation.

        Args:
            file_path: Path to validate
            must_exist: Whether file must exist
            allowed_base: Optional base directory restriction

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if path is safe
        if not PathValidator.is_safe_path(file_path, allowed_base):
            return False, "Path contains unsafe patterns or is outside allowed directory"

        # Check existence if required
        if must_exist and not os.path.exists(file_path):
            return False, f"File does not exist: {file_path}"

        # Check if it's a file (not directory)
        if must_exist and not os.path.isfile(file_path):
            return False, f"Path is not a file: {file_path}"

        # Check read permissions
        if must_exist and not os.access(file_path, os.R_OK):
            return False, f"File is not readable: {file_path}"

        return True, ""


# ============================================================================
# File Size Validation
# ============================================================================

class FileSizeValidator:
    """Validates file sizes to prevent DoS attacks and resource exhaustion."""

    @staticmethod
    def validate_size(file_path: str, max_size: Optional[int] = None,
                     file_type: Optional[str] = None) -> Tuple[bool, int, str]:
        """
        Validate file size against limits.

        Args:
            file_path: Path to file
            max_size: Optional custom maximum size
            file_type: Optional file type for type-specific limits

        Returns:
            Tuple of (is_valid, actual_size, error_message)
        """
        try:
            actual_size = os.path.getsize(file_path)

            # Determine size limit
            if max_size is not None:
                size_limit = max_size
            elif file_type and file_type in MAX_FILE_SIZE_LIMITS:
                size_limit = MAX_FILE_SIZE_LIMITS[file_type]
            else:
                size_limit = MAX_FILE_SIZE_DEFAULT

            # Validate
            if actual_size > size_limit:
                return False, actual_size, f"File size {actual_size} exceeds limit {size_limit}"

            if actual_size == 0:
                return False, actual_size, "File is empty"

            return True, actual_size, ""

        except Exception as e:
            return False, 0, f"Error checking file size: {e}"


# ============================================================================
# Magic Byte Validation
# ============================================================================

class MagicByteValidator:
    """Validates files using magic byte signatures to detect file type spoofing."""

    @staticmethod
    def validate_magic_bytes(file_path: str, expected_type: Optional[str] = None,
                            bytes_to_read: int = 16) -> Tuple[bool, str, str]:
        """
        Validate file magic bytes.

        Args:
            file_path: Path to file
            expected_type: Optional expected file type
            bytes_to_read: Number of bytes to read for validation

        Returns:
            Tuple of (is_valid, detected_type, error_message)
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(bytes_to_read)

            if not header:
                return False, 'empty', "File is empty or unreadable"

            # Detect file type from magic bytes
            detected_type = None
            for file_type, signatures in MAGIC_BYTES.items():
                for signature in signatures:
                    if header.startswith(signature):
                        detected_type = file_type
                        break
                if detected_type:
                    break

            if not detected_type:
                detected_type = 'unknown'

            # Validate against expected type if provided
            if expected_type and detected_type != expected_type:
                return False, detected_type, \
                    f"Magic bytes indicate {detected_type}, expected {expected_type}"

            return True, detected_type, ""

        except Exception as e:
            return False, 'error', f"Error reading magic bytes: {e}"


# ============================================================================
# Command Injection Protection
# ============================================================================

class CommandValidator:
    """Validates and sanitizes commands for subprocess execution."""

    @staticmethod
    def is_safe_command(command: List[str]) -> Tuple[bool, str]:
        """
        Validate a command for safety before subprocess execution.

        Args:
            command: Command as list of arguments

        Returns:
            Tuple of (is_safe, error_message)
        """
        if not command:
            return False, "Empty command"

        # Join command for pattern checking
        command_str = ' '.join(command)

        # Check for dangerous patterns
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, command_str):
                return False, f"Dangerous command pattern detected: {pattern}"

        # Check for shell metacharacters in arguments
        for arg in command[1:]:  # Skip executable name
            if any(char in arg for char in ['|', ';', '&', '$', '`', '\n']):
                return False, f"Shell metacharacter detected in argument: {arg}"

        return True, ""

    @staticmethod
    def sanitize_command_args(args: List[str]) -> List[str]:
        """
        Sanitize command arguments by escaping dangerous characters.

        Args:
            args: List of command arguments

        Returns:
            List of sanitized arguments
        """
        sanitized = []
        for arg in args:
            # Remove or escape shell metacharacters
            sanitized_arg = arg.replace('|', '').replace(';', '').replace('&', '')
            sanitized_arg = sanitized_arg.replace('$', '').replace('`', '')
            sanitized.append(sanitized_arg)
        return sanitized


# ============================================================================
# Secure Temporary File Management
# ============================================================================

@contextmanager
def secure_temp_file(suffix: str = '', prefix: str = 'kp14_',
                    dir: Optional[str] = None, delete: bool = True):
    """
    Context manager for secure temporary file creation and cleanup.

    Args:
        suffix: File suffix
        prefix: File prefix
        dir: Directory for temp file
        delete: Whether to delete file on exit

    Yields:
        Path to temporary file
    """
    temp_fd = None
    temp_path = None

    try:
        # Create secure temporary file
        temp_fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)

        # Close the file descriptor (we'll reopen as needed)
        os.close(temp_fd)
        temp_fd = None

        # Set restrictive permissions (owner read/write only)
        os.chmod(temp_path, 0o600)

        logger.debug(f"Created secure temp file: {temp_path}")
        yield temp_path

    finally:
        # Cleanup
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except:
                pass

        if delete and temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
                logger.debug(f"Deleted temp file: {temp_path}")
            except Exception as e:
                logger.warning(f"Failed to delete temp file {temp_path}: {e}")


@contextmanager
def secure_temp_directory(suffix: str = '', prefix: str = 'kp14_',
                         dir: Optional[str] = None, delete: bool = True):
    """
    Context manager for secure temporary directory creation and cleanup.

    Args:
        suffix: Directory suffix
        prefix: Directory prefix
        dir: Parent directory
        delete: Whether to delete directory on exit

    Yields:
        Path to temporary directory
    """
    temp_dir = None

    try:
        # Create secure temporary directory
        temp_dir = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

        # Set restrictive permissions
        os.chmod(temp_dir, 0o700)

        logger.debug(f"Created secure temp directory: {temp_dir}")
        yield temp_dir

    finally:
        # Cleanup
        if delete and temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.debug(f"Deleted temp directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to delete temp directory {temp_dir}: {e}")


# ============================================================================
# Input Sanitization
# ============================================================================

class InputSanitizer:
    """Sanitizes various types of user input."""

    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize a file path."""
        # Normalize and resolve path
        path = os.path.normpath(path)

        # Remove dangerous patterns
        path = path.replace('..', '')

        return path

    @staticmethod
    def sanitize_string(text: str, max_length: int = 1000) -> str:
        """
        Sanitize a string by removing control characters and limiting length.

        Args:
            text: Input text
            max_length: Maximum allowed length

        Returns:
            Sanitized text
        """
        # Remove control characters
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)

        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        return sanitized

    @staticmethod
    def sanitize_ip_address(ip: str) -> Optional[str]:
        """
        Validate and sanitize an IP address.

        Args:
            ip: IP address string

        Returns:
            Sanitized IP or None if invalid
        """
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'

        if re.match(ipv4_pattern, ip):
            # Validate IPv4 ranges
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return ip

        if re.match(ipv6_pattern, ip):
            return ip

        return None


# ============================================================================
# Security Exception Handler
# ============================================================================

def handle_security_exception(func):
    """
    Decorator for security-focused exception handling.
    Catches exceptions and converts them to SecurityError with sanitized messages.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SecurityError:
            # Re-raise security errors
            raise
        except FileValidationError:
            # Re-raise validation errors
            raise
        except Exception as e:
            # Sanitize exception message to prevent information leakage
            sanitized_msg = str(e).replace(os.path.expanduser('~'), '[HOME]')
            sanitized_msg = re.sub(r'/[^ ]+/', '[PATH]/', sanitized_msg)

            logger.error(f"Security exception in {func.__name__}: {sanitized_msg}")
            raise SecurityError(
                f"Security operation failed: {func.__name__}",
                context={'sanitized_error': sanitized_msg}
            )
    return wrapper


# ============================================================================
# Comprehensive Security Validator
# ============================================================================

class SecurityValidator:
    """
    Comprehensive security validation combining all security checks.
    This is the main interface for security validation in KP14.
    """

    def __init__(self, base_directory: Optional[str] = None,
                 max_file_size: Optional[int] = None):
        """
        Initialize security validator.

        Args:
            base_directory: Optional base directory to restrict file access
            max_file_size: Optional maximum file size
        """
        self.base_directory = base_directory
        self.max_file_size = max_file_size or MAX_FILE_SIZE_DEFAULT
        self.logger = logger

    @handle_security_exception
    def validate_file(self, file_path: str, expected_type: Optional[str] = None,
                     check_magic: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive security validation on a file.

        Args:
            file_path: Path to file
            expected_type: Optional expected file type
            check_magic: Whether to validate magic bytes

        Returns:
            Validation report dictionary

        Raises:
            FileValidationError: If validation fails
            SecurityError: If security check fails
        """
        report = {
            'file_path': file_path,
            'validation_passed': False,
            'checks': {},
            'warnings': [],
            'errors': []
        }

        # 1. Path validation
        is_safe, error_msg = PathValidator.validate_file_path(
            file_path, must_exist=True, allowed_base=self.base_directory
        )
        report['checks']['path_validation'] = is_safe
        if not is_safe:
            report['errors'].append(f"Path validation failed: {error_msg}")
            raise FileValidationError(error_msg, file_path=file_path)

        # 2. Size validation
        is_valid_size, actual_size, size_error = FileSizeValidator.validate_size(
            file_path, max_size=self.max_file_size, file_type=expected_type
        )
        report['checks']['size_validation'] = is_valid_size
        report['file_size'] = actual_size
        if not is_valid_size:
            report['errors'].append(f"Size validation failed: {size_error}")
            raise FileValidationError(size_error, file_path=file_path)

        # 3. Magic byte validation
        if check_magic:
            is_valid_magic, detected_type, magic_error = MagicByteValidator.validate_magic_bytes(
                file_path, expected_type
            )
            report['checks']['magic_validation'] = is_valid_magic
            report['detected_type'] = detected_type

            if not is_valid_magic and expected_type:
                report['warnings'].append(f"Magic byte validation: {magic_error}")
                # Don't fail on magic byte mismatch, just warn

        # All checks passed
        report['validation_passed'] = True
        self.logger.info(f"Security validation passed for: {file_path}")

        return report


# ============================================================================
# Utility Functions
# ============================================================================

def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Compute hash of a file for integrity checking.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, sha1, md5)

    Returns:
        Hex digest of file hash
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def is_suspicious_filename(filename: str) -> bool:
    """
    Check if a filename contains suspicious patterns.

    Args:
        filename: Filename to check

    Returns:
        True if suspicious
    """
    suspicious_patterns = [
        r'\.exe\.txt$',     # Double extension
        r'\.scr$',          # Screensaver executable
        r'^\.',             # Hidden file (Unix)
        r'\s{2,}',          # Multiple spaces
        r'[^\x00-\x7f]',    # Non-ASCII characters
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, filename, re.IGNORECASE):
            return True

    return False
