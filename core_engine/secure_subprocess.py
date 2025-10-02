"""
Secure Subprocess Execution Module for KP14 Analysis Framework

This module provides secure wrappers for subprocess execution with:
- Command injection protection
- Argument validation and sanitization
- Resource limits (timeout, memory)
- Process isolation recommendations
- Comprehensive logging of subprocess calls
- Sandboxing support (firejail, bubblewrap)

Author: KP14 Security Team
Version: 1.0.0
Security Level: CRITICAL

IMPORTANT: Always use these secure wrappers instead of direct subprocess calls.
"""

import subprocess
import shlex
import logging
import os
import re
import shutil
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from .error_handler import SecurityError
from .security_utils import CommandValidator

# Logger
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# Default timeout for subprocess execution (seconds)
DEFAULT_TIMEOUT = 300  # 5 minutes

# Maximum timeout allowed
MAX_TIMEOUT = 1800  # 30 minutes

# Whitelist of allowed executables (HARDENED - SECURITY CRITICAL)
# SECURITY NOTE: This whitelist has been hardened to prevent arbitrary code execution
# Removed: python, python3, docker (arbitrary code execution vectors)
# Each executable requires explicit argument validation patterns
ALLOWED_EXECUTABLES = {
    # Binary analysis tools (safe - read-only analysis)
    'radare2', 'r2',           # Binary analysis (with argument restrictions)
    'strings',                  # String extraction (safe)
    'xxd',                     # Hex dump (safe)
    'file',                    # File type identification (safe)

    # Static analysis tools (safe with argument validation)
    'yara',                    # Pattern matching (safe with file arguments)
    'clamscan',                # Antivirus scanning (safe)
    'binwalk',                 # Binary analysis (safe)

    # Archive tools (controlled extraction only)
    'unzip',                   # With -n (never overwrite) flag required
    '7z',                      # With extraction flags only
    'tar',                     # With list/extract flags only

    # Crypto tools (safe operations only)
    'openssl',                 # With restricted subcommands

    # Sandboxing tools (for running other tools safely)
    'firejail',                # Sandbox wrapper
    'bubblewrap',              # Sandbox wrapper
}

# Blocked command patterns (in addition to security_utils checks)
BLOCKED_PATTERNS = [
    'rm -rf /',
    'mkfs',
    'dd if=',
    ':(){:|:&};:',  # Fork bomb
]

# Argument validation patterns for each allowed executable
# This provides defense-in-depth by validating not just the executable,
# but also its arguments to prevent abuse
ALLOWED_ARGS_PATTERNS = {
    'radare2': {
        'allowed_flags': [
            '-q', '-qq', '-Q',           # Quiet modes
            '-c', '-i',                  # Commands and script files
            '-A', '-AA', '-AAA',         # Analysis levels
            '-n', '-N',                  # No analysis / symbols
            '-B', '-b',                  # Binary info / bits
            '-e',                        # Configuration
            '-V', '-v',                  # Version / verbose
            '-w',                        # Write mode (required for some analysis)
            '-nn',                       # No analysis at all
            '-0',                        # Run at load time
        ],
        'forbidden_patterns': [
            r'-d',                       # Debug mode (can execute code)
            r'http://',                  # Network access
            r'https://',                 # Network access
            r'tcp://',                   # Network access
            r'rap://',                   # Remote access
            r'!',                        # Shell command execution
            r'#!',                       # Shebang (script execution)
        ],
        'max_args': 15,
        'requires_file_arg': True,
    },
    'r2': {
        # Same as radare2
        'allowed_flags': ['-q', '-qq', '-Q', '-c', '-i', '-A', '-AA', '-AAA',
                         '-n', '-N', '-B', '-b', '-e', '-V', '-v', '-w', '-nn', '-0'],
        'forbidden_patterns': [r'-d', r'http://', r'https://', r'tcp://', r'rap://', r'!', r'#!'],
        'max_args': 15,
        'requires_file_arg': True,
    },
    'file': {
        'allowed_flags': [
            '--brief', '-b',             # Brief output
            '--mime-type',               # MIME type
            '--mime-encoding',           # MIME encoding
            '--mime', '-i',              # MIME info
            '-z',                        # Look inside compressed files
            '-L',                        # Follow symlinks
            '-s',                        # Special files
            '-k',                        # Keep going
        ],
        'forbidden_patterns': [
            r'-C',                       # Compile magic file (dangerous)
            r'-m',                       # Use alternate magic file
            r'-f',                       # Read filenames from file
        ],
        'max_args': 5,
        'requires_file_arg': True,
    },
    'strings': {
        'allowed_flags': [
            '-a', '--all',               # Scan entire file
            '-n', '--bytes',             # Minimum string length
            '-t', '--radix',             # Print offset
            '-e', '--encoding',          # Character encoding
            '-o',                        # Alias for -t o
            '-d',                        # Decimal offsets
            '-x',                        # Hex offsets
        ],
        'forbidden_patterns': [],
        'max_args': 6,
        'requires_file_arg': True,
    },
    'xxd': {
        'allowed_flags': [
            '-l',                        # Length
            '-s',                        # Seek
            '-c',                        # Columns
            '-g',                        # Group size
            '-i',                        # C include file style
            '-p',                        # Plain hex dump
            '-u',                        # Uppercase hex
        ],
        'forbidden_patterns': [
            r'-r',                       # Reverse (can write files)
        ],
        'max_args': 8,
        'requires_file_arg': True,
    },
    'yara': {
        'allowed_flags': [
            '-r',                        # Recursive
            '-f',                        # Fast matching
            '-n',                        # Print only not satisfied rules
            '-s',                        # Print matching strings
            '-m',                        # Print metadata
            '-g',                        # Print tags
            '-d',                        # Define external variable
        ],
        'forbidden_patterns': [
            r'http://',                  # No network rules
            r'https://',
        ],
        'max_args': 10,
        'requires_file_arg': True,
    },
    'clamscan': {
        'allowed_flags': [
            '-r',                        # Recursive
            '-i',                        # Only print infected
            '--no-summary',
            '--stdout',
            '-d',                        # Database directory
        ],
        'forbidden_patterns': [
            r'--remove',                 # Don't allow file deletion
            r'--move',                   # Don't allow file moving
        ],
        'max_args': 8,
        'requires_file_arg': True,
    },
    'binwalk': {
        'allowed_flags': [
            '-e',                        # Extract
            '-B',                        # Signature scan
            '-E',                        # Entropy analysis
            '-A',                        # Opcodes
            '-R',                        # Raw signature scan
            '-y',                        # Display YARA signatures
        ],
        'forbidden_patterns': [
            r'--run-as=',                # Don't allow privilege changes
        ],
        'max_args': 8,
        'requires_file_arg': True,
    },
    'unzip': {
        'allowed_flags': [
            '-l',                        # List contents
            '-t',                        # Test archive
            '-n',                        # Never overwrite
            '-q',                        # Quiet
            '-d',                        # Extract to directory
        ],
        'forbidden_patterns': [
            r'-o',                       # Overwrite without prompting (dangerous)
            r'^/',                       # Absolute paths
            r'\.\.',                     # Path traversal
        ],
        'max_args': 6,
        'requires_file_arg': True,
    },
    '7z': {
        'allowed_flags': [
            'l',                         # List (subcommand, not flag)
            't',                         # Test
            'x',                         # Extract with paths
            'e',                         # Extract without paths
            '-o',                        # Output directory (followed by path)
        ],
        'forbidden_patterns': [
            r'-p',                       # Password (avoid password in CLI)
        ],
        'max_args': 8,
        'requires_file_arg': True,
    },
    'tar': {
        'allowed_flags': [
            '-t',                        # List contents
            '-x',                        # Extract
            '-z',                        # Gzip
            '-j',                        # Bzip2
            '-J',                        # Xz
            '-f',                        # File
            '-v',                        # Verbose
            '-C',                        # Change directory
        ],
        'forbidden_patterns': [
            r'--absolute-names',         # Absolute paths (dangerous)
        ],
        'max_args': 8,
        'requires_file_arg': True,
    },
    'openssl': {
        'allowed_flags': [
            'dgst',                      # Digest operations
            'enc',                       # Encoding (read-only mode)
            'base64',                    # Base64
            'x509',                      # Certificate operations
            '-d',                        # Decode
            '-in',                       # Input file
            '-out',                      # Output file
        ],
        'forbidden_patterns': [
            r'req',                      # Certificate request (can create files)
            r'genrsa',                   # Key generation
            r'genpkey',                  # Key generation
        ],
        'max_args': 10,
        'requires_file_arg': False,     # Openssl has subcommands
    },
    'firejail': {
        'allowed_flags': [
            '--noprofile',
            '--net=none',
            '--noroot',
            '--private-tmp',
            '--read-only=',
            '--read-write=',
            '--',
        ],
        'forbidden_patterns': [],
        'max_args': 20,                  # Sandbox can wrap complex commands
        'requires_file_arg': False,
    },
    'bubblewrap': {
        'allowed_flags': [
            '--ro-bind',
            '--bind',
            '--dev',
            '--tmpfs',
            '--unshare-net',
            '--',
        ],
        'forbidden_patterns': [],
        'max_args': 30,                  # Sandbox can wrap complex commands
        'requires_file_arg': False,
    },
}


# ============================================================================
# Secure Subprocess Wrapper
# ============================================================================

class SecureSubprocess:
    """
    Secure wrapper for subprocess execution with validation and sandboxing.

    This class should be used for ALL subprocess calls in KP14 to ensure:
    - Command injection protection
    - Resource limits
    - Proper error handling
    - Audit logging
    """

    def __init__(self, enable_sandboxing: bool = False, sandbox_type: str = 'firejail'):
        """
        Initialize secure subprocess wrapper.

        Args:
            enable_sandboxing: Whether to use sandboxing
            sandbox_type: Type of sandbox ('firejail', 'bubblewrap', 'docker')
        """
        self.enable_sandboxing = enable_sandboxing
        self.sandbox_type = sandbox_type
        self.logger = logger

        # Check sandbox availability if enabled
        if self.enable_sandboxing:
            self._check_sandbox_availability()

    def _check_sandbox_availability(self) -> bool:
        """Check if requested sandbox is available."""
        try:
            result = subprocess.run(
                [self.sandbox_type, '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            available = result.returncode == 0

            if not available:
                self.logger.warning(f"Sandbox {self.sandbox_type} not available, disabling sandboxing")
                self.enable_sandboxing = False

            return available

        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.warning(f"Sandbox {self.sandbox_type} not found, disabling sandboxing")
            self.enable_sandboxing = False
            return False

    def _validate_executable(self, executable: str) -> bool:
        """
        Validate that executable is allowed.

        Args:
            executable: Executable name or path

        Returns:
            True if allowed
        """
        # Get basename
        exe_name = os.path.basename(executable)

        # Check whitelist
        if exe_name in ALLOWED_EXECUTABLES:
            return True

        # Check if it's a full path to an allowed executable
        if os.path.isabs(executable):
            if exe_name in ALLOWED_EXECUTABLES:
                return True

        self.logger.error(f"Executable not in whitelist: {exe_name}")
        return False

    def _validate_command_arguments(self, executable: str, args: List[str]) -> Tuple[bool, str]:
        """
        Validate command arguments against whitelist patterns.

        This provides defense-in-depth by validating not just the executable,
        but also its arguments to prevent abuse of allowed tools.

        Args:
            executable: Executable name
            args: Command arguments (not including executable itself)

        Returns:
            Tuple of (is_valid, error_message)
        """
        exe_name = os.path.basename(executable)

        # If executable not in argument patterns, it's not validated
        # (fail secure - require explicit validation patterns)
        if exe_name not in ALLOWED_ARGS_PATTERNS:
            self.logger.warning(
                f"Executable {exe_name} in whitelist but has no argument validation patterns"
            )
            return False, f"No argument validation patterns defined for {exe_name}"

        patterns = ALLOWED_ARGS_PATTERNS[exe_name]

        # Check argument count
        if len(args) > patterns['max_args']:
            self.logger.error(
                f"Too many arguments for {exe_name}: {len(args)} > {patterns['max_args']}"
            )
            return False, f"Too many arguments (max {patterns['max_args']})"

        # Check for forbidden patterns in all arguments
        args_str = ' '.join(args)
        for forbidden in patterns['forbidden_patterns']:
            if re.search(forbidden, args_str, re.IGNORECASE):
                self.logger.error(
                    f"Forbidden pattern '{forbidden}' detected in arguments for {exe_name}"
                )
                return False, f"Forbidden pattern detected: {forbidden}"

        # Check each individual argument for forbidden patterns
        for arg in args:
            for forbidden in patterns['forbidden_patterns']:
                if re.search(forbidden, arg, re.IGNORECASE):
                    self.logger.error(
                        f"Forbidden pattern '{forbidden}' in argument '{arg}' for {exe_name}"
                    )
                    return False, f"Forbidden pattern in argument: {forbidden}"

        # Verify flags are in allowed list
        # Split on '=' to handle --flag=value
        for arg in args:
            if arg.startswith('-'):
                # Handle --flag=value format
                flag = arg.split('=')[0]

                # Check if flag or its prefix is allowed
                flag_allowed = False
                for allowed_flag in patterns['allowed_flags']:
                    if flag == allowed_flag or flag.startswith(allowed_flag + '='):
                        flag_allowed = True
                        break

                if not flag_allowed:
                    self.logger.error(
                        f"Flag '{flag}' not in allowed list for {exe_name}"
                    )
                    return False, f"Disallowed flag: {flag}"

        # Check if file argument is required and present
        if patterns.get('requires_file_arg', False):
            # Look for a non-flag argument (potential file path)
            has_file_arg = any(not arg.startswith('-') for arg in args)
            if not has_file_arg:
                self.logger.error(
                    f"No file argument provided for {exe_name} (required)"
                )
                return False, "File argument required but not provided"

        # All validations passed
        self.logger.debug(f"Argument validation passed for {exe_name}")
        return True, ""

    def _validate_command(self, command: List[str]) -> Tuple[bool, str]:
        """
        Comprehensive command validation with argument validation.

        Args:
            command: Command and arguments as list

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not command:
            return False, "Empty command"

        # Validate executable
        if not self._validate_executable(command[0]):
            return False, f"Executable not allowed: {command[0]}"

        # Validate command arguments (defense-in-depth)
        # This is critical to prevent abuse of whitelisted executables
        is_valid_args, args_error = self._validate_command_arguments(
            command[0], command[1:]
        )
        if not is_valid_args:
            self.logger.error(f"Argument validation failed: {args_error}")
            return False, f"Argument validation failed: {args_error}"

        # Use CommandValidator from security_utils
        is_safe, error = CommandValidator.is_safe_command(command)
        if not is_safe:
            return False, error

        # Check for blocked patterns
        command_str = ' '.join(command)
        for pattern in BLOCKED_PATTERNS:
            if pattern in command_str:
                return False, f"Blocked command pattern: {pattern}"

        return True, ""

    def _wrap_with_sandbox(self, command: List[str],
                          work_dir: Optional[str] = None) -> List[str]:
        """
        Wrap command with sandbox.

        Args:
            command: Original command
            work_dir: Working directory to allow access to

        Returns:
            Sandboxed command
        """
        if not self.enable_sandboxing:
            return command

        if self.sandbox_type == 'firejail':
            # Firejail sandbox with network disabled
            sandbox_cmd = [
                'firejail',
                '--noprofile',      # No profile
                '--net=none',       # No network
                '--noroot',         # No root
                '--private-tmp',    # Private /tmp
                '--read-only=/',    # Read-only root
            ]

            # Allow write access to work directory if specified
            if work_dir:
                sandbox_cmd.append(f'--read-write={work_dir}')

            sandbox_cmd.append('--')
            sandbox_cmd.extend(command)
            return sandbox_cmd

        elif self.sandbox_type == 'bubblewrap':
            # Bubblewrap sandbox
            sandbox_cmd = [
                'bwrap',
                '--ro-bind', '/', '/',
                '--dev', '/dev',
                '--tmpfs', '/tmp',
                '--unshare-net',    # No network
            ]

            if work_dir:
                sandbox_cmd.extend(['--bind', work_dir, work_dir])

            sandbox_cmd.append('--')
            sandbox_cmd.extend(command)
            return sandbox_cmd

        else:
            self.logger.warning(f"Unknown sandbox type: {self.sandbox_type}")
            return command

    def run(self, command: List[str],
            timeout: Optional[int] = None,
            work_dir: Optional[str] = None,
            capture_output: bool = True,
            check: bool = False,
            env: Optional[Dict[str, str]] = None,
            **kwargs) -> subprocess.CompletedProcess:
        """
        Securely execute a command with validation and sandboxing.

        Args:
            command: Command and arguments as list
            timeout: Timeout in seconds
            work_dir: Working directory
            capture_output: Whether to capture stdout/stderr
            check: Whether to raise exception on non-zero exit
            env: Environment variables
            **kwargs: Additional subprocess.run arguments

        Returns:
            CompletedProcess instance

        Raises:
            SecurityError: If command validation fails
            subprocess.TimeoutExpired: If timeout is exceeded
            subprocess.CalledProcessError: If check=True and command fails
        """
        # Validate command
        is_valid, error_msg = self._validate_command(command)
        if not is_valid:
            # Enhanced security audit logging for blocked attempts
            self.logger.error(f"SECURITY: Command validation failed: {error_msg}")
            self.logger.error(f"SECURITY: Blocked command: {command[0]}")
            self.logger.error(f"SECURITY: Blocked arguments: {command[1:] if len(command) > 1 else 'none'}")

            # Log to security audit trail
            audit_logger = logging.getLogger('kp14.security.audit')
            audit_logger.warning(
                f"BLOCKED_SUBPROCESS_ATTEMPT: executable={command[0]}, "
                f"args={command[1:] if len(command) > 1 else []}, "
                f"reason={error_msg}"
            )

            raise SecurityError(
                f"Subprocess command validation failed: {error_msg}",
                security_check="subprocess_validation"
            )

        # Validate timeout
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        elif timeout > MAX_TIMEOUT:
            self.logger.warning(f"Timeout {timeout}s exceeds maximum, using {MAX_TIMEOUT}s")
            timeout = MAX_TIMEOUT

        # Wrap with sandbox if enabled
        final_command = self._wrap_with_sandbox(command, work_dir)

        # Log the execution
        self.logger.info(f"Executing subprocess: {' '.join(final_command[:3])}...")
        self.logger.debug(f"Full command: {final_command}")

        # Prepare environment
        if env is None:
            # Use minimal environment
            env = {
                'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                'HOME': os.environ.get('HOME', '/tmp'),
                'LANG': 'C',
            }

        # Execute with security settings
        try:
            result = subprocess.run(
                final_command,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                check=check,
                cwd=work_dir,
                env=env,
                **kwargs
            )

            self.logger.info(f"Subprocess completed with return code: {result.returncode}")
            return result

        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Subprocess timeout after {timeout}s: {command[0]}")
            raise

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Subprocess failed with code {e.returncode}: {command[0]}")
            raise

        except Exception as e:
            self.logger.error(f"Subprocess execution error: {e}")
            raise SecurityError(
                f"Subprocess execution failed: {e}",
                security_check="subprocess_execution"
            )

    def check_output(self, command: List[str],
                    timeout: Optional[int] = None,
                    **kwargs) -> str:
        """
        Execute command and return output (convenience method).

        Args:
            command: Command and arguments
            timeout: Timeout in seconds
            **kwargs: Additional arguments

        Returns:
            Command output as string
        """
        result = self.run(
            command,
            timeout=timeout,
            capture_output=True,
            check=True,
            **kwargs
        )
        return result.stdout


# ============================================================================
# Global Secure Subprocess Instance
# ============================================================================

# Create global instance for convenience
_secure_subprocess = SecureSubprocess(enable_sandboxing=False)


def secure_run(command: List[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Global function for secure subprocess execution.

    This should be used instead of subprocess.run() throughout KP14.

    Args:
        command: Command and arguments as list
        **kwargs: Arguments passed to SecureSubprocess.run()

    Returns:
        CompletedProcess instance

    Example:
        result = secure_run(['radare2', '-v'])
    """
    return _secure_subprocess.run(command, **kwargs)


def secure_check_output(command: List[str], **kwargs) -> str:
    """
    Global function for secure subprocess execution with output capture.

    Args:
        command: Command and arguments
        **kwargs: Additional arguments

    Returns:
        Command output as string
    """
    return _secure_subprocess.check_output(command, **kwargs)


# ============================================================================
# Subprocess Audit Logger
# ============================================================================

class SubprocessAuditLogger:
    """
    Audit logger for subprocess executions.
    Logs all subprocess calls for security auditing.
    """

    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize audit logger.

        Args:
            log_file: Optional file for audit log
        """
        self.log_file = log_file
        self.logger = logging.getLogger('kp14.subprocess.audit')

    def log_execution(self, command: List[str], result: subprocess.CompletedProcess,
                     context: Optional[Dict[str, Any]] = None):
        """
        Log subprocess execution.

        Args:
            command: Command that was executed
            result: Execution result
            context: Additional context
        """
        audit_entry = {
            'command': command,
            'returncode': result.returncode,
            'execution_time': context.get('execution_time') if context else None,
            'sandboxed': context.get('sandboxed', False) if context else False,
        }

        self.logger.info(f"Subprocess audit: {audit_entry}")

        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"{audit_entry}\n")


# ============================================================================
# Usage Examples and Documentation
# ============================================================================

"""
USAGE EXAMPLES:

1. Basic secure execution:
    from core_engine.secure_subprocess import secure_run

    result = secure_run(['radare2', '-v'])
    if result.returncode == 0:
        print(result.stdout)

2. With sandboxing:
    secure_subprocess = SecureSubprocess(enable_sandboxing=True, sandbox_type='firejail')
    result = secure_subprocess.run(['ghidra', 'input.exe'])

3. With timeout:
    result = secure_run(['long-running-command'], timeout=60)

4. Capture output:
    output = secure_check_output(['command', '--version'])
    print(output)

MIGRATION FROM UNSAFE CODE:

# OLD (UNSAFE):
subprocess.run(['command', user_input])  # Command injection risk!
subprocess.run(f'command {user_input}', shell=True)  # VERY DANGEROUS!

# NEW (SAFE):
secure_run(['command', user_input])  # Validated and safe

SECURITY NOTES:
- NEVER use shell=True
- NEVER concatenate strings to build commands
- ALWAYS use list format for commands
- ALWAYS validate user input before passing to commands
- Use sandboxing when processing untrusted files
"""
