# Security Modules - Quick Reference

This directory contains critical security modules for KP14. **Read this before using these modules.**

## Overview

| Module | Purpose | Security Level |
|--------|---------|----------------|
| `security_utils.py` | Input validation, sanitization | CRITICAL |
| `secure_subprocess.py` | Command injection prevention | CRITICAL |
| `error_handler.py` | Secure exception handling | HIGH |
| `logging_config.py` | Sanitized logging | HIGH |

## Quick Start

### 1. Validate File Paths

```python
from core_engine.security_utils import SecurityValidator

# Create validator with base directory restriction
validator = SecurityValidator(base_directory='/safe/directory')

# Validate file before processing
try:
    report = validator.validate_file('/safe/directory/sample.exe')
    if report['validation_passed']:
        # Safe to process
        process_file(report['file_path'])
except FileValidationError as e:
    logger.error(f"Validation failed: {e}")
```

### 2. Execute Subprocess Safely

```python
from core_engine.secure_subprocess import secure_run

# Safe subprocess execution
try:
    result = secure_run(['radare2', '-v'], timeout=60)
    print(result.stdout)
except SecurityError as e:
    logger.error(f"Command blocked: {e}")
```

### 3. Sanitize Filenames

```python
from core_engine.security_utils import PathValidator

# Sanitize user-provided filename
safe_filename = PathValidator.sanitize_filename(user_input)
```

### 4. Validate IP Addresses

```python
from core_engine.security_utils import InputSanitizer

# Validate IP before using
ip = InputSanitizer.sanitize_ip_address(user_provided_ip)
if ip:
    # Safe to use
    query_threat_intel(ip)
```

## Security Rules

### ✅ DO

- **Always validate file paths** before opening files
- **Use `secure_run()` for all subprocess calls**
- **Check function return values** for validation results
- **Handle `SecurityError` exceptions** appropriately
- **Use base directory restrictions** when possible
- **Enable sandboxing** for untrusted executables

### ❌ DON'T

- **Never use `subprocess.run()` directly** - use `secure_run()`
- **Never use `shell=True`** in subprocess calls
- **Never trust user input** without validation
- **Never concatenate strings** to build file paths
- **Never ignore validation errors** - fail safely
- **Never expose raw exception messages** to users

## Common Pitfalls

### Path Traversal

```python
# ❌ BAD - Vulnerable to path traversal
file_path = user_input
with open(file_path, 'r') as f:
    data = f.read()

# ✅ GOOD - Validated and safe
validator = SecurityValidator(base_directory='/allowed')
report = validator.validate_file(user_input)
if report['validation_passed']:
    with open(user_input, 'r') as f:
        data = f.read()
```

### Command Injection

```python
# ❌ BAD - Command injection risk
os.system(f'radare2 {user_file}')

# ✅ GOOD - Validated and safe
from core_engine.secure_subprocess import secure_run
secure_run(['radare2', user_file])
```

### Information Leakage

```python
# ❌ BAD - Exposes system paths
except Exception as e:
    return {"error": str(e)}

# ✅ GOOD - Sanitized error message
except Exception as e:
    logger.error("Operation failed", exc_info=True)
    return {"error": "Operation failed"}
```

## Testing Your Code

Run security tests to verify your changes:

```bash
# Run all security tests
python tests/security/run_security_tests.py

# Run specific test category
python -m unittest tests.security.test_path_validation

# Run with coverage
python tests/security/run_security_tests.py --coverage
```

## Migration Guide

### Updating Existing Code

1. **Find unsafe subprocess calls:**
   ```bash
   grep -r "subprocess\.run\|subprocess\.call\|subprocess\.Popen" .
   ```

2. **Replace with secure wrapper:**
   ```python
   # Before
   result = subprocess.run(['command', arg], capture_output=True)

   # After
   from core_engine.secure_subprocess import secure_run
   result = secure_run(['command', arg])
   ```

3. **Add validation to file operations:**
   ```python
   # Before
   with open(file_path, 'r') as f:
       data = f.read()

   # After
   from core_engine.security_utils import SecurityValidator
   validator = SecurityValidator(base_directory='/safe')
   report = validator.validate_file(file_path)
   if report['validation_passed']:
       with open(file_path, 'r') as f:
           data = f.read()
   ```

## API Reference

### PathValidator

| Method | Purpose |
|--------|---------|
| `is_safe_path(path, base_dir)` | Check if path is safe |
| `sanitize_filename(name)` | Remove dangerous characters |
| `validate_file_path(path, must_exist, allowed_base)` | Comprehensive validation |

### FileSizeValidator

| Method | Purpose |
|--------|---------|
| `validate_size(path, max_size, file_type)` | Check file size |

### MagicByteValidator

| Method | Purpose |
|--------|---------|
| `validate_magic_bytes(path, expected_type)` | Validate file type |

### CommandValidator

| Method | Purpose |
|--------|---------|
| `is_safe_command(cmd)` | Check if command is safe |
| `sanitize_command_args(args)` | Sanitize arguments |

### SecureSubprocess

| Method | Purpose |
|--------|---------|
| `run(command, timeout, ...)` | Execute command safely |
| `check_output(command, ...)` | Execute and capture output |

### SecurityValidator

| Method | Purpose |
|--------|---------|
| `validate_file(path, expected_type, check_magic)` | Full validation |

## Support

- **Security Issues:** See `/docs/SECURITY.md` for responsible disclosure
- **Documentation:** See `/docs/SECURITY.md` for complete security guide
- **Tests:** See `/tests/security/` for test examples

## Version History

- **1.0.0** (2025-10-02): Initial security hardening implementation
