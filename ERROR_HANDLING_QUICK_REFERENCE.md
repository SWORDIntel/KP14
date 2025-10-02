# KP14 Error Handling & Logging - Quick Reference Guide

## Import Statements

```python
# Error handling
from core_engine.error_handler import (
    KP14Error,
    FileValidationError,
    FileSizeError,
    FileFormatError,
    SuspiciousPayloadError,
    HardwareError,
    ModelLoadError,
    AnalysisError,
    NetworkError,
    ResourceExhaustionError,
    ConfigurationError,
    error_context,
    retry_with_backoff,
    ErrorRecoveryManager,
    safe_execute,
    create_error_report
)

# Logging
from core_engine.logging_config import (
    LoggingConfigManager,
    get_logging_manager,
    create_module_logger,
    log_operation,
    log_function_call,
    sanitize_sensitive_data
)

# File validation
from core_engine.file_validator import (
    FileValidator,
    FileType,
    ValidationConfig,
    identify_file_type,
    validate_magic_bytes,
    validate_file_size,
    calculate_entropy,
    calculate_file_hashes,
    quick_validate
)
```

---

## Common Patterns

### Pattern 1: Basic Error Handling

```python
try:
    result = risky_operation()
except Exception as e:
    raise AnalysisError(
        "Operation failed",
        analyzer_name="MyAnalyzer",
        context={"param": value},
        original_exception=e,
        recoverable=True
    )
```

### Pattern 2: Error Context Manager

```python
with error_context(
    "Loading file",
    logger=logger,
    file_path=path,
    fail_fast=False
):
    data = load_file(path)
```

### Pattern 3: Retry with Backoff

```python
@retry_with_backoff(
    max_retries=3,
    initial_delay=1.0,
    backoff_factor=2.0,
    retriable_exceptions=(NetworkError, IOError)
)
def fetch_data():
    return requests.get(url)
```

### Pattern 4: Safe Execution

```python
result = safe_execute(
    func=risky_function,
    args=(arg1, arg2),
    kwargs={"key": "value"},
    default_return=None,
    logger=logger
)
```

### Pattern 5: Logging Setup

```python
# Initialize logging
log_mgr = get_logging_manager(
    log_dir="logs",
    log_level="INFO",
    json_logging=True
)

# Get module logger
logger = log_mgr.get_logger(
    "my_module",
    module_log_file="my_module.log"
)
```

### Pattern 6: Operation Logging

```python
with log_operation(
    "PE Analysis",
    logger=logger,
    level=logging.INFO,
    file_path=path
):
    analyze_pe(path)
```

### Pattern 7: File Validation

```python
# Quick validation
if not quick_validate(file_path, max_size=100*1024*1024):
    raise FileValidationError("Invalid file", file_path)

# Full validation
validator = FileValidator(logger=logger)
report = validator.validate_file(
    file_path,
    expected_type=FileType.PE_EXECUTABLE,
    calculate_hashes=True,
    scan_payloads=True
)
```

---

## Exception Hierarchy

```
Exception
└── KP14Error (base, context preservation)
    ├── FileValidationError
    │   ├── FileSizeError
    │   ├── FileFormatError
    │   └── SuspiciousPayloadError
    ├── HardwareError
    ├── ModelLoadError
    ├── AnalysisError (recoverable=True)
    ├── NetworkError (recoverable=True)
    ├── ResourceExhaustionError
    └── ConfigurationError
```

---

## Log Levels

| Level    | When to Use                           | Example                                    |
|----------|---------------------------------------|--------------------------------------------|
| DEBUG    | Detailed diagnostics                  | "Parsing section at offset 0x1000"         |
| INFO     | Normal operations, milestones         | "Analysis started", "File loaded"          |
| WARNING  | Recoverable issues, degradation       | "Analyzer X failed, continuing"            |
| ERROR    | Operation failures                    | "Failed to load model", "Parse error"      |
| CRITICAL | Fatal errors, system failures         | "Out of memory", "Configuration missing"   |

---

## Logging Best Practices

### DO:
```python
# Use structured logging
logger.info(
    "Analysis completed",
    extra={
        "file_path": path,
        "duration_seconds": 5.2,
        "result_count": 10
    }
)

# Log exceptions with context
logger.error(
    "Analysis failed",
    extra={"file_path": path},
    exc_info=True
)
```

### DON'T:
```python
# Don't use print()
print("Error:", e)  # ❌

# Don't log secrets
logger.info(f"API key: {api_key}")  # ❌

# Don't use string formatting in log calls
logger.info(f"Processing {file_path}")  # ❌
logger.info("Processing %s", file_path)  # ✅
```

---

## Validation Patterns

### Size Validation

```python
from core_engine.file_validator import validate_file_size

try:
    file_size = validate_file_size(
        file_path,
        max_size=500*1024*1024,  # 500 MB
        min_size=100              # 100 bytes
    )
except FileSizeError as e:
    logger.error(f"File too large: {e}")
```

### Type Validation

```python
from core_engine.file_validator import identify_file_type, FileType

# Identify
file_type, confidence = identify_file_type(data, file_path)

if file_type == FileType.PE_EXECUTABLE:
    analyze_pe(file_path)
elif file_type == FileType.PDF:
    analyze_pdf(file_path)
```

### Entropy Analysis

```python
from core_engine.file_validator import calculate_entropy

entropy = calculate_entropy(file_data)

if entropy > 7.5:
    logger.warning("High entropy - file may be encrypted")
elif entropy < 1.0:
    logger.warning("Low entropy - file may be padded")
```

---

## Error Recovery

### Register Recovery Strategy

```python
from core_engine.error_handler import ErrorRecoveryManager

recovery_mgr = ErrorRecoveryManager(logger=logger)

def recover_from_missing_file(error, context):
    logger.warning(f"Using default file: {error}")
    return load_default_file()

recovery_mgr.register_recovery_strategy(
    FileNotFoundError,
    recover_from_missing_file
)

# Use recovery
try:
    data = load_file(path)
except FileNotFoundError as e:
    data = recovery_mgr.handle_error(e, context={"path": path})
```

---

## Configuration

### Logging Configuration

```python
log_mgr = LoggingConfigManager(
    log_dir="logs",              # Log directory
    log_level="INFO",            # Default level
    max_bytes=10*1024*1024,      # 10 MB per file
    backup_count=5,              # Keep 5 backups
    json_logging=True,           # Enable JSON logs
    console_logging=True,        # Enable console
    sanitize_logs=True           # Sanitize sensitive data
)
```

### Validation Configuration

```python
from core_engine.file_validator import ValidationConfig

config = ValidationConfig()
config.MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
config.HIGH_ENTROPY_THRESHOLD = 7.5
config.ENABLE_PAYLOAD_SCAN = True
config.MAX_SCAN_SIZE = 10 * 1024 * 1024

validator = FileValidator(config=config, logger=logger)
```

---

## Testing

### Test Error Handling

```python
def test_custom_exception():
    with pytest.raises(FileValidationError) as exc_info:
        raise FileValidationError("Test", "/test/file")

    assert exc_info.value.context["file_path"] == "/test/file"
```

### Test Logging

```python
def test_logging(caplog):
    logger = create_module_logger("test")
    logger.info("Test message", extra={"key": "value"})

    assert "Test message" in caplog.text
```

### Test Validation

```python
def test_file_validation():
    validator = FileValidator()
    report = validator.validate_file("test.exe")

    assert "validation_passed" in report
    assert "file_info" in report
```

---

## Cheat Sheet

| Task                       | Function/Class                                  |
|----------------------------|-------------------------------------------------|
| Raise custom error         | `raise FileValidationError(msg, path)`          |
| Wrap code with errors      | `with error_context(op, logger=log):`          |
| Retry on failure           | `@retry_with_backoff(max_retries=3)`           |
| Setup logging              | `get_logging_manager(log_dir, log_level)`      |
| Get module logger          | `create_module_logger(name, separate_file=T)`  |
| Log operation              | `with log_operation(name, logger=log):`        |
| Validate file              | `validator.validate_file(path)`                |
| Check file type            | `identify_file_type(data, path)`               |
| Calculate entropy          | `calculate_entropy(data)`                      |
| Calculate hashes           | `calculate_file_hashes(path, ['md5','sha256'])` |
| Quick validation           | `quick_validate(path, max_size=10MB)`          |
| Sanitize log data          | `sanitize_sensitive_data(text)`                |

---

## Exit Codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | Success                              |
| 1    | Fatal error (config, validation)     |
| 2    | Partial failure (analysis errors)    |
| 130  | User interrupt (Ctrl+C)              |

---

## Command Line

```bash
# Basic usage
python main.py sample.exe

# With custom settings
python main.py malware.dll -s custom_settings.ini

# Debug logging
python main.py suspicious.pdf --log-level DEBUG

# Save output to file
python main.py archive.zip --output report.json

# Summary format
python main.py file.exe --format summary

# Custom log directory
python main.py file.exe --log-dir /var/log/kp14
```

---

## Performance Tips

1. **Use INFO level in production** - DEBUG is verbose
2. **Skip validation if pre-validated** - `--no-validation`
3. **Limit hash algorithms** - Only calculate what you need
4. **Use quick_validate()** - For fast checks
5. **Disable JSON logging** - If not needed for parsing
6. **Rotate logs regularly** - Use cleanup utilities

---

**Quick Reference Version:** 1.0
**Last Updated:** 2025-10-02
