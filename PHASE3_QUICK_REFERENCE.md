# Phase 3 Quick Reference Guide
## New Features and Usage Examples

This quick reference guide provides practical examples for using the new Phase 3 features.

---

## 1. Environment Variable Configuration

### Quick Start

```bash
# Override log level
export KP14_GENERAL_LOG_LEVEL=DEBUG

# Override output directory
export KP14_GENERAL_OUTPUT_DIR=/custom/output

# Override PE analyzer settings
export KP14_PE_ANALYZER_MAX_FILE_SIZE_MB=200
export KP14_PE_ANALYZER_ENABLED=true

# Run your analysis
python run_analyzer.py sample.exe
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Set KP14 configuration via environment
ENV KP14_GENERAL_LOG_LEVEL=INFO
ENV KP14_GENERAL_OUTPUT_DIR=/app/output
ENV KP14_PE_ANALYZER_MAX_FILE_SIZE_MB=500

# Copy application
COPY . /app
WORKDIR /app

# Run analysis
CMD ["python", "run_analyzer.py"]
```

### Kubernetes ConfigMap

```yaml
# kp14-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kp14-config
data:
  KP14_GENERAL_LOG_LEVEL: "INFO"
  KP14_GENERAL_OUTPUT_DIR: "/data/output"
  KP14_PE_ANALYZER_MAX_FILE_SIZE_MB: "500"
  KP14_HARDWARE_USE_GPU: "true"
```

---

## 2. Distributed Tracing with Correlation IDs

### Basic Usage

```python
from core_engine.correlation_context import analysis_context

# Wrap your analysis code
with analysis_context("analyze_malware", file_name="sample.exe") as ctx:
    # Your code here
    print(f"Correlation ID: {ctx.correlation_id}")
```

### Nested Operations

```python
from core_engine.correlation_context import analysis_context, add_context_metadata

with analysis_context("main_analysis", sample_id="12345") as main_ctx:
    add_context_metadata(file_size=1024000, file_type="PE")

    # Sub-operation 1
    with analysis_context("extract_strings") as str_ctx:
        strings = extract_strings(data)
        add_context_metadata(string_count=len(strings))

    # Sub-operation 2
    with analysis_context("analyze_imports") as imp_ctx:
        imports = analyze_imports(data)
        add_context_metadata(import_count=len(imports))

    # Sub-operation 3
    with analysis_context("entropy_analysis") as ent_ctx:
        entropy = calculate_entropy(data)
        add_context_metadata(entropy=entropy)
```

### Using the Decorator

```python
from core_engine.correlation_context import traced, add_context_metadata

@traced("process_pe_file")
def process_pe(file_path):
    """Automatically traced function."""
    add_context_metadata(file_path=file_path)
    # Your processing code
    return results

@traced("extract_iocs")
def extract_iocs(pe_data):
    """Another traced function."""
    # IOC extraction code
    return iocs

# Usage
results = process_pe("sample.exe")  # Automatically traced
iocs = extract_iocs(results)         # Also automatically traced
```

### Accessing Correlation Context

```python
from core_engine.correlation_context import (
    get_current_correlation_id,
    add_context_metadata,
    add_context_tags
)

with analysis_context("analysis"):
    # Get current correlation ID
    corr_id = get_current_correlation_id()
    print(f"Current operation ID: {corr_id}")

    # Add metadata
    add_context_metadata(
        detected_malware=True,
        threat_score=8.5,
        family="KeyPlug"
    )

    # Add tags
    add_context_tags("malware", "apt", "keyplug")
```

### Logging with Correlation Context

```python
import logging
from core_engine.correlation_context import analysis_context

logger = logging.getLogger(__name__)

with analysis_context("scan_file", file_name="sample.exe") as ctx:
    # Logs will automatically include correlation_id
    logger.info(
        "Starting file scan",
        extra=ctx.get_log_extra()
    )

    # Log output:
    # 2025-10-02 14:30:45 - module - INFO - [abc-123-def-456] Starting file scan
```

---

## 3. Common Utilities Module

### Hash Calculation

```python
from core_engine.common_utils import (
    calculate_file_hash,
    calculate_multiple_hashes
)

# Single hash
sha256 = calculate_file_hash("/path/to/file.exe", algorithm="sha256")
print(f"SHA256: {sha256}")

# Multiple hashes (efficient - single file read)
hashes = calculate_multiple_hashes(
    "/path/to/file.exe",
    algorithms=["md5", "sha1", "sha256"]
)
print(f"MD5:    {hashes['md5']}")
print(f"SHA1:   {hashes['sha1']}")
print(f"SHA256: {hashes['sha256']}")
```

### Entropy Analysis

```python
from core_engine.common_utils import (
    calculate_shannon_entropy,
    calculate_file_entropy
)

# Calculate entropy of data
data = b"Some binary data..."
entropy = calculate_shannon_entropy(data)
print(f"Entropy: {entropy:.2f}")

# Interpret entropy
if entropy > 7.5:
    print("Data is likely encrypted or compressed")
elif entropy < 1.0:
    print("Data has very low randomness (padding?)")
else:
    print("Normal data entropy")

# Calculate entropy of large file (memory efficient)
entropy = calculate_file_entropy(
    "/path/to/large/file.bin",
    max_bytes=10*1024*1024  # Only scan first 10MB
)
```

### File Validation

```python
from core_engine.common_utils import (
    validate_file_exists,
    validate_file_size,
    read_file_header
)

# Validate file exists and is readable
try:
    path = validate_file_exists("/path/to/file.exe")
    print(f"File exists: {path}")
except FileNotFoundError:
    print("File not found")
except PermissionError:
    print("File is not readable")

# Validate file size
try:
    size = validate_file_size(
        "/path/to/file.exe",
        max_size=100*1024*1024  # 100MB max
    )
    print(f"File size: {size:,} bytes")
except ValueError as e:
    print(f"Size validation failed: {e}")

# Read file header for magic byte detection
header = read_file_header("/path/to/file.exe", num_bytes=16)
if header.startswith(b'MZ'):
    print("PE executable detected")
elif header.startswith(b'\x7fELF'):
    print("ELF executable detected")
```

### Data Formatting

```python
from core_engine.common_utils import (
    format_bytes,
    format_hex,
    safe_get_nested
)

# Format byte counts
print(format_bytes(1536))         # "1.5 KB"
print(format_bytes(1048576))      # "1.0 MB"
print(format_bytes(1073741824))   # "1.0 GB"

# Format hex dump
data = b"Hello, World!"
print(format_hex(data, bytes_per_line=8))
# Output:
# 48 65 6C 6C 6F 2C 20 57
# 6F 72 6C 64 21

# Safely access nested dictionaries
data = {
    'analysis': {
        'pe': {
            'imports': ['kernel32.dll', 'ntdll.dll']
        }
    }
}

imports = safe_get_nested(data, 'analysis', 'pe', 'imports', default=[])
print(imports)  # ['kernel32.dll', 'ntdll.dll']

# Non-existent path returns default
missing = safe_get_nested(data, 'analysis', 'elf', 'sections', default=[])
print(missing)  # []
```

### Path Utilities

```python
from core_engine.common_utils import (
    ensure_directory,
    get_safe_filename
)

# Ensure directory exists (creates if needed)
output_dir = ensure_directory("/path/to/output")
print(f"Output directory ready: {output_dir}")

# Create safe filename
unsafe_name = "file:name?.exe"
safe_name = get_safe_filename(unsafe_name)
print(safe_name)  # "file_name_.exe"

# Truncate long filenames
long_name = "a" * 300 + ".exe"
safe_name = get_safe_filename(long_name, max_length=255)
print(len(safe_name))  # 255
```

---

## 4. Complete Analysis Example

Here's a complete example combining all Phase 3 features:

```python
from core_engine.correlation_context import analysis_context, add_context_metadata
from core_engine.common_utils import (
    validate_file_exists,
    validate_file_size,
    calculate_multiple_hashes,
    calculate_file_entropy,
    format_bytes
)
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - [%(correlation_id)s] - %(message)s'
)
logger = logging.getLogger(__name__)

def analyze_malware_sample(file_path):
    """Complete malware analysis with tracing and utilities."""

    with analysis_context("analyze_malware_sample", file_path=file_path) as ctx:

        # Step 1: Validate file
        with analysis_context("validate_file") as val_ctx:
            try:
                path = validate_file_exists(file_path)
                size = validate_file_size(
                    file_path,
                    max_size=500*1024*1024  # 500MB max
                )
                add_context_metadata(
                    file_size=size,
                    file_size_formatted=format_bytes(size)
                )
                logger.info(f"File validated: {format_bytes(size)}")
            except Exception as e:
                logger.error(f"Validation failed: {e}")
                return None

        # Step 2: Calculate hashes
        with analysis_context("calculate_hashes") as hash_ctx:
            hashes = calculate_multiple_hashes(
                file_path,
                algorithms=['md5', 'sha1', 'sha256']
            )
            add_context_metadata(**hashes)
            logger.info(f"SHA256: {hashes['sha256']}")

        # Step 3: Entropy analysis
        with analysis_context("entropy_analysis") as ent_ctx:
            entropy = calculate_file_entropy(file_path)
            add_context_metadata(entropy=entropy)

            if entropy > 7.5:
                logger.warning("High entropy detected - file may be encrypted")
            elif entropy < 1.0:
                logger.warning("Low entropy detected - file may be padded")
            else:
                logger.info(f"Normal entropy: {entropy:.2f}")

        # Step 4: Further analysis here...
        logger.info("Analysis complete")

        return {
            'file_path': file_path,
            'file_size': size,
            'hashes': hashes,
            'entropy': entropy,
            'correlation_id': ctx.correlation_id
        }

# Usage
if __name__ == "__main__":
    result = analyze_malware_sample("/path/to/sample.exe")
    print(result)
```

---

## 5. Environment Variable Priority

Remember the configuration priority order:

1. **Environment Variables** (highest priority)
2. **settings.ini file**
3. **Default values** (lowest priority)

Example:
```ini
# settings.ini
[general]
log_level = INFO
output_dir = ./output
```

```bash
# Environment variable overrides settings.ini
export KP14_GENERAL_LOG_LEVEL=DEBUG

# When run, will use:
# - log_level: DEBUG (from environment)
# - output_dir: ./output (from settings.ini)
```

---

## 6. Tips and Best Practices

### Correlation Context Best Practices

1. **Use descriptive operation names:**
   ```python
   # Good
   with analysis_context("extract_pe_imports"):

   # Not as good
   with analysis_context("step1"):
   ```

2. **Add meaningful metadata:**
   ```python
   with analysis_context("scan_file") as ctx:
       add_context_metadata(
           file_type="PE",
           architecture="x64",
           detected_threats=3,
           scan_duration_ms=1234
       )
   ```

3. **Use tags for categorization:**
   ```python
   add_context_tags("malware", "apt", "keyplug", "high-confidence")
   ```

### Common Utilities Best Practices

1. **Reuse hash calculations:**
   ```python
   # Good - calculates once
   hashes = calculate_multiple_hashes(file_path)

   # Wasteful - reads file 3 times
   md5 = calculate_file_hash(file_path, 'md5')
   sha1 = calculate_file_hash(file_path, 'sha1')
   sha256 = calculate_file_hash(file_path, 'sha256')
   ```

2. **Validate early:**
   ```python
   # Validate at the start
   validate_file_exists(file_path)
   validate_file_size(file_path, max_size=100*1024*1024)

   # Then proceed with analysis
   ```

3. **Use safe accessors:**
   ```python
   # Good - safe
   value = safe_get_nested(data, 'key1', 'key2', default=None)

   # Risky - can raise KeyError
   value = data['key1']['key2']
   ```

---

## 7. Troubleshooting

### Environment Variables Not Working

**Problem:** Environment variables not being applied

**Solution:**
```bash
# Verify environment variables are set
env | grep KP14_

# Make sure to export (not just set)
export KP14_GENERAL_LOG_LEVEL=DEBUG  # Correct
KP14_GENERAL_LOG_LEVEL=DEBUG         # Won't work

# Check configuration loading
python -c "from core_engine.configuration_manager import ConfigurationManager; \
           config = ConfigurationManager(); \
           print(config.get('general', 'log_level'))"
```

### Correlation IDs Not Appearing in Logs

**Problem:** Log messages don't include correlation IDs

**Solution:**
```python
# Make sure logging format includes correlation_id
logging.basicConfig(
    format='%(asctime)s - [%(correlation_id)s] - %(message)s'
)

# Use extra parameter in logging
logger.info("Message", extra=ctx.get_log_extra())
```

### Import Errors for New Modules

**Problem:** Cannot import common_utils or correlation_context

**Solution:**
```bash
# Make sure you're running from the correct directory
cd /path/to/kp14

# Or use absolute imports
from core_engine.common_utils import calculate_file_hash
```

---

**Quick Reference Version:** 1.0
**Last Updated:** 2025-10-02
**Related:** PHASE3_FINAL_POLISH_REPORT.md
