# Integration Tests Quick Start Guide

**Quick reference for running KP14 integration tests**

---

## Run All Integration Tests

```bash
# Run all integration tests (excludes Docker/hardware)
pytest tests/integration/ -v

# Run with coverage
pytest tests/integration/ --cov=. --cov-report=html

# Run with performance tracking
pytest tests/integration/ --durations=10
```

---

## Run Specific Test Modules

```bash
# Test 1: Full Pipeline PE Analysis
pytest tests/integration/test_full_pipeline_pe_analysis.py -v

# Test 2: Polyglot Extraction
pytest tests/integration/test_polyglot_extraction.py -v

# Test 3: Steganography Detection
pytest tests/integration/test_steganography_workflow.py -v

# Test 4: Recursive Analysis
pytest tests/integration/test_recursive_analysis.py -v

# Test 5: C2 Extraction
pytest tests/integration/test_c2_extraction_e2e.py -v

# Test 6: Batch Processing
pytest tests/integration/test_batch_processing.py -v

# Test 7: Docker Integration (requires Docker)
pytest tests/integration/test_docker_integration.py -v

# Test 8: Hardware Acceleration (requires NPU/GPU)
pytest tests/integration/test_hardware_acceleration.py -v

# Test 9: Export Formats
pytest tests/integration/test_export_formats.py -v

# Test 10: Error Recovery
pytest tests/integration/test_error_recovery.py -v
```

---

## Run by Markers

```bash
# Run only integration tests
pytest -m integration -v

# Run slow tests only
pytest -m slow -v

# Exclude slow tests
pytest -m "not slow" -v

# Run Docker tests (requires Docker)
pytest -m docker -v

# Run hardware tests (requires NPU/GPU)
pytest -m hardware -v

# Run everything except Docker and hardware
pytest -m "integration and not docker and not hardware" -v
```

---

## Test Results

**Last Run**: 2025-10-02
- **Total Tests**: 74
- **Passed**: 64 (97%)
- **Failed**: 2 (minor, non-critical)
- **Skipped**: 8 (Docker/hardware)
- **Duration**: 4.89s

---

## Common Issues

### Issue: PIL deprecation warnings

**Warning**: `'mode' parameter is deprecated in Pillow 13`

**Fix**: Ignore (non-critical) or update Image.fromarray() calls

### Issue: Empty ZIP detected as 'unknown'

**Status**: Known minor issue
**Impact**: Low
**Fix**: Update file type detection logic

### Issue: Docker tests skipped

**Cause**: Docker not installed
**Fix**: Install Docker and build image:
```bash
docker build -t kp14-test:latest .
```

---

## CI/CD

Integration tests run automatically on:
- Push to `main` or `develop`
- Pull requests to `main`
- Manual workflow dispatch

**GitHub Actions**: `.github/workflows/integration-tests.yml`

---

## Documentation

- **Full Report**: `INTEGRATION_TESTS_REPORT.md`
- **Summary**: `INTEGRATION_TEST_SUMMARY.md`
- **This Guide**: `INTEGRATION_TESTS_QUICKSTART.md`

---

**Quick Help**: `pytest tests/integration/ --help`
