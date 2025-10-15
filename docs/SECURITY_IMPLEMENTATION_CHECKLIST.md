# Security Implementation Checklist

**Status:** Hardening Complete - Ready for Integration
**Date:** 2025-10-02
**Priority:** HIGH

This checklist guides the integration of security hardening into existing KP14 code.

---

## Phase 1: Immediate Actions (Do This Now)

### 1.1 Environment Setup
- [x] Review `.env.example`
- [ ] Copy to `.env`: `cp .env.example .env`
- [ ] Add your credentials to `.env`
- [ ] Verify permissions: `chmod 600 .env`
- [ ] Confirm `.env` in `.gitignore`

### 1.2 Review Security Modules
- [x] Read `core_engine/SECURITY_README.md`
- [x] Review `core_engine/security_utils.py`
- [x] Review `core_engine/secure_subprocess.py`
- [x] Review `docs/SECURITY.md`

### 1.3 Run Security Tests
```bash
cd tests/security
python run_security_tests.py --verbose
```
- [ ] All tests pass
- [ ] Review any failures
- [ ] Fix issues if found

---

## Phase 2: Code Migration (High Priority)

### 2.1 Update Subprocess Calls

**Files to Update:**

#### File: `stego-analyzer/utils/decompiler_integration.py`
**Lines:** 76, 232, 248, 315, 360

```python
# Add import at top of file
from core_engine.secure_subprocess import secure_run

# Replace each subprocess.run() with secure_run()
# Example:
# OLD: result = subprocess.run(["retdec-decompiler", "--version"], ...)
# NEW: result = secure_run(["retdec-decompiler", "--version"], timeout=60)
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

#### File: `stego-analyzer/analysis/code_intent_classifier.py`
**Line:** 531

```python
# Add import
from core_engine.secure_subprocess import secure_run

# Replace:
# OLD: result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
# NEW: result = secure_run(cmd, timeout=300, check=True)
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 2.2 Add Path Validation

**Files to Update:**

#### File: `main.py`
**Already Has Validation:** ✅ (uses FileValidator)

Verify SecurityValidator is used:
```python
from core_engine.security_utils import SecurityValidator
```

**Status:** [ ] Verified

---

#### File: `api_server.py`
**Lines:** 160-170 (file upload handling)

```python
# Add at top
from core_engine.security_utils import SecurityValidator

# In analyze_file() function, add validation:
validator = SecurityValidator(base_directory=temp_dir)
try:
    report = validator.validate_file(str(temp_file))
    if not report['validation_passed']:
        raise HTTPException(status_code=400, detail="File validation failed")
except FileValidationError as e:
    raise HTTPException(status_code=400, detail=str(e))

# Then proceed with analysis
result = pipeline_manager.run_pipeline(str(temp_file))
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

#### File: `batch_analyzer.py`
**Lines:** 269-286 (file analysis)

```python
# Add import
from core_engine.security_utils import SecurityValidator

# In _analyze_file_worker(), add validation before analysis:
validator = SecurityValidator()
try:
    report = validator.validate_file(file_path)
    if not report['validation_passed']:
        return {
            'file_path': file_path,
            'error': 'Validation failed',
            'threat_assessment': {'level': 'error'}
        }
except Exception as e:
    return {
        'file_path': file_path,
        'error': f'Validation error: {e}',
        'threat_assessment': {'level': 'error'}
    }

# Then run pipeline
result = _worker_pipeline_manager.run_pipeline(file_path)
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 2.3 Update Configuration Files

#### File: `settings.ini`
Add security section:

```ini
[security]
enable_sandboxing = false  # Set to true if firejail installed
sandbox_type = firejail
max_file_size_mb = 500
allowed_base_directory = /opt/kp14/samples

[path_validation]
block_system_paths = true
enforce_base_directory = true

[subprocess_security]
timeout_default_seconds = 300
timeout_max_seconds = 1800
enable_audit_logging = true
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

## Phase 3: Testing & Verification

### 3.1 Unit Testing
- [ ] Run: `python tests/security/run_security_tests.py`
- [ ] Verify all 25+ tests pass
- [ ] Review any warnings

### 3.2 Integration Testing
- [ ] Test file analysis with valid samples
- [ ] Test with various file types (PE, images, archives)
- [ ] Test path traversal attempts (should be blocked)
- [ ] Test oversized files (should be rejected)
- [ ] Test command injection attempts (should be blocked)

### 3.3 Manual Testing
```bash
# Test 1: Valid file analysis
python main.py samples/valid.exe

# Test 2: Path traversal (should fail)
python main.py ../../../etc/passwd

# Test 3: Oversized file (should fail)
dd if=/dev/zero of=huge.bin bs=1M count=1000
python main.py huge.bin

# Test 4: Subprocess security
# (Code review - ensure no shell=True usage)
grep -r "shell=True" .
```

**Results:**
- Test 1: [ ] Pass [ ] Fail
- Test 2: [ ] Blocked [ ] Not Blocked
- Test 3: [ ] Rejected [ ] Not Rejected
- Test 4: [ ] No instances [ ] Found instances

---

## Phase 4: Documentation Updates

### 4.1 Update README.md
Add security section:

```markdown
## Security

KP14 processes potentially malicious files and requires careful security configuration.

### Key Security Features
- Input validation and path traversal protection
- Command injection prevention
- Sandboxing support (firejail, bubblewrap)
- Resource limits and timeouts
- Comprehensive security testing

### Secure Configuration
See [docs/SECURITY.md](docs/SECURITY.md) for:
- Threat model
- Production deployment guide
- Security best practices
- Incident response procedures

### Reporting Security Issues
Please report security vulnerabilities responsibly. See [docs/SECURITY.md](docs/SECURITY.md#responsible-disclosure) for details.
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 4.2 Update Installation Docs
Add security setup:

```markdown
## Security Setup

1. **Configure secrets:**
   ```bash
   cp .env.example .env
   nano .env  # Add your API keys
   chmod 600 .env
   ```

2. **Install sandboxing (recommended):**
   ```bash
   # Ubuntu/Debian
   sudo apt install firejail

   # Enable in settings.ini
   [security]
   enable_sandboxing = true
   ```

3. **Run security tests:**
   ```bash
   python tests/security/run_security_tests.py
   ```
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

## Phase 5: Production Deployment

### 5.1 Docker Security
Update `Dockerfile`:

```dockerfile
# Run as non-root user
RUN useradd -m -u 1000 kp14
USER kp14

# Secure permissions
RUN chmod 700 /app && \
    chmod 600 /app/.env

# Security options in docker-compose.yml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 5.2 Monitoring Setup
Set up security monitoring:

```bash
# Log monitoring
tail -f logs/kp14.log | grep -i "security\|violation\|blocked"

# Failed validation tracking
watch "grep 'validation failed' logs/*.log | wc -l"

# Resource monitoring
watch -n 5 'docker stats kp14'
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 5.3 Firewall Configuration
Configure network security:

```bash
# UFW (Ubuntu)
ufw enable
ufw default deny incoming
ufw default deny outgoing
ufw allow from 10.0.0.0/8 to any port 8000  # API if needed

# Docker
# Add to docker-compose.yml:
networks:
  kp14_internal:
    driver: bridge
    internal: true  # No external access
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

## Phase 6: Ongoing Security

### 6.1 Regular Tasks
Set up scheduled tasks:

```bash
# Weekly security test (add to crontab)
0 0 * * 0 cd /opt/kp14 && python tests/security/run_security_tests.py

# Weekly dependency scan
0 2 * * 0 cd /opt/kp14 && safety check

# Monthly credential rotation reminder
0 9 1 * * echo "Rotate KP14 credentials" | mail -s "Security Reminder" admin@example.com
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

### 6.2 Security Scanning
Set up automated scanning:

```bash
# Install tools
pip install bandit safety

# Run scans
bandit -r . -f json -o security-report.json
safety check --json > dependency-report.json

# Add to CI/CD pipeline
```

**Status:** [ ] Not Started [ ] In Progress [ ] Complete

---

## Verification Checklist

Before marking complete, verify:

- [ ] All security modules reviewed and understood
- [ ] Environment file (.env) created and secured
- [ ] All subprocess calls migrated to `secure_run()`
- [ ] Path validation added to file handling code
- [ ] Settings.ini updated with security options
- [ ] All security tests pass
- [ ] Integration testing completed
- [ ] Documentation updated
- [ ] Docker security configured (if using Docker)
- [ ] Monitoring set up
- [ ] Firewall configured
- [ ] Team trained on security practices

---

## Success Criteria

✅ **Complete when:**
1. All security tests pass (25/25)
2. No `subprocess.run()` with `shell=True` in codebase
3. All file operations use `SecurityValidator`
4. `.env` file configured and secured
5. Production deployment uses Docker with security options
6. Documentation updated
7. Team review completed

---

## Support & Questions

- **Security Documentation:** `/docs/SECURITY.md`
- **Module Reference:** `/core_engine/SECURITY_README.md`
- **Test Suite:** `/tests/security/`
- **Summary Report:** `/SECURITY_HARDENING_SUMMARY.md`

For security issues: security@kp14.dev (or project maintainer)

---

**Checklist Version:** 1.0.0
**Last Updated:** 2025-10-02
**Next Review:** After implementation completion
