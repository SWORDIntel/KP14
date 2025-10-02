# Security Scanning Quick Start Guide

## 1-Minute Setup

```bash
# Install security tools
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run initial scan
python scripts/security_scan.py
```

## Daily Workflow

### Before Committing
Pre-commit hooks run automatically:
- ✅ Bandit (code security)
- ✅ detect-secrets (secret detection)
- ✅ safety (on requirements.txt changes)

### Manual Security Scan
```bash
python scripts/security_scan.py
```

### Review Results
```bash
cat security_reports/security_summary_*.txt
```

## Common Commands

### Quick Scans
```bash
# Safety check only
safety check

# pip-audit only
pip-audit

# Bandit only
bandit -r . -ll

# Full comprehensive scan
python scripts/security_scan.py
```

### Update Dependencies
```bash
# Update specific package
pip install package-name==X.Y.Z

# Update all outdated
pip list --outdated | cut -d' ' -f1 | xargs pip install -U

# Re-scan after updates
python scripts/security_scan.py
```

### Pre-commit Hooks
```bash
# Run all hooks manually
pre-commit run --all-files

# Run specific hook
pre-commit run bandit --all-files

# Run pip-audit (manual stage)
pre-commit run pip-audit --hook-stage manual --all-files
```

## Severity Guide

| Level | Action Timeline |
|-------|----------------|
| 🔴 CRITICAL | Fix immediately (24h) |
| 🟠 HIGH | Fix within 1 week |
| 🟡 MEDIUM | Fix within 1 month |
| 🟢 LOW | Fix in next release |

## Current Status

### Dependencies Updated (2025-10-02)
- ✅ Pillow: 10.0.1 → 10.4.0 (CVE-2024-28219, CVE-2023-50447)
- ✅ opencv-python: 4.8.0.76 → 4.10.0.84 (CVE-2024-32462)
- ✅ matplotlib: 3.8.0 → 3.9.2
- ✅ pefile: 2023.2.7 → 2024.8.26
- ✅ pycparser: 2.21 → 2.22
- ✅ capstone: 5.0.1 → 5.0.3

### Current Vulnerability Status
- CRITICAL: 0 ✅
- HIGH: 0 ✅
- MEDIUM: 0 ✅
- LOW: 0 ✅

## Automated Scans

- **Every commit**: Pre-commit hooks
- **Every PR**: GitHub Actions full scan
- **Weekly**: Monday 00:00 UTC deep scan
- **Dependabot**: Weekly dependency updates

## Emergency Response

If CRITICAL vulnerability found:

1. **Identify**: Review scan report
2. **Research**: Check CVE database
3. **Update**: Install secure version
4. **Test**: Run test suite
5. **Deploy**: Update production
6. **Verify**: Re-scan

```bash
# Emergency fix workflow
pip install package-name==SAFE_VERSION
pytest tests/ -v
python scripts/security_scan.py
```

## Getting Help

- 📖 **Full Guide**: SECURITY_SCANNING.md
- 📊 **Scan Report**: DEPENDENCY_SCAN_REPORT.md
- 📋 **Summary**: PHASE2_FIX6_SECURITY_SCANNING.md

## Critical Files

```
kp14/
├── requirements-dev.txt          # Security tools
├── scripts/security_scan.py      # Scan script
├── .github/
│   ├── workflows/
│   │   └── security-scan.yml     # CI/CD automation
│   └── dependabot.yml            # Auto-updates
├── .pre-commit-config.yaml       # Pre-commit hooks
├── .secrets.baseline             # Secret detection baseline
└── SECURITY_SCANNING.md          # Full documentation
```

## Quick Checks

```bash
# Verify installation
safety --version && pip-audit --version && bandit --version

# Check for outdated packages
pip list --outdated

# View last scan results
ls -lt security_reports/ | head -5

# Check GitHub Actions status
gh run list --workflow=security-scan.yml --limit 5
```

---

**Last Updated**: 2025-10-02
**Status**: All critical vulnerabilities remediated
**Next Review**: 2025-11-02
