# Security Scanning Guide for KP14

## Overview

This document describes the automated security scanning infrastructure implemented for the KP14 project. The security scanning system monitors dependencies for vulnerabilities (CVEs), performs static code analysis, and detects potential security issues.

## Table of Contents

1. [Security Tools](#security-tools)
2. [Running Scans Locally](#running-scans-locally)
3. [Automated CI/CD Scanning](#automated-cicd-scanning)
4. [Interpreting Results](#interpreting-results)
5. [Remediation Procedures](#remediation-procedures)
6. [Exception Policy](#exception-policy)
7. [Continuous Monitoring](#continuous-monitoring)

## Security Tools

The KP14 project uses multiple security scanning tools to provide comprehensive coverage:

### 1. Safety
- **Purpose**: Check for known CVEs in Python dependencies
- **Database**: PyUp.io vulnerability database
- **Coverage**: ~50,000+ known vulnerabilities
- **Installation**: `pip install safety>=3.0.0`

### 2. pip-audit
- **Purpose**: Audit Python packages for known vulnerabilities
- **Database**: OSV (Open Source Vulnerabilities) database
- **Coverage**: Multiple vulnerability databases including PyPI Advisory Database
- **Installation**: `pip install pip-audit>=2.6.0`

### 3. Bandit
- **Purpose**: Static security analysis for Python code
- **Coverage**: Common security issues (SQL injection, hardcoded passwords, etc.)
- **Installation**: `pip install bandit[toml]>=1.7.5`

### 4. Semgrep (Optional)
- **Purpose**: Advanced pattern-based security scanning
- **Coverage**: Security patterns, secrets, best practices
- **Usage**: Integrated in GitHub Actions for weekly deep scans

### 5. detect-secrets
- **Purpose**: Prevent secrets from being committed to version control
- **Coverage**: API keys, passwords, tokens, certificates
- **Integration**: Pre-commit hook

## Running Scans Locally

### Quick Start

1. **Install security tools:**
   ```bash
   pip install -r requirements-dev.txt
   ```

2. **Run comprehensive scan:**
   ```bash
   python scripts/security_scan.py
   ```

3. **Review results:**
   ```bash
   cat security_reports/security_summary_*.txt
   ```

### Individual Tool Usage

#### Safety Check
```bash
# Basic scan
safety check

# JSON output
safety check --json

# Continue on error (don't fail on vulnerabilities)
safety check --continue-on-error

# Save report
safety check --json --save-json safety_report.json
```

#### pip-audit
```bash
# Basic scan
pip-audit

# JSON output
pip-audit --format json

# Skip editable packages
pip-audit --skip-editable

# Fix vulnerabilities automatically (when possible)
pip-audit --fix
```

#### Bandit
```bash
# Scan entire project
bandit -r .

# Only HIGH and MEDIUM severity
bandit -r . -ll

# JSON output
bandit -r . -f json -o bandit_results.json

# Exclude specific directories
bandit -r . --exclude ./tests,./venv
```

#### Comprehensive Scan Script
```bash
# Run all scans with default settings
python scripts/security_scan.py

# Specify output directory
python scripts/security_scan.py --output-dir /path/to/reports

# JSON format output
python scripts/security_scan.py --format json

# Scan specific directory
python scripts/security_scan.py --scan-dir /path/to/code
```

### Exit Codes

The security scan script uses the following exit codes:

- `0`: No vulnerabilities found
- `1`: LOW severity issues found
- `2`: MEDIUM severity issues found
- `3`: HIGH severity issues found
- `4`: CRITICAL severity issues found

## Automated CI/CD Scanning

### GitHub Actions Workflow

The project includes a comprehensive GitHub Actions workflow (`.github/workflows/security-scan.yml`) that runs:

#### Trigger Events

1. **Push to main/develop branches**: Immediate scan on code changes
2. **Pull requests**: Scan PR changes before merge
3. **Weekly schedule**: Every Monday at 00:00 UTC
4. **Manual dispatch**: On-demand scans via GitHub UI

#### Scan Jobs

1. **dependency-scan**: CVE checking with Safety and pip-audit
2. **code-security-scan**: Static analysis with Bandit
3. **comprehensive-scan**: Full security audit
4. **semgrep-scan**: Advanced pattern detection (weekly/manual only)

#### Viewing Results

1. Navigate to **Actions** tab in GitHub
2. Select **Security Scan** workflow
3. Click on the specific run
4. Download artifacts:
   - `dependency-scan-results`
   - `bandit-scan-results`
   - `comprehensive-security-scan`

### Pre-commit Hooks

Security checks run automatically before each commit:

#### Setup
```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install
```

#### Hooks Included

1. **bandit**: Static security analysis
2. **safety-check**: CVE checking (on requirements.txt changes)
3. **pip-audit**: Dependency audit (manual stage)
4. **detect-secrets**: Secret detection

#### Running Manual Hooks
```bash
# Run pip-audit manually
pre-commit run pip-audit --hook-stage manual --all-files

# Run all hooks
pre-commit run --all-files

# Run specific hook
pre-commit run bandit --all-files
```

## Interpreting Results

### Severity Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **CRITICAL** | Immediate exploit risk, active exploitation | Fix immediately (24h) |
| **HIGH** | Significant security risk | Fix within 1 week |
| **MEDIUM** | Moderate security concern | Fix within 1 month |
| **LOW** | Minor security issue | Fix in next release |
| **INFO** | Informational, best practice | Consider for improvement |

### Common Vulnerability Types

#### Dependency Vulnerabilities

**Example Safety Output:**
```json
{
  "package": "pillow",
  "installed_version": "10.0.1",
  "vulnerable_spec": "<10.2.0",
  "advisory": "CVE-2024-XXXXX: Buffer overflow in image processing",
  "severity": "HIGH"
}
```

**Action**: Update to safe version (`pip install pillow>=10.2.0`)

#### Code Security Issues

**Example Bandit Output:**
```json
{
  "test_id": "B105",
  "test_name": "hardcoded_password_string",
  "issue_severity": "MEDIUM",
  "issue_confidence": "MEDIUM",
  "filename": "config.py",
  "line_number": 42,
  "issue_text": "Possible hardcoded password: 'secret123'"
}
```

**Action**: Use environment variables or secrets management

### False Positives

Some findings may be false positives. To suppress:

#### Bandit False Positives
```python
# nosec: Add inline comment to suppress
password = get_password_from_env()  # nosec B105

# Or use configuration in pyproject.toml
```

#### Safety False Positives
Create `.safety-policy.yml`:
```yaml
security:
  ignore-vulnerabilities:
    - id: 12345
      reason: "Not applicable to our use case"
      expires: "2025-12-31"
```

## Remediation Procedures

### Step 1: Identify Vulnerabilities

Run the comprehensive scan:
```bash
python scripts/security_scan.py
```

### Step 2: Prioritize by Severity

1. Review `security_reports/security_summary_*.txt`
2. Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
3. Check CVE databases for exploit availability

### Step 3: Update Dependencies

For dependency vulnerabilities:

```bash
# Check current version
pip show package-name

# Update to latest safe version
pip install --upgrade package-name

# Or specify exact version
pip install package-name==1.2.3

# Update requirements.txt
pip freeze | grep package-name >> requirements.txt
```

### Step 4: Test Compatibility

After updating dependencies:

```bash
# Run test suite
pytest tests/

# Run integration tests
python -m pytest tests/integration/

# Check for breaking changes
python -m pytest tests/ -v
```

### Step 5: Document Changes

Update `CHANGELOG.md`:
```markdown
## [Version] - Date

### Security
- Updated Pillow from 10.0.1 to 10.2.0 (CVE-2024-XXXXX)
- Fixed hardcoded credentials in config module
```

### Step 6: Verify Fix

Re-run security scan:
```bash
python scripts/security_scan.py
```

Confirm vulnerability is resolved.

## Exception Policy

### When to Grant Exceptions

Exceptions may be granted when:

1. **False Positive**: Confirmed false positive after analysis
2. **No Fix Available**: No patch available and risk is mitigated
3. **Breaking Changes**: Fix would break critical functionality
4. **Not Applicable**: Vulnerability doesn't affect our usage

### Exception Process

1. **Document the vulnerability**
   - CVE ID or Bandit test ID
   - Affected component
   - Why exception is needed

2. **Create exception file**

For Safety:
```yaml
# .safety-policy.yml
security:
  ignore-vulnerabilities:
    - id: CVE-2024-XXXXX
      reason: "Vulnerability in unused feature"
      expires: "2025-12-31"
```

For Bandit:
```toml
# pyproject.toml
[tool.bandit]
exclude_dirs = ["tests"]
skips = ["B101"]  # assert_used
```

3. **Get approval**
   - Security team review
   - Document in `SECURITY_EXCEPTIONS.md`
   - Set expiration date

4. **Regular review**
   - Review exceptions quarterly
   - Check if fixes are now available
   - Remove expired exceptions

## Continuous Monitoring

### Automated Scanning Schedule

1. **Every commit**: Pre-commit hooks (Bandit, detect-secrets)
2. **Every PR**: Full dependency + code scan
3. **Every push to main**: Comprehensive scan
4. **Weekly (Monday)**: Deep scan with Semgrep
5. **On-demand**: Manual workflow dispatch

### GitHub Dependabot

Enable Dependabot for automatic dependency updates:

1. Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

2. Dependabot will:
   - Check for updates weekly
   - Create PRs for vulnerable dependencies
   - Include CVE information in PR description

### Notification Channels

Configure notifications for security findings:

1. **GitHub Actions**: Email on workflow failure
2. **Slack Integration**: Post alerts to security channel
3. **Email Alerts**: Critical vulnerabilities only

Example Slack notification (GitHub Actions):
```yaml
- name: Send Slack notification
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    text: 'Security scan failed! Check results.'
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### Metrics and Reporting

Track security metrics over time:

1. **Vulnerability count trend**: Track CRITICAL/HIGH over time
2. **Mean time to remediation**: Average time to fix vulnerabilities
3. **Scan coverage**: Percentage of code scanned
4. **Exception rate**: Number of active exceptions

Generate monthly security report:
```bash
# Run comprehensive scan
python scripts/security_scan.py

# Extract metrics
cat security_reports/security_summary_*.txt
```

## Best Practices

1. **Never commit secrets**: Use environment variables
2. **Update dependencies regularly**: Don't wait for vulnerabilities
3. **Review scan results weekly**: Don't ignore warnings
4. **Test after updates**: Ensure compatibility
5. **Document exceptions**: Always document why
6. **Set expiration dates**: Review exceptions regularly
7. **Monitor security advisories**: Subscribe to security mailing lists
8. **Use virtual environments**: Isolate project dependencies
9. **Pin versions**: Use exact versions in production
10. **Scan before deployment**: Always scan before releasing

## Troubleshooting

### Common Issues

**Issue**: `safety check` fails with connection error
**Solution**: Check internet connection or use `--proxy` flag

**Issue**: `pip-audit` reports many vulnerabilities
**Solution**: Update all dependencies: `pip list --outdated | cut -d' ' -f1 | xargs pip install -U`

**Issue**: Bandit reports too many false positives
**Solution**: Configure exclusions in `pyproject.toml`

**Issue**: Pre-commit hooks are slow
**Solution**: Disable pip-audit in pre-commit, run manually instead

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [CVE Database](https://cve.mitre.org/)
- [PyPI Advisory Database](https://github.com/pypa/advisory-database)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Safety Documentation](https://docs.pyup.io/docs/safety-20-using-the-cli)

## Support

For security questions or to report vulnerabilities:

- **Email**: security@kp14-project.org
- **GitHub Issues**: Use `security` label
- **Emergency**: Contact security team directly

---

**Last Updated**: 2025-10-02
**Version**: 1.0.0
**Maintained by**: KP14 Security Team
