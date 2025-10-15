# KP14 Development Guide

## Code Quality Standards

This project maintains high code quality standards through automated tools and consistent practices.

### Quick Start

```bash
# Install development dependencies
pip install -r requirements.txt
pip install black pylint mypy isort pre-commit bandit pytest

# Install pre-commit hooks (one-time setup)
pre-commit install

# Your commits will now be automatically checked!
```

## Code Formatting

### Black - The Uncompromising Code Formatter

**Configuration:** Line length = 100 characters

```bash
# Format a single file
black main.py

# Format all Python files
black .

# Check without modifying
black --check .
```

**Editor Integration:**
- **VS Code:** Install "Python" extension, enable "Format on Save"
- **PyCharm:** Settings → Tools → Black → Enable
- **Vim:** Use `vim-black` plugin

### isort - Import Statement Sorter

**Configuration:** Profile = black (compatible)

```bash
# Sort imports in a file
isort main.py

# Sort all imports
isort .

# Check only
isort --check-only .
```

**Import Order:**
1. Standard library imports
2. Third-party imports
3. Local application imports

## Linting

### Pylint - Comprehensive Code Analysis

**Target Score:** 9.0/10 or higher

```bash
# Check a single file
pylint main.py

# Check multiple files
pylint main.py keyplug_module_loader.py

# Generate detailed report
pylint main.py --output-format=text > pylint_report.txt

# Check specific error types only
pylint --disable=all --enable=E,F main.py
```

**Common Pylint Messages:**
- **E (Error):** Serious issues that must be fixed
- **W (Warning):** Potential bugs or style issues
- **R (Refactor):** Code complexity issues
- **C (Convention):** PEP 8 style violations

**Acceptable Suppressions:**
```python
# Disable specific check for one line
result = complex_function()  # pylint: disable=line-too-long

# Disable for entire function
def complex_legacy_code():
    # pylint: disable=too-many-branches
    pass
```

### Bandit - Security Linter

```bash
# Scan for security issues
bandit -r .

# Generate report
bandit -r . -f json -o bandit_report.json

# Check specific test
bandit -t B201,B301 main.py
```

**Common Security Issues:**
- B201: Flask debug mode
- B301: Pickle usage
- B303: Insecure MD5/SHA1 usage
- B501: SSL certificate verification

## Type Checking

### MyPy - Static Type Checker

```bash
# Check types
mypy main.py

# Check entire project
mypy .

# Generate HTML report
mypy --html-report mypy_report .
```

**Type Hint Examples:**
```python
from typing import Dict, List, Optional, Union, Any, Tuple

def process_data(
    input_file: str,
    options: Dict[str, Any],
    timeout: Optional[int] = None
) -> Tuple[bool, str]:
    """Process data with type-safe interface."""
    return True, "Success"
```

## Testing

### Pytest

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_module.py

# Run with markers
pytest -m "not slow"
```

**Test Structure:**
```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── security/       # Security tests
└── conftest.py     # Shared fixtures
```

## Pre-commit Hooks

Pre-commit hooks automatically check your code before each commit.

### Installation

```bash
# Install the hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files

# Update hook versions
pre-commit autoupdate
```

### Configured Hooks

1. **Black** - Auto-format code
2. **isort** - Sort imports
3. **Pylint** - Lint code (score must be >7.0)
4. **MyPy** - Type check
5. **Bandit** - Security check
6. **Built-in hooks:**
   - trailing-whitespace
   - end-of-file-fixer
   - check-yaml
   - check-json
   - check-added-large-files
   - debug-statements
   - detect-private-key

### Bypassing Hooks (Use Sparingly!)

```bash
# Skip all hooks (not recommended)
git commit --no-verify

# Skip specific hook
SKIP=pylint git commit -m "message"
```

## Code Review Checklist

Before submitting a PR, ensure:

- [ ] Code formatted with Black
- [ ] Imports sorted with isort
- [ ] Pylint score ≥ 9.0/10
- [ ] No MyPy errors
- [ ] No Bandit security warnings
- [ ] All tests passing
- [ ] Test coverage maintained or increased
- [ ] Documentation updated
- [ ] Commit messages clear and descriptive

## Common Issues and Solutions

### Issue: "Black would reformat"

```bash
# Fix it
black .

# Or auto-fix on commit (pre-commit does this)
```

### Issue: "Import order incorrect"

```bash
# Fix it
isort .
```

### Issue: "Pylint score too low"

1. Run `pylint your_file.py` to see issues
2. Fix errors (E) first
3. Then warnings (W)
4. Refactor (R) if needed
5. Convention (C) issues are lowest priority

### Issue: "MyPy type errors"

```python
# Add type hints
def my_function(arg: str) -> int:
    return len(arg)

# Or ignore specific line (use sparingly)
result = complex_call()  # type: ignore[return-value]
```

### Issue: "Pre-commit hook fails"

```bash
# See what failed
git commit -v

# Fix the issues shown
black .
isort .
pylint file.py

# Try again
git commit
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install black pylint mypy isort pytest
      - name: Format check
        run: black --check .
      - name: Lint
        run: pylint **/*.py --fail-under=9.0
      - name: Type check
        run: mypy .
      - name: Test
        run: pytest --cov=. --cov-fail-under=80
```

## Best Practices

### Function Design

```python
from typing import Dict, Any

def good_function(
    input_path: str,
    config: Dict[str, Any],
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Process input file according to configuration.

    Args:
        input_path: Path to input file
        config: Configuration dictionary
        verbose: Enable verbose output

    Returns:
        Processing results dictionary

    Raises:
        FileNotFoundError: If input_path doesn't exist
        ValueError: If config is invalid

    Example:
        >>> result = good_function("data.txt", {"mode": "fast"})
        >>> print(result["status"])
        "success"
    """
    # Implementation
    pass
```

### Error Handling

```python
# Good - Specific exceptions
try:
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
except FileNotFoundError:
    logger.error(f"File not found: {path}")
    raise
except PermissionError:
    logger.error(f"Permission denied: {path}")
    raise

# Bad - Overly broad
try:
    do_something()
except Exception:  # Too broad!
    pass
```

### File Operations

```python
# Always specify encoding
with open("file.txt", "r", encoding="utf-8") as f:
    content = f.read()

with open("output.txt", "w", encoding="utf-8") as f:
    f.write(content)
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Use appropriate levels
logger.debug("Detailed diagnostic info")
logger.info("General information")
logger.warning("Warning message")
logger.error("Error occurred", exc_info=True)
logger.critical("Critical failure")

# Include context
logger.info("Processing file", extra={"file": path, "size": size})
```

## Performance Profiling

```bash
# Profile script
python -m cProfile -o profile.stats main.py

# View results
python -m pstats profile.stats
> sort cumulative
> stats 20

# Use snakeviz for visual analysis
pip install snakeviz
snakeviz profile.stats
```

## Documentation

### Docstring Format (Google Style)

```python
def complex_function(
    param1: str,
    param2: int,
    param3: Optional[Dict[str, Any]] = None
) -> Tuple[bool, str]:
    """
    One-line summary of function purpose.

    Detailed description of what the function does,
    including any important implementation details.

    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        param3: Optional parameter description.
            Can span multiple lines with proper indentation.

    Returns:
        Tuple of (success flag, message string).
        First element is True if successful.

    Raises:
        ValueError: When param2 is negative
        TypeError: When param1 is not a string

    Example:
        >>> success, msg = complex_function("test", 42)
        >>> print(success)
        True

    Note:
        This function is thread-safe but not process-safe.

    Warning:
        Do not use with untrusted input without validation.
    """
    pass
```

## Resources

### Official Documentation
- [Black](https://black.readthedocs.io/)
- [Pylint](https://pylint.pycqa.org/)
- [MyPy](https://mypy.readthedocs.io/)
- [isort](https://pycqa.github.io/isort/)
- [Pre-commit](https://pre-commit.com/)

### Style Guides
- [PEP 8](https://pep8.org/) - Python Style Guide
- [PEP 257](https://www.python.org/dev/peps/pep-0257/) - Docstring Conventions
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

### Tools
- [Sourcery](https://sourcery.ai/) - AI-powered refactoring
- [Ruff](https://github.com/charliermarsh/ruff) - Fast Python linter
- [pyupgrade](https://github.com/asottile/pyupgrade) - Upgrade syntax

## Getting Help

- **Code Review:** Tag `@team-lead` in PR
- **Style Questions:** Check this guide first, then ask in `#dev-python`
- **Tool Issues:** Check tool documentation, file issue if needed
- **Best Practices:** Consult team wiki or senior developers

---

**Last Updated:** 2025-10-02
**Maintainer:** KP14 Development Team
**Questions?** Open an issue or contact the team lead
