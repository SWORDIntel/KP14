#!/usr/bin/env python3
"""
Security Test Suite Runner for KP14

Runs all security tests and generates a report.

Usage:
    python run_security_tests.py
    python run_security_tests.py --verbose
    python run_security_tests.py --coverage

Author: KP14 Security Team
"""

import sys
import unittest
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def discover_and_run_tests(verbosity=2, pattern='test_*.py'):
    """
    Discover and run all security tests.

    Args:
        verbosity: Test runner verbosity level
        pattern: Pattern for test file discovery

    Returns:
        TestResult object
    """
    # Get the security tests directory
    test_dir = Path(__file__).parent

    # Create test loader
    loader = unittest.TestLoader()

    # Discover tests
    suite = loader.discover(
        start_dir=str(test_dir),
        pattern=pattern,
        top_level_dir=str(test_dir.parent.parent)
    )

    # Run tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)

    return result


def print_summary(result):
    """Print test summary."""
    print("\n" + "=" * 80)
    print("SECURITY TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 80)

    if result.wasSuccessful():
        print("\n✓ ALL SECURITY TESTS PASSED")
        return 0
    else:
        print("\n✗ SOME SECURITY TESTS FAILED")
        return 1


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Run KP14 security tests')
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Run with coverage analysis (requires coverage.py)'
    )
    parser.add_argument(
        '--pattern', '-p',
        default='test_*.py',
        help='Pattern for test discovery (default: test_*.py)'
    )

    args = parser.parse_args()

    verbosity = 2 if args.verbose else 1

    if args.coverage:
        try:
            import coverage
            cov = coverage.Coverage()
            cov.start()

            result = discover_and_run_tests(verbosity=verbosity, pattern=args.pattern)

            cov.stop()
            cov.save()

            print("\n" + "=" * 80)
            print("COVERAGE REPORT")
            print("=" * 80)
            cov.report()

            # Generate HTML report
            html_dir = Path(__file__).parent / 'coverage_html'
            cov.html_report(directory=str(html_dir))
            print(f"\nHTML coverage report: {html_dir}/index.html")

        except ImportError:
            print("ERROR: coverage.py not installed. Install with: pip install coverage")
            return 1
    else:
        result = discover_and_run_tests(verbosity=verbosity, pattern=args.pattern)

    exit_code = print_summary(result)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
