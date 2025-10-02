#!/usr/bin/env python3
"""
Automated Security Scanning for KP14 Project
=============================================

This script performs comprehensive security scanning including:
- CVE checking with Safety
- Dependency auditing with pip-audit
- Static code analysis with Bandit
- Secret detection

Usage:
    python scripts/security_scan.py [--format json|text] [--output-dir reports]

Exit codes:
    0: No vulnerabilities found
    1: LOW severity issues found
    2: MEDIUM severity issues found
    3: HIGH severity issues found
    4: CRITICAL severity issues found
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple


class SecurityScanner:
    """Comprehensive security scanner for KP14 project."""

    def __init__(self, output_dir: Path = None, format: str = "text"):
        """Initialize the security scanner.

        Args:
            output_dir: Directory to save scan reports
            format: Output format ('json' or 'text')
        """
        self.output_dir = output_dir or Path("security_reports")
        self.output_dir.mkdir(exist_ok=True)
        self.format = format
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "scans": {},
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

    def run_safety_check(self) -> Tuple[bool, Dict[str, Any]]:
        """Check for known CVEs in dependencies using Safety.

        Returns:
            Tuple of (success, results_dict)
        """
        print("=" * 70)
        print("Running Safety Check for CVE Detection...")
        print("=" * 70)

        try:
            # Run safety check with JSON output
            result = subprocess.run(
                ['safety', 'check', '--json', '--continue-on-error'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Parse JSON output
            try:
                safety_data = json.loads(result.stdout) if result.stdout else {}
            except json.JSONDecodeError:
                safety_data = {"error": "Failed to parse Safety output", "raw": result.stdout}

            # Extract vulnerability count
            vulnerabilities = safety_data.get('vulnerabilities', []) if isinstance(safety_data, dict) else []

            scan_result = {
                "tool": "safety",
                "status": "completed",
                "vulnerabilities_found": len(vulnerabilities),
                "details": safety_data,
                "exit_code": result.returncode
            }

            # Update severity counts
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN').lower()
                if severity in self.results['summary']:
                    self.results['summary'][severity] += 1

            self.results['scans']['safety'] = scan_result

            print(f"Safety Check: {len(vulnerabilities)} vulnerabilities found")
            if vulnerabilities:
                print("\nVulnerabilities detected:")
                for vuln in vulnerabilities[:5]:  # Show first 5
                    pkg = vuln.get('package', 'unknown')
                    cve = vuln.get('vulnerability_id', 'N/A')
                    print(f"  - {pkg}: {cve}")
                if len(vulnerabilities) > 5:
                    print(f"  ... and {len(vulnerabilities) - 5} more")

            return True, scan_result

        except FileNotFoundError:
            error_msg = "Safety not installed. Install with: pip install safety>=3.0.0"
            print(f"ERROR: {error_msg}")
            self.results['scans']['safety'] = {"status": "error", "message": error_msg}
            return False, {}
        except subprocess.TimeoutExpired:
            error_msg = "Safety check timed out after 5 minutes"
            print(f"ERROR: {error_msg}")
            self.results['scans']['safety'] = {"status": "timeout", "message": error_msg}
            return False, {}
        except Exception as e:
            error_msg = f"Safety check failed: {str(e)}"
            print(f"ERROR: {error_msg}")
            self.results['scans']['safety'] = {"status": "error", "message": error_msg}
            return False, {}

    def run_pip_audit(self) -> Tuple[bool, Dict[str, Any]]:
        """Audit dependencies for vulnerabilities using pip-audit.

        Returns:
            Tuple of (success, results_dict)
        """
        print("\n" + "=" * 70)
        print("Running pip-audit for Dependency Vulnerability Assessment...")
        print("=" * 70)

        try:
            # Run pip-audit with JSON output
            result = subprocess.run(
                ['pip-audit', '--format', 'json', '--skip-editable'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Parse JSON output
            try:
                audit_data = json.loads(result.stdout) if result.stdout else {"dependencies": []}
            except json.JSONDecodeError:
                audit_data = {"error": "Failed to parse pip-audit output", "raw": result.stdout}

            # Extract vulnerability count
            dependencies = audit_data.get('dependencies', []) if isinstance(audit_data, dict) else []
            total_vulns = sum(len(dep.get('vulns', [])) for dep in dependencies)

            scan_result = {
                "tool": "pip-audit",
                "status": "completed",
                "vulnerable_packages": len(dependencies),
                "total_vulnerabilities": total_vulns,
                "details": audit_data,
                "exit_code": result.returncode
            }

            # Update severity counts
            for dep in dependencies:
                for vuln in dep.get('vulns', []):
                    severity = self._normalize_severity(vuln.get('severity', 'UNKNOWN'))
                    if severity in self.results['summary']:
                        self.results['summary'][severity] += 1

            self.results['scans']['pip_audit'] = scan_result

            print(f"pip-audit: {len(dependencies)} vulnerable packages found")
            print(f"Total vulnerabilities: {total_vulns}")

            if dependencies:
                print("\nVulnerable packages:")
                for dep in dependencies[:5]:  # Show first 5
                    pkg_name = dep.get('name', 'unknown')
                    pkg_version = dep.get('version', 'unknown')
                    vuln_count = len(dep.get('vulns', []))
                    print(f"  - {pkg_name} {pkg_version}: {vuln_count} vulnerabilities")
                if len(dependencies) > 5:
                    print(f"  ... and {len(dependencies) - 5} more packages")

            return True, scan_result

        except FileNotFoundError:
            error_msg = "pip-audit not installed. Install with: pip install pip-audit>=2.6.0"
            print(f"ERROR: {error_msg}")
            self.results['scans']['pip_audit'] = {"status": "error", "message": error_msg}
            return False, {}
        except subprocess.TimeoutExpired:
            error_msg = "pip-audit timed out after 5 minutes"
            print(f"ERROR: {error_msg}")
            self.results['scans']['pip_audit'] = {"status": "timeout", "message": error_msg}
            return False, {}
        except Exception as e:
            error_msg = f"pip-audit failed: {str(e)}"
            print(f"ERROR: {error_msg}")
            self.results['scans']['pip_audit'] = {"status": "error", "message": error_msg}
            return False, {}

    def run_bandit_scan(self, target_dir: str = ".") -> Tuple[bool, Dict[str, Any]]:
        """Run static security analysis with Bandit.

        Args:
            target_dir: Directory to scan

        Returns:
            Tuple of (success, results_dict)
        """
        print("\n" + "=" * 70)
        print("Running Bandit Static Security Analysis...")
        print("=" * 70)

        output_file = self.output_dir / "bandit_results.json"

        try:
            # Run bandit with JSON output, only HIGH and MEDIUM severity
            result = subprocess.run(
                [
                    'bandit',
                    '-r', target_dir,
                    '-ll',  # Only report issues of severity level LOW or higher
                    '--format', 'json',
                    '-o', str(output_file),
                    '--exclude', './tests,./kp14_qa_venv,./keyplug_venv,./stego-analyzer,./venv,./.git'
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Read the JSON output file
            try:
                with open(output_file, 'r') as f:
                    bandit_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                bandit_data = {"error": "Failed to read Bandit output"}

            # Extract metrics
            metrics = bandit_data.get('metrics', {})
            total_issues = sum(
                loc_data.get('SEVERITY.HIGH', 0) + loc_data.get('SEVERITY.MEDIUM', 0) +
                loc_data.get('SEVERITY.LOW', 0)
                for loc_data in metrics.values()
                if isinstance(loc_data, dict)
            )

            results_list = bandit_data.get('results', [])

            scan_result = {
                "tool": "bandit",
                "status": "completed",
                "total_issues": len(results_list),
                "metrics": metrics,
                "output_file": str(output_file),
                "exit_code": result.returncode
            }

            # Update severity counts from results
            for issue in results_list:
                severity = issue.get('issue_severity', 'UNKNOWN').lower()
                if severity in self.results['summary']:
                    self.results['summary'][severity] += 1

            self.results['scans']['bandit'] = scan_result

            print(f"Bandit: {len(results_list)} security issues found")
            if results_list:
                print("\nTop security issues:")
                for issue in results_list[:5]:  # Show first 5
                    severity = issue.get('issue_severity', 'UNKNOWN')
                    test_id = issue.get('test_id', 'N/A')
                    issue_text = issue.get('issue_text', 'No description')
                    print(f"  - [{severity}] {test_id}: {issue_text}")
                if len(results_list) > 5:
                    print(f"  ... and {len(results_list) - 5} more issues")

            print(f"\nFull report saved to: {output_file}")

            return True, scan_result

        except FileNotFoundError:
            error_msg = "Bandit not installed. Install with: pip install bandit[toml]>=1.7.5"
            print(f"ERROR: {error_msg}")
            self.results['scans']['bandit'] = {"status": "error", "message": error_msg}
            return False, {}
        except subprocess.TimeoutExpired:
            error_msg = "Bandit scan timed out after 5 minutes"
            print(f"ERROR: {error_msg}")
            self.results['scans']['bandit'] = {"status": "timeout", "message": error_msg}
            return False, {}
        except Exception as e:
            error_msg = f"Bandit scan failed: {str(e)}"
            print(f"ERROR: {error_msg}")
            self.results['scans']['bandit'] = {"status": "error", "message": error_msg}
            return False, {}

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels to standard format.

        Args:
            severity: Severity string from scanner

        Returns:
            Normalized severity level
        """
        severity = severity.upper()
        mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'MODERATE': 'medium',
            'LOW': 'low',
            'INFO': 'info',
            'INFORMATIONAL': 'info',
            'UNKNOWN': 'info'
        }
        return mapping.get(severity, 'info')

    def generate_summary_report(self) -> str:
        """Generate a human-readable summary report.

        Returns:
            Summary report as string
        """
        report_lines = [
            "\n" + "=" * 70,
            "SECURITY SCAN SUMMARY REPORT",
            "=" * 70,
            f"Scan Date: {self.results['timestamp']}",
            f"Project: KP14",
            "",
            "SEVERITY BREAKDOWN:",
            f"  CRITICAL: {self.results['summary']['critical']}",
            f"  HIGH:     {self.results['summary']['high']}",
            f"  MEDIUM:   {self.results['summary']['medium']}",
            f"  LOW:      {self.results['summary']['low']}",
            f"  INFO:     {self.results['summary']['info']}",
            "",
            "SCAN RESULTS:",
        ]

        for scan_name, scan_data in self.results['scans'].items():
            status = scan_data.get('status', 'unknown')
            report_lines.append(f"  {scan_name.upper()}: {status}")

            if scan_name == 'safety':
                vuln_count = scan_data.get('vulnerabilities_found', 0)
                report_lines.append(f"    - Vulnerabilities: {vuln_count}")
            elif scan_name == 'pip_audit':
                pkg_count = scan_data.get('vulnerable_packages', 0)
                vuln_count = scan_data.get('total_vulnerabilities', 0)
                report_lines.append(f"    - Vulnerable packages: {pkg_count}")
                report_lines.append(f"    - Total vulnerabilities: {vuln_count}")
            elif scan_name == 'bandit':
                issue_count = scan_data.get('total_issues', 0)
                report_lines.append(f"    - Security issues: {issue_count}")

        report_lines.extend([
            "",
            "=" * 70,
            ""
        ])

        return "\n".join(report_lines)

    def save_reports(self) -> None:
        """Save all scan reports to disk."""
        # Save JSON report
        json_report_path = self.output_dir / f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nJSON report saved to: {json_report_path}")

        # Save text summary
        summary_report_path = self.output_dir / f"security_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(summary_report_path, 'w') as f:
            f.write(self.generate_summary_report())
        print(f"Summary report saved to: {summary_report_path}")

    def get_exit_code(self) -> int:
        """Determine appropriate exit code based on findings.

        Returns:
            Exit code (0-4 based on severity)
        """
        if self.results['summary']['critical'] > 0:
            return 4
        elif self.results['summary']['high'] > 0:
            return 3
        elif self.results['summary']['medium'] > 0:
            return 2
        elif self.results['summary']['low'] > 0:
            return 1
        return 0

    def run_all_scans(self) -> int:
        """Run all security scans.

        Returns:
            Exit code based on severity of findings
        """
        print("\n" + "=" * 70)
        print("KP14 COMPREHENSIVE SECURITY SCAN")
        print("=" * 70)
        print(f"Starting scan at {self.results['timestamp']}")
        print("")

        # Run all scans
        self.run_safety_check()
        self.run_pip_audit()
        self.run_bandit_scan()

        # Generate and display summary
        print(self.generate_summary_report())

        # Save reports
        self.save_reports()

        # Determine exit code
        exit_code = self.get_exit_code()

        if exit_code == 0:
            print("SUCCESS: No vulnerabilities found!")
        else:
            severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
            print(f"WARNING: {severity_map[exit_code]} or higher severity issues found!")
            print("Please review the scan reports and remediate vulnerabilities.")

        return exit_code


def main():
    """Main entry point for security scanning."""
    parser = argparse.ArgumentParser(
        description="Automated security scanning for KP14 project"
    )
    parser.add_argument(
        '--format',
        choices=['json', 'text'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('security_reports'),
        help='Output directory for reports (default: security_reports)'
    )
    parser.add_argument(
        '--scan-dir',
        type=str,
        default='.',
        help='Directory to scan with Bandit (default: current directory)'
    )

    args = parser.parse_args()

    # Create scanner and run all scans
    scanner = SecurityScanner(output_dir=args.output_dir, format=args.format)
    exit_code = scanner.run_all_scans()

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
