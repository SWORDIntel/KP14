#!/usr/bin/env python3
"""
GitHub Issue Generator for KP14 Technical Debt Items

This script generates GitHub issues from the TECHNICAL_DEBT.md register.
Issues can be created automatically via GitHub CLI or exported to JSON for manual creation.

Usage:
    # Dry run (preview issues):
    python scripts/create_github_issues.py --dry-run

    # Create issues via GitHub CLI:
    python scripts/create_github_issues.py --create

    # Export to JSON:
    python scripts/create_github_issues.py --export issues.json

Requirements:
    - GitHub CLI (gh) installed and authenticated (for --create)
    - Python 3.11+
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional


class TechnicalDebtIssue:
    """Represents a technical debt item to be converted to a GitHub issue"""

    def __init__(
        self,
        id: str,
        title: str,
        priority: str,
        debt_type: str,
        description: str,
        impact: str,
        remediation: str,
        effort: str,
        timeline: str,
        tracking_number: Optional[int] = None,
    ):
        self.id = id
        self.title = title
        self.priority = priority
        self.debt_type = debt_type
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.effort = effort
        self.timeline = timeline
        self.tracking_number = tracking_number

    def to_github_issue(self) -> Dict[str, any]:
        """Convert to GitHub issue format"""
        # Construct issue body
        body = f"""## Description

{self.description}

## Impact

{self.impact}

## Remediation Plan

{self.remediation}

## Metadata

- **Priority:** {self.priority}
- **Type:** {self.debt_type}
- **Estimated Effort:** {self.effort}
- **Timeline:** {self.timeline}
- **Technical Debt ID:** {self.id}

## Acceptance Criteria

See TECHNICAL_DEBT.md for detailed acceptance criteria.

---

*This issue was automatically generated from the Technical Debt Register.*
*Reference: `TECHNICAL_DEBT.md` - {self.id}*
"""

        # Determine labels based on priority and type
        labels = ["technical-debt"]

        priority_map = {
            "P0 - Critical": "priority: critical",
            "P1 - High": "priority: high",
            "P2 - Medium": "priority: medium",
            "P3 - Low": "priority: low",
        }
        labels.append(priority_map.get(self.priority, "priority: medium"))

        type_map = {
            "Testing": "testing",
            "Architecture": "architecture",
            "Code Quality": "code-quality",
            "Performance": "performance",
            "Security": "security",
            "Documentation": "documentation",
            "Dependencies": "dependencies",
        }
        if self.debt_type in type_map:
            labels.append(type_map[self.debt_type])

        return {
            "title": self.title,
            "body": body,
            "labels": labels,
            "assignees": [],
        }


# Define the technical debt items from TECHNICAL_DEBT.md
TECHNICAL_DEBT_ITEMS = [
    TechnicalDebtIssue(
        id="TD-001",
        title="Incomplete Unit Test Coverage",
        priority="P1 - High",
        debt_type="Testing",
        description="Current code coverage is estimated at 45-55%. Many modules lack comprehensive unit tests, particularly steganography analyzers (30%), crypto analyzers (40%), and behavioral analyzer (35%).",
        impact="Difficult to refactor confidently, high regression risk, slower development speed, bugs discovered later in cycle (more expensive to fix).",
        remediation="Phase 1 (20h): Create pytest fixtures, mock OpenVINO, sample repository → 60% coverage. Phase 2 (30h): Unit tests for all public APIs, edge cases, integration tests → 80% coverage. Phase 3 (10h): Property-based testing, mutation testing → 85%+ coverage.",
        effort="60 hours",
        timeline="Q4 2025 - Q2 2026",
        tracking_number=3,
    ),
    TechnicalDebtIssue(
        id="TD-002",
        title="Monolithic Configuration Management",
        priority="P1 - High",
        debt_type="Architecture",
        description="Configuration handled via single settings.ini file with no validation, type safety, or secrets management. Difficult to extend for plugins, no environment-specific overrides.",
        impact="Hard to add configuration for new modules, cannot use environment variables for containerization, secrets stored in plaintext, configuration errors detected at runtime not startup.",
        remediation="Phase 1 (15h): Pydantic models for all configuration sections, validation at load time. Phase 2 (10h): Environment variable overrides, secrets management integration. Phase 3 (5h): Plugin configuration namespaces.",
        effort="30 hours",
        timeline="Q4 2025 - Q2 2026",
        tracking_number=4,
    ),
    TechnicalDebtIssue(
        id="TD-003",
        title="Limited Error Handling Granularity",
        priority="P2 - Medium",
        debt_type="Code Quality",
        description="Error handling lacks granularity: generic Exception caught, error context lost, inconsistent messaging, some bare except: clauses.",
        impact="Difficult to trace root cause, cannot distinguish error types in logs, generic error messages not actionable, may hide unexpected errors.",
        remediation="Step 1 (5h): Exception hierarchy review, add missing types. Step 2 (15h): Replace generic exceptions, add context, exception chaining. Step 3 (5h): Structured error logging, user-friendly messages, error codes.",
        effort="25 hours",
        timeline="Q1 2026",
        tracking_number=5,
    ),
    TechnicalDebtIssue(
        id="TD-004",
        title="Inconsistent Logging Practices",
        priority="P2 - Medium",
        debt_type="Code Quality",
        description="Logging varies across modules: some use print(), inconsistent log levels, missing structured logging, no correlation IDs, sensitive data occasionally logged.",
        impact="Difficult to diagnose production issues, potential PII/sensitive data leakage, excessive logging impacts performance, audit trail gaps.",
        remediation="Step 1 (5h): Logging audit, convert print() to logging, identify sensitive data. Step 2 (10h): Logging helpers, correlation IDs, structured logging, sanitization. Step 3 (5h): Centralized config, rotation, optimization.",
        effort="20 hours",
        timeline="Q1 2026",
        tracking_number=6,
    ),
    TechnicalDebtIssue(
        id="TD-005",
        title="String Extraction Performance Bottleneck",
        priority="P2 - Medium",
        debt_type="Performance",
        description="String extraction is inefficient: scans entire file for each pattern, no caching, regex compiled per invocation, large files cause exponential degradation (100MB → 45 seconds).",
        impact="20-30% of total analysis time, slow for large binaries, bottleneck for batch processing.",
        remediation="Step 1 (3h): Profile string extraction, identify bottlenecks. Step 2 (12h): Compile regex once, single-pass extraction, LRU cache, memory-mapped reading, consider Rust/C++. Step 3 (3h): Benchmark 50%+ improvement.",
        effort="18 hours",
        timeline="Q1 2026",
        tracking_number=7,
    ),
    TechnicalDebtIssue(
        id="TD-006",
        title="Hardcoded Constants Throughout Codebase",
        priority="P2 - Medium",
        debt_type="Code Quality",
        description="Many constants hardcoded: magic numbers (thresholds, sizes), file paths (/tmp/kp14_temp), default values (chunk sizes), API endpoints.",
        impact="Changes require code modifications, difficult to test with different values, cannot tune without redeployment, platform-specific paths.",
        remediation="Step 1 (5h): Audit for hardcoded constants, categorize. Step 2 (10h): Move to configuration, create constants.py, update docs. Step 3 (3h): Validation.",
        effort="18 hours",
        timeline="Q2 2026",
        tracking_number=8,
    ),
    TechnicalDebtIssue(
        id="TD-007",
        title="Code Duplication Across Modules",
        priority="P2 - Medium",
        debt_type="Architecture",
        description="Functionality duplicated: file reading logic repeated, entropy calculation (3 implementations), hash computation (4 implementations), PE header parsing (2 implementations).",
        impact="Bug fixes must be applied multiple times, different implementations may behave differently, unnecessary code size, must test duplicated logic separately.",
        remediation="Step 1 (5h): Use duplication detection tools, document instances. Step 2 (15h): Create utils/ modules, extract shared logic, update call sites. Step 3 (2h): Document patterns, PR checklist.",
        effort="22 hours",
        timeline="Q2 2026",
        tracking_number=9,
    ),
    TechnicalDebtIssue(
        id="TD-008",
        title="Insufficient Input Validation",
        priority="P3 - Low (Security: P2)",
        debt_type="Security",
        description="Input validation inconsistent: file size limits not consistently enforced, magic byte validation missing, path traversal not fully prevented, no config validation, limited archive bomb detection.",
        impact="Potential DoS via malformed files, crashes on unexpected input, cryptic errors instead of validation messages. Attack vectors: oversized files (OOM), malformed headers (crashes), zip bombs (disk exhaustion), path traversal, recursive archives (stack overflow).",
        remediation="Step 1 (4h): Threat modeling, identify input vectors. Step 2 (12h): Implement validation (size, magic bytes, path sanitization, depth limits, timeouts). Step 3 (6h): Malicious test samples, fuzzing, regression tests.",
        effort="22 hours",
        timeline="Q4 2025 - Q1 2026",
        tracking_number=10,
    ),
    TechnicalDebtIssue(
        id="TD-009",
        title="Outdated Dependency Versions",
        priority="P3 - Low",
        debt_type="Dependencies",
        description="Some dependencies not on latest versions (deliberately pinned for stability): OpenVINO 2025.3.0 (latest: 2025.4.0), PyCryptodome 3.19.x (latest: 3.20.x), Capstone 5.0.1 (latest: 5.0.2), NumPy 1.26.x (latest: 2.0.x with breaking changes).",
        impact="Missing security patches (low risk currently), missing new features/optimizations, potential compatibility issues with newer Python versions.",
        remediation="Ongoing maintenance (2h/month): Monthly Dependabot review, update no-breaking-change deps, test in CI/CD. Major update sprints (8h each): Q1 2026 NumPy 2.0, Q2 2026 OpenVINO 2026.x.",
        effort="2 hours/month + 16 hours for major updates",
        timeline="Ongoing",
        tracking_number=11,
    ),
    TechnicalDebtIssue(
        id="TD-010",
        title="Missing API Documentation",
        priority="P3 - Low",
        debt_type="Documentation",
        description="Internal API documentation lacking: 30% of functions missing docstrings, no generated API reference, unclear module interfaces, no Python API usage examples.",
        impact="Hard to extend or integrate, future developers must read source code, higher barrier to community contributions.",
        remediation="Step 1 (5h): Docstring audit, prioritize public APIs. Step 2 (20h): Add Google-style docstrings with params/returns/exceptions/examples. Step 3 (5h): Configure Sphinx/MkDocs, generate reference, publish to ReadTheDocs.",
        effort="30 hours",
        timeline="Q2 2026",
        tracking_number=12,
    ),
    TechnicalDebtIssue(
        id="TD-011",
        title="Single-Threaded Bottlenecks",
        priority="P3 - Low",
        debt_type="Performance",
        description="Some parallelizable operations single-threaded: sequential import/export processing, serial YARA matching, single-threaded disassembly, crypto brute-forcing not parallelized.",
        impact="Leaves CPU cores idle, cannot fully utilize modern multi-core systems, unnecessarily slow on powerful hardware. Potential speedups: imports 4×, YARA 8×, crypto 16×.",
        remediation="Step 1 (3h): Profile for parallelization opportunities. Step 2 (15h): ThreadPoolExecutor for I/O-bound, multiprocessing.Pool for CPU-bound, work queues. Step 3 (2h): Benchmark, race condition checks.",
        effort="20 hours",
        timeline="Q2 2026",
        tracking_number=13,
    ),
    TechnicalDebtIssue(
        id="TD-012",
        title="Limited Internationalization Support",
        priority="P3 - Low",
        debt_type="Feature Gap",
        description="All user-facing messages in English: errors hardcoded, logs English-only, reports generated in English, no i18n framework.",
        impact="Non-English speakers have difficulty, limits international adoption, some regions require local language for compliance.",
        remediation="Step 1 (8h): i18n framework setup (gettext/Babel), mark strings for translation. Step 2 (15h/language): Professional translation, validate terminology. Step 3 (5h/format): Localized report templates, locale-aware formatting.",
        effort="40+ hours per language",
        timeline="Not scheduled (future consideration)",
        tracking_number=14,
    ),
]


def create_issue_via_gh_cli(issue: TechnicalDebtIssue, repo: str, dry_run: bool = False):
    """Create a GitHub issue using the GitHub CLI"""
    issue_data = issue.to_github_issue()

    if dry_run:
        print(f"\n{'='*70}")
        print(f"ISSUE: {issue_data['title']}")
        print(f"{'='*70}")
        print(f"Labels: {', '.join(issue_data['labels'])}")
        print(f"\nBody:\n{issue_data['body']}")
        return

    # Check if issue already exists
    if issue.tracking_number:
        print(f"✓ Issue #{issue.tracking_number} already exists for {issue.id}: {issue.title}")
        return

    # Build gh command
    cmd = [
        "gh",
        "issue",
        "create",
        "--repo",
        repo,
        "--title",
        issue_data["title"],
        "--body",
        issue_data["body"],
    ]

    for label in issue_data["labels"]:
        cmd.extend(["--label", label])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        issue_url = result.stdout.strip()
        print(f"✓ Created issue for {issue.id}: {issue_url}")
        return issue_url
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to create issue for {issue.id}: {e.stderr}")
        return None
    except FileNotFoundError:
        print("✗ GitHub CLI (gh) not found. Please install it: https://cli.github.com/")
        sys.exit(1)


def export_to_json(issues: List[TechnicalDebtIssue], output_path: Path):
    """Export issues to JSON for manual creation"""
    data = {
        "metadata": {
            "source": "TECHNICAL_DEBT.md",
            "generated_by": "scripts/create_github_issues.py",
            "total_issues": len(issues),
        },
        "issues": [issue.to_github_issue() for issue in issues],
    }

    output_path.write_text(json.dumps(data, indent=2))
    print(f"✓ Exported {len(issues)} issues to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate GitHub issues from KP14 Technical Debt Register"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview issues without creating them",
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create issues via GitHub CLI (requires gh)",
    )
    parser.add_argument(
        "--export",
        type=Path,
        metavar="FILE",
        help="Export issues to JSON file",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default="yourusername/kp14",
        help="GitHub repository (owner/repo)",
    )
    parser.add_argument(
        "--filter-priority",
        choices=["P0", "P1", "P2", "P3"],
        help="Only process issues of this priority",
    )
    parser.add_argument(
        "--filter-type",
        choices=["Testing", "Architecture", "Code Quality", "Performance", "Security", "Documentation", "Dependencies"],
        help="Only process issues of this type",
    )

    args = parser.parse_args()

    if not (args.dry_run or args.create or args.export):
        parser.error("Must specify --dry-run, --create, or --export")

    # Filter issues if requested
    issues = TECHNICAL_DEBT_ITEMS

    if args.filter_priority:
        issues = [i for i in issues if i.priority.startswith(args.filter_priority)]

    if args.filter_type:
        issues = [i for i in issues if i.debt_type == args.filter_type]

    print(f"\nProcessing {len(issues)} technical debt items...")

    if args.dry_run:
        print("\nDRY RUN MODE - No issues will be created\n")
        for issue in issues:
            create_issue_via_gh_cli(issue, args.repo, dry_run=True)

    elif args.create:
        print("\nCreating issues via GitHub CLI...\n")
        created = 0
        for issue in issues:
            if create_issue_via_gh_cli(issue, args.repo, dry_run=False):
                created += 1

        print(f"\n✓ Successfully created {created} new issues")
        print(f"✓ Skipped {len(issues) - created} existing issues")

    elif args.export:
        export_to_json(issues, args.export)

    print("\nDone!")


if __name__ == "__main__":
    main()
