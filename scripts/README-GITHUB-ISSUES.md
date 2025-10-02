# GitHub Issues Management - Quick Reference

This document provides instructions for using the GitHub issues infrastructure created for KP14.

---

## Overview

The KP14 project now has:
- **5 issue templates** for standardized reporting
- **Automated issue creation script** for technical debt items
- **12 technical debt items** ready to be converted to GitHub issues

---

## Creating Issues Manually

### Using Issue Templates

1. Go to: https://github.com/yourusername/kp14/issues/new/choose
2. Select the appropriate template:
   - **Bug Report** - For reporting bugs or unexpected behavior
   - **Feature Request** - For suggesting new features
   - **Technical Debt** - For code quality or refactoring needs
   - **Performance Issue** - For slow operations or optimization opportunities
   - **Documentation** - For doc improvements

3. Fill out all required fields
4. Submit the issue

### Template Selection Guide

| Use Case | Template |
|----------|----------|
| Analysis crashes or gives wrong results | Bug Report |
| Want a new file format supported | Feature Request |
| Code is hard to maintain | Technical Debt |
| Analysis takes too long | Performance Issue |
| Documentation is unclear | Documentation |

---

## Creating Technical Debt Issues (Automated)

### Prerequisites

Install GitHub CLI:
```bash
# Ubuntu/Debian
sudo apt install gh

# macOS
brew install gh

# Windows
winget install GitHub.cli

# Authenticate
gh auth login
```

### Usage

#### 1. Preview Issues (Dry Run)

Before creating issues, preview what will be created:

```bash
cd /run/media/john/DATA/Active\ Measures/c2-enum-toolkit/kp14
python scripts/create_github_issues.py --dry-run
```

This shows you all 12 technical debt issues that will be created.

#### 2. Create All Issues

```bash
python scripts/create_github_issues.py \
    --create \
    --repo yourusername/kp14
```

Replace `yourusername/kp14` with your actual GitHub repository.

#### 3. Filter by Priority

Create only high-priority issues:

```bash
python scripts/create_github_issues.py \
    --create \
    --repo yourusername/kp14 \
    --filter-priority P1
```

Available priorities: P0, P1, P2, P3

#### 4. Filter by Type

Create only testing-related issues:

```bash
python scripts/create_github_issues.py \
    --create \
    --repo yourusername/kp14 \
    --filter-type Testing
```

Available types:
- Testing
- Architecture
- Code Quality
- Performance
- Security
- Documentation
- Dependencies

#### 5. Export to JSON

Export issues to JSON for review or manual creation:

```bash
python scripts/create_github_issues.py \
    --export /tmp/kp14-issues.json
```

Then review the JSON and create issues manually via GitHub web UI.

---

## Issue Labels

The script automatically applies these labels:

### Priority Labels
- `priority: critical` - P0 items
- `priority: high` - P1 items
- `priority: medium` - P2 items
- `priority: low` - P3 items

### Type Labels
- `technical-debt` - All technical debt issues
- `testing` - Test coverage issues
- `architecture` - Design issues
- `code-quality` - Code cleanliness
- `performance` - Performance issues
- `security` - Security issues
- `documentation` - Doc issues

### Note
You may need to create these labels in your repository first:

```bash
# Create labels using GitHub CLI
gh label create "technical-debt" --description "Technical debt items" --color E99695
gh label create "priority: high" --description "High priority" --color D93F0B
gh label create "priority: medium" --description "Medium priority" --color FFA500
gh label create "priority: low" --description "Low priority" --color 0E8A16
# ... etc
```

Or use the GitHub web UI: Settings → Labels → New label

---

## Expected Issues

Running the script with `--create` will create these 12 issues:

1. **TD-001:** Incomplete Unit Test Coverage (P1, testing)
2. **TD-002:** Monolithic Configuration Management (P1, architecture)
3. **TD-003:** Limited Error Handling Granularity (P2, code-quality)
4. **TD-004:** Inconsistent Logging Practices (P2, code-quality)
5. **TD-005:** String Extraction Performance (P2, performance)
6. **TD-006:** Hardcoded Constants (P2, code-quality)
7. **TD-007:** Code Duplication (P2, architecture)
8. **TD-008:** Insufficient Input Validation (P2, security)
9. **TD-009:** Outdated Dependencies (P3, dependencies)
10. **TD-010:** Missing API Documentation (P3, documentation)
11. **TD-011:** Single-Threaded Bottlenecks (P3, performance)
12. **TD-012:** Limited Internationalization (P3, feature-gap)

Each issue includes:
- Detailed description
- Impact analysis
- Remediation plan
- Effort estimate
- Timeline
- Link back to TECHNICAL_DEBT.md

---

## Workflow After Creating Issues

### 1. Triage (Week 1)
- Review all created issues
- Assign to milestones (Q4 2025, Q1 2026, etc.)
- Assign owners where applicable
- Add to project board if using GitHub Projects

### 2. Prioritization (Week 1-2)
- Start with P1 items (TD-001, TD-002)
- Create implementation plan for each
- Break down into subtasks if needed

### 3. Implementation (Ongoing)
- Assign issues to sprints
- Link pull requests to issues
- Update issue with progress
- Close when acceptance criteria met

### 4. Tracking (Monthly)
- Review open technical debt issues
- Update TECHNICAL_DEBT.md if status changes
- Adjust timelines based on actual progress

---

## Troubleshooting

### "gh: command not found"
Install GitHub CLI: https://cli.github.com/

### "Authentication failed"
Run: `gh auth login` and follow prompts

### "Issues already exist"
The script checks tracking numbers and skips existing issues. You can safely re-run it.

### "Permission denied"
Make sure you have write access to the repository.

### Want to delete created issues?
```bash
# Delete a specific issue
gh issue delete <issue-number> --repo yourusername/kp14

# Or close instead of delete
gh issue close <issue-number> --repo yourusername/kp14
```

---

## Integration with Project Board

### GitHub Projects (Recommended)

1. Create a project board: https://github.com/yourusername/kp14/projects
2. Add columns:
   - Backlog
   - To Do
   - In Progress
   - Review
   - Done

3. Add technical debt issues to board:
```bash
# Using GitHub CLI
gh issue list --label "technical-debt" | while read issue; do
  gh project item-add <project-number> --issue <issue-number>
done
```

4. Or use automation: Settings → Projects → Add automation

---

## Continuous Management

### Monthly Process

1. **Review New Issues**
   - Check for new bug reports, feature requests
   - Triage and label appropriately
   - Assign to milestones

2. **Update Technical Debt**
   - Review progress on open debt issues
   - Create new issues for newly discovered debt
   - Update TECHNICAL_DEBT.md to match reality

3. **Dependency Updates**
   - Review Dependabot alerts
   - Update dependencies with no breaking changes
   - Plan major version updates

### Quarterly Process

1. **Debt Review**
   - Run automated TODO scan (should still be 0)
   - Review technical debt health score
   - Adjust priorities based on business needs

2. **Roadmap Update**
   - Update ROADMAP.md with actual progress
   - Adjust timelines if needed
   - Communicate changes to community

---

## Best Practices

### For Maintainers

- **Respond quickly:** Triage new issues within 48 hours
- **Be transparent:** Update issues with progress regularly
- **Close promptly:** Close issues when complete (don't let them accumulate)
- **Link PRs:** Always link pull requests to issues
- **Use templates:** Enforce template usage (already configured)

### For Contributors

- **Search first:** Check if issue already exists
- **Use templates:** Fill out all required fields
- **Be specific:** Provide reproduction steps, logs, versions
- **Stay engaged:** Respond to questions from maintainers
- **Test fixes:** Verify that fixes actually resolve issues

---

## References

- **TECHNICAL_DEBT.md** - Full technical debt register
- **TODO_CLEANUP_SUMMARY.md** - This cleanup mission's report
- **ROADMAP.md** - Development roadmap and timelines
- **GitHub Issues Docs** - https://docs.github.com/en/issues

---

## Need Help?

- **GitHub Discussions:** https://github.com/yourusername/kp14/discussions
- **Issue Template Questions:** Open a discussion in "Ideas" category
- **Script Issues:** Open a bug report or contact maintainers

---

**Last Updated:** 2025-10-02
**Maintained By:** KP14 Core Team
