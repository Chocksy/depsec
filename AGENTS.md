# depsec — Agent Instructions

Supply chain security scanner. Single binary, zero config.

## Quick Reference

```bash
depsec scan .                              # scan for all security issues
depsec scan . --json                       # JSON output for parsing
depsec fix .                               # auto-pin GitHub Actions to SHA
depsec protect npm install <pkg>           # safe install with monitoring
depsec setup --hook                        # pre-commit secret detection
depsec ci .                                # CI mode (SARIF + exit codes)
```

## When to Run depsec

- After adding or updating dependencies
- Before committing (secrets check)
- Before merging PRs (full scan)
- When installing unfamiliar packages (use `protect`)

## Interpreting Results

- **Exit 0**: clean, no issues
- **Exit 1**: findings detected — check output
- **Exit 2**: error running scan

Findings are grouped: Patterns, Dependencies, Secrets, Workflows, Hygiene.
Focus on Critical/High severity in runtime packages. Build-tool findings are lower priority.

## Auto-Fix

`depsec fix .` pins unpinned GitHub Actions to commit SHAs. For other findings, follow the remediation suggestion printed with each finding.

## Configuration

Create `depsec.toml` to suppress rules or configure scanning:

```toml
[ignore]
patterns = ["DEPSEC-P003"]        # suppress by rule ID
secrets = ["tests/fixtures/*"]     # ignore paths
```
