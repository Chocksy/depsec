---
name: depsec
description: >
  Supply chain security scanner. Use when installing dependencies, before
  committing code, or when the user asks to scan for security issues, secrets,
  or vulnerabilities. Runs as a single binary CLI — no API keys required for
  core scanning.
---

# depsec — Supply Chain Security Scanner

## Prerequisite

```bash
command -v depsec >/dev/null 2>&1 && echo "depsec: installed" || echo "NOT INSTALLED — run: curl -fsSL https://depsec.dev/install | sh"
```

If `cargo` is available: `cargo install depsec`

## Core Workflow

### 1. Scan

```bash
depsec scan .                    # full scan — patterns, deps, secrets, workflows, hygiene
depsec scan . --json             # machine-readable output
depsec scan . --format sarif     # SARIF for GitHub Code Scanning
depsec scan . --checks deps      # specific check only (patterns, deps, secrets, workflows, hygiene)
```

**Exit codes:** 0 = clean, 1 = findings, 2 = error.

### 2. Interpret Output

The scan returns a **grade (A–F)** and groups findings by check module:

- **[Patterns]** — malicious code in dependencies (shell exec, credential harvesting, encoded payloads)
  - "ACTION REQUIRED" = runtime dependency, investigate immediately
  - "BUILD TOOLS" = dev dependency, lower risk, collapsed by default
- **[Dependencies]** — known CVEs from OSV database
- **[Secrets]** — hardcoded API keys, tokens, passwords (regex + AST + entropy)
- **[Workflows]** — GitHub Actions misconfigurations (unpinned actions, expression injection)
- **[Hygiene]** — SECURITY.md, .gitignore, lockfile, branch protection

Critical/High severity findings in runtime packages require action. Build-tool findings are informational.

### 3. Fix

```bash
depsec fix .            # auto-pin GitHub Actions to commit SHAs
depsec fix . --dry-run  # preview changes
```

Currently auto-fixes workflow pinning (W001). Other findings require manual remediation — follow the suggestions in scan output.

### 4. Setup

```bash
depsec setup                     # interactive wizard — checkboxes for shell hooks, pre-commit, sandbox
depsec setup --all               # install all defaults non-interactively (for CI/LLMs)
depsec setup --hook              # install pre-commit hook only
depsec setup --shell             # print shell aliases (for eval in shell profile)
depsec setup --baseline          # initialize network connection baseline
depsec setup --self-check        # verify depsec binary integrity
```

### 5. Protected Installs

When installing unfamiliar packages, wrap the command:

```bash
depsec protect npm install sketchy-pkg      # preflight + network monitor + file watchdog
depsec protect --preflight-only npm install  # just typosquatting/metadata checks
```

## Configuration

Optional `depsec.toml` in project root:

```toml
[ignore]
patterns = ["DEPSEC-P003"]             # suppress rules by ID
secrets = ["tests/fixtures/*"]          # ignore paths for secrets
hosts = ["internal-mirror.example.com"] # allowed network hosts

[patterns.allow]
shelljs = ["DEPSEC-P001"]              # allow specific rule for a package
```

## When to Use

- **Before committing**: `depsec scan . --staged` (or use `depsec setup --hook`)
- **Before installing packages**: `depsec protect npm install <pkg>`
- **In CI**: `depsec ci .` (outputs SARIF + human summary)
- **After adding dependencies**: `depsec scan . --checks deps,patterns`
- **To fix workflow pinning**: `depsec fix .`
