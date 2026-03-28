# DepSec

Supply chain security scanner for any GitHub project. Single binary, zero config.

Detects vulnerable dependencies, malicious code patterns, hardcoded secrets, workflow misconfigurations, and unexpected network connections in CI.

[![CI](https://github.com/chocksy/depsec/actions/workflows/ci.yml/badge.svg)](https://github.com/chocksy/depsec/actions/workflows/ci.yml)
[![DepSec Score](https://img.shields.io/badge/depsec-A-brightgreen)](https://github.com/chocksy/depsec)
[![crates.io](https://img.shields.io/crates/v/depsec)](https://crates.io/crates/depsec)

<img src="depsec-scorecard.svg" width="480">

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/chocksy/depsec/main/install.sh | sh
```

Or with Cargo:

```sh
cargo install depsec
```

## Quick Start

```sh
depsec scan .
```

```
depsec v0.1.0 — Supply Chain Security Scanner

Project: my-app
Grade: B (7.8/10)

[Workflows]
  ✓ All GitHub Actions pinned to SHA
  ✓ Workflow permissions minimized
  ✗ pull_request_target with checkout detected (ci.yml:15)
    → Remove checkout in pull_request_target or use pull_request instead

[Dependencies]
  ✓ Lockfile committed (Cargo.lock)
  ✓ 0 known vulnerabilities (142 packages checked via OSV)
  ⚠ 2 suspicious patterns found:
    node_modules/sketchy-pkg/lib.js:42 — eval()/exec() with decoded or variable input
    → Review or remove this dependency

[Secrets]
  ✓ No hardcoded secrets found (scanned 234 files)

[Hygiene]
  ✓ SECURITY.md exists
  ✗ No branch protection on main
    → Enable at github.com/owner/repo/settings/branches

Score: 7.8/10 (B)
Run 'depsec fix' to auto-fix 1 issue.
```

## Usage

### Scan

```sh
depsec scan .                         # All checks
depsec scan . --checks workflows,deps # Specific checks only
depsec scan . --json                  # Machine-readable output
```

**Exit codes:** 0 = pass, 1 = findings, 2 = error.

### Auto-Fix

```sh
depsec fix .            # Pin GitHub Actions to commit SHAs
depsec fix . --dry-run  # Preview changes without writing
```

Resolves action tags to commit SHAs via the GitHub API. Set `GITHUB_TOKEN` for higher rate limits.

### Baseline

```sh
depsec baseline init    # Generate network baseline file
depsec baseline check   # Compare CI run against baseline
```

### Badge

```sh
depsec badge            # Output badge markdown
```

## Check Modules

### Workflows (25 pts)

Parses `.github/workflows/*.yml`:

| Rule | What it catches | Severity |
|------|----------------|----------|
| W001 | Actions not pinned to commit SHA | High |
| W002 | Missing or write-all permissions | Medium |
| W003 | `pull_request_target` with checkout | Critical |
| W004 | User-controlled expressions in `run:` blocks | Critical |
| W005 | `--no-verify` or `--force` in git commands | Medium |

### Dependencies (20 pts)

Auto-detects lockfiles and queries [OSV](https://osv.dev) for known vulnerabilities:

| Lockfile | Ecosystem |
|----------|-----------|
| `Cargo.lock` | Rust |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | Node |
| `Gemfile.lock` | Ruby |
| `go.sum` | Go |
| `poetry.lock` / `Pipfile.lock` / `requirements.txt` | Python |

### Suspicious Patterns (10 pts)

Scans `node_modules/`, `vendor/`, etc. for malicious code:

| Rule | What it catches |
|------|----------------|
| P001 | `eval()`/`exec()` with decoded input |
| P002 | base64 decode → execute chains |
| P003 | HTTP calls to raw IP addresses |
| P004 | File reads targeting `~/.ssh`, `~/.aws`, `~/.env` |
| P005 | Binary file read → byte extraction → execution |
| P006 | postinstall scripts with network calls |
| P007 | High-entropy strings (encoded payloads) |
| P008 | `new Function()` with dynamic input |

### Secrets (25 pts)

20 high-confidence regex patterns for:

AWS keys, GitHub tokens, private keys, JWTs, Slack webhooks, Stripe keys, SendGrid keys, Google API keys, NPM tokens, database connection strings, and more.

### Repo Hygiene (10 pts)

| Rule | What it checks |
|------|---------------|
| H001 | `SECURITY.md` exists |
| H002 | `.gitignore` covers `.env`, `*.pem`, `*.key` |
| H003 | Lockfile committed (not gitignored) |
| H004 | Branch protection on main (requires `GITHUB_TOKEN`) |

## Scoring

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

## GitHub Action

```yaml
- uses: chocksy/depsec@v1
  with:
    mode: static        # static (default), full, or report
    fail-on: high       # critical, high, medium, low, or any
    github-token: ${{ github.token }}
```

**Outputs:** `score`, `grade`, `findings-count`.

## Configuration

Create `depsec.toml` in your project root:

```toml
[ignore]
patterns = ["DEPSEC-P003"]          # Suppress rules by ID
secrets = ["tests/fixtures/*"]       # Ignore paths for secrets scan
hosts = ["internal-mirror.company.com"]  # Baseline allowed hosts

[checks]
enabled = ["workflows", "deps", "patterns", "secrets", "hygiene"]

[scoring]
workflows = 25
deps = 20
patterns = 10
secrets = 25
hygiene = 10
network = 10
```

## Network Monitor (CI only)

In `full` mode, the GitHub Action captures network connections via `tcpdump` and diffs against a committed baseline:

```
[Network Monitor]
  ✓ github.com — in baseline
  ✓ registry.npmjs.org — in baseline
  ✗ 83.142.209.203:8080 — NOT in baseline!
```

Generate a baseline:

```sh
depsec baseline init
# Edit depsec.baseline.json, then commit it
```

## Design Principles

1. **Own the parsers** — no shelling out to `cargo audit`, `npm audit`, etc.
2. **Query OSV directly** — single API for all ecosystems
3. **Own the secret patterns** — 20 high-confidence regexes, no scanning libraries
4. **No plugins** — closed attack surface
5. **No secrets required** — pure read-only analysis (GitHub token optional)
6. **8 direct dependencies** — minimal supply chain surface

## License

MIT
