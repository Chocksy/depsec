# DepSec

Supply chain security scanner for any project. Single binary, zero config.

Detects vulnerable dependencies, malicious code patterns, hardcoded secrets, workflow misconfigurations, and unexpected network connections — with AST-aware analysis, LLM triage, and reachability scoring.

[![CI](https://github.com/chocksy/depsec/actions/workflows/ci.yml/badge.svg)](https://github.com/chocksy/depsec/actions/workflows/ci.yml)
[![DepSec Score](https://img.shields.io/badge/depsec-A-brightgreen)](https://github.com/chocksy/depsec)
[![crates.io](https://img.shields.io/crates/v/depsec)](https://crates.io/crates/depsec)

<img src="depsec-scorecard.svg?v=0.16.0" width="100%">

## Install

```sh
curl -fsSL https://depsec.dev/install | sh
```

Or with Cargo:

```sh
cargo install depsec
```

## Get Protected (2 minutes)

```sh
# Run the setup wizard — checkboxes for what to enable
depsec setup
```

The wizard configures:
- **Shell protection** — wraps npm/yarn/pip/cargo with automatic monitoring
- **Pre-commit hook** — blocks secrets from being committed
- **Sandbox by default** — sandboxes all protected installs

For CI or LLMs (non-interactive): `depsec setup --all`

After setup, every `npm install`, `pip install`, `cargo add` etc. is automatically monitored and sandboxed. No extra flags needed.

## Quick Start

```sh
depsec scan .
```

```
depsec v0.16.0 — Supply Chain Security Scanner

Project: my-app
Grade: B (7.8/10)

[Patterns]
  -- ACTION REQUIRED (2 runtime packages) ------
  evil-pkg (2 findings)
    x P001: Shell Execution — exec() with variable input
      node_modules/evil-pkg/index.js:42
    x P004: Credential Harvesting — reads ~/.ssh
      node_modules/evil-pkg/lib/steal.js:8

  -- BUILD TOOLS (safe, 12 findings collapsed) --
  webpack, esbuild, vite — 12 findings in build-only tools

[Dependencies]  0 known vulnerabilities (142 packages checked via OSV)
[Secrets]       No hardcoded secrets found (scanned 234 files)
[Workflows]     All GitHub Actions pinned to SHA
[Hygiene]       SECURITY.md exists, .gitignore covers sensitive patterns
```

## How It Works

```
scan ──→ score ──→ protect ──→ fix
  │         │         │          │
  │     grade A-F     │     auto-pin
  │                   │     GitHub Actions
  patterns        preflight
  deps            sandbox
  secrets         network monitor
  workflows       file watchdog
  hygiene         canary tokens
  capabilities
```

**Scan** runs 6 check modules across your project. AST-aware analysis (tree-sitter) eliminates false positives. Reachability analysis separates runtime from build-only findings.

**Protect** wraps package installs with a 4-phase pipeline: preflight typosquatting checks, OS-level sandbox (bubblewrap/sandbox-exec/Docker), network monitoring, and file watchdog with canary tokens.

**Fix** auto-pins GitHub Actions to commit SHAs. Other findings include actionable remediation guidance.

## AI Agent Integration

depsec works with AI coding tools out of the box.

**Claude Code** — paste into your project's `CLAUDE.md`:

```markdown
## Security
Run `depsec scan .` before committing. Run `depsec fix .` to auto-pin Actions.
Run `depsec protect npm install <pkg>` for unfamiliar packages.
Run `depsec setup --all` to enable shell hooks, pre-commit, and sandbox.
```

Or copy the skill: `mkdir -p .claude/commands && cp SKILL.md .claude/commands/depsec.md`

**Codex / Cursor / Windsurf** — reads `AGENTS.md` from repo root automatically.

**OpenClaw / Gemini / Amp** — `SKILL.md` follows the [AgentSkills](https://agentskills.io) spec. Works across 10+ AI coding tools.

## Benchmark

Tested against **10,582 real malware packages** from the [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset):

| Dataset | Packages | Detected | Rate |
|---------|----------|----------|------|
| npm malware | 8,806 | 8,806 | 100% |
| PyPI malware | 1,776 | 1,776 | 100% |
| **Total** | **10,582** | **10,582** | **100%** |

## Features

### AST-Aware Analysis

Tree-sitter parses JS/TS/Python into an AST for import-aware detection:

1. **Pass 1:** Find `require('child_process')` / `import` statements and track aliases
2. **Pass 2:** Flag exec/spawn calls only on those aliases

This means `regex.exec()` is not flagged, but `cp.exec(userInput)` is — eliminating the #1 source of false positives.

### Reachability Analysis

Parses your app's own source (not `node_modules`) to determine which dependencies are imported at runtime vs. build-only. Runtime findings get "ACTION REQUIRED" status; build-only findings are collapsed.

### Smart Secret Detection

Three-tier approach beyond regex:

| Rule | Method | Confidence |
|------|--------|------------|
| S001-S020 | 20 format-specific regexes (AWS, GitHub, Stripe, etc.) | Known patterns |
| S021 | AST variable name + high entropy + long value | High |
| S022 | AST variable name match (token, secret, password, etc.) | Medium |
| S023 | High entropy only (>4.5 bits/char, >30 chars) | Low |

Supports `// depsec:allow` inline comments to suppress individual lines.

### Protected Installs

After running `depsec setup`, all package installs are automatically monitored and sandboxed:

```sh
npm install lodash                    # auto-protected via shell hooks
depsec protect npm install lodash     # explicit protection (same thing)
depsec protect --no-sandbox npm install lodash  # skip sandbox for this install
depsec protect --learn npm install    # record expected connections as baseline
depsec protect --strict npm test      # fail on unexpected connections
```

The protection pipeline:
1. **Preflight** — typosquatting detection via Levenshtein distance, install hook detection
2. **Sandbox** — OS-level isolation masking ~/.ssh, ~/.aws, ~/.gnupg (bubblewrap/sandbox-exec/Docker)
3. **Network monitor** — polls connections every 100ms, classifies as expected/unexpected/critical
4. **File watchdog** — monitors file descriptors across process tree, detects sensitive reads

### LLM Triage

Send findings to an LLM for classification (requires [OpenRouter](https://openrouter.ai) API key):

```sh
depsec scan . --triage              # Real triage via LLM
depsec scan . --triage-dry-run      # Preview what would be sent
```

Results are cached (30-day TTL) so repeat scans don't re-query.

### Deep Package Audit

LLM-powered 4-phase analysis of a specific package:

```sh
depsec audit shelljs              # Deep audit
depsec audit shelljs --dry-run    # Preview capabilities
depsec audit shelljs --budget 2.0 # Cap LLM spend at $2.00
```

## Usage

### Scan

```sh
depsec scan .                         # All checks (executive summary)
depsec scan . --full                  # Detailed output
depsec scan . --checks workflows,deps # Specific checks only
depsec scan . --json                  # JSON output
depsec scan . --format sarif          # SARIF output (for GitHub Code Scanning)
```

**Exit codes:** 0 = pass, 1 = findings, 2 = error.

### Fix

```sh
depsec fix .            # Pin GitHub Actions to commit SHAs
depsec fix . --dry-run  # Preview changes
```

### Setup

```sh
depsec setup                # Interactive wizard (recommended)
depsec setup --all          # Install all defaults non-interactively (CI/LLM)
depsec setup --hook         # Install pre-commit hook only
depsec setup --unhook       # Remove pre-commit hook
depsec setup --baseline     # Generate network baseline
depsec setup --shell        # Print shell aliases (for eval in shell profile)
depsec setup --self-check   # Verify depsec binary integrity
```

### CI

```sh
depsec ci .                 # SARIF output + exit codes for CI pipelines
```

### Utilities

```sh
depsec scorecard .          # Generate SVG scorecard image
depsec badge .              # Output badge markdown
depsec cache stats          # Show triage cache statistics
depsec cache clear          # Clear cached triage results
depsec attestation verify . # Verify install attestation
depsec attestation summary .# Show attestation summary
depsec rules update         # Download community rules
depsec rules list           # List active rules
```

## Check Modules

### Patterns (10 pts)

Scans `node_modules/`, `vendor/`, `.venv/` for malicious code (15 rules):

| Rule | What it catches | Severity |
|------|----------------|----------|
| P001 | Shell execution via child_process (AST-aware) | High |
| P002 | base64 decode -> execute chains | Critical |
| P003 | HTTP calls to raw IP addresses | High |
| P004 | File reads targeting ~/.ssh, ~/.aws, ~/.env | Critical |
| P005 | Binary file read -> byte extraction -> execution | Critical |
| P006 | postinstall scripts with network calls | High |
| P008 | `new Function()` with dynamic input (AST-aware) | High |
| P010 | Cloud IMDS credential probing (169.254.169.254) | Critical |
| P011 | Environment variable serialization/exfiltration | High |
| P013 | Dynamic require() with non-literal argument | High |
| P014 | String.fromCharCode + XOR deobfuscation | High |
| P015 | Anti-forensic file operations (self-deleting code) | Critical |
| P017 | Code obfuscation (hex identifiers, infinite loops) | High |
| P018 | Node.js internal binding access (process.binding) | Critical |
| P019 | VM module code execution (vm.runInThisContext) | High |

### Dependencies (20 pts)

Queries [OSV](https://osv.dev) for known vulnerabilities across all ecosystems:

| Lockfile | Ecosystem |
|----------|-----------|
| `Cargo.lock` | Rust |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | Node |
| `Gemfile.lock` | Ruby |
| `go.sum` | Go |
| `poetry.lock` / `Pipfile.lock` / `requirements.txt` | Python |

### Secrets (25 pts)

20 format-specific regex patterns plus AST-based detection:

AWS keys, GitHub tokens (classic/fine-grained/app), private keys, JWTs, Slack webhooks/tokens, Stripe keys, SendGrid keys, Google API keys, NPM tokens, database connection strings (Postgres/MySQL/MongoDB), Heroku API keys, Twilio keys, and entropy-based detection for unknown formats.

### Workflows (25 pts)

| Rule | What it catches | Severity |
|------|----------------|----------|
| W001 | Actions not pinned to commit SHA | High |
| W002 | Missing or write-all permissions | Medium |
| W003 | `pull_request_target` with checkout | Critical |
| W004 | User-controlled expressions in `run:` blocks | Critical |
| W005 | `--no-verify` or `--force` in git commands | Medium |

### Repo Hygiene (10 pts)

| Rule | What it checks |
|------|---------------|
| H001 | `SECURITY.md` exists |
| H002 | `.gitignore` covers `.env`, `*.pem`, `*.key` |
| H003 | Lockfile committed (not gitignored) |
| H004 | Branch protection on main (requires `GITHUB_TOKEN`) |

### Capabilities (10 pts)

Detects dangerous capability combinations across packages:

| Rule | What it catches |
|------|----------------|
| CAP:credential-exfiltration | Credential reads + network access in same package |
| CAP:dropper | Network download + shell execution |
| CAP:data-theft | Environment/file reads + network exfiltration |
| CAP:reverse-shell | Network + shell + dynamic execution |
| CAP:crypto-miner | High CPU patterns + network + obfuscation |
| CAP:ransomware | File system writes + crypto + network |
| CAP:persistence | Startup injection + shell execution |
| CAP:supply-chain | Install hooks + network + shell execution |

### External Rules

```sh
depsec rules update        # Download rules from community repo
depsec rules list          # Show active rules
depsec rules add rule.toml # Add a custom rule file
```

## Configuration

Create `depsec.toml` in your project root:

```toml
[ignore]
patterns = ["DEPSEC-P003"]              # Suppress rules by ID
secrets = ["tests/fixtures/*"]           # Ignore paths for secrets scan
hosts = ["internal-mirror.company.com"]  # Baseline allowed hosts

[patterns]
skip_dirs = ["legacy-vendor"]            # Extra dirs to skip in pattern scan

[patterns.allow]
shelljs = ["DEPSEC-P001"]               # Allow P001 for shelljs specifically

[protect]
sandbox = false                          # Override sandbox default for this project

[checks]
enabled = ["workflows", "deps", "patterns", "secrets", "hygiene", "capabilities"]

[scoring]
workflows = 25
deps = 20
patterns = 10
secrets = 25
hygiene = 10
capabilities = 10
external_rules = 0                        # Opt-in: weight for custom rules

[triage]
api_key_env = "OPENROUTER_API_KEY"       # Env var containing API key
model = "anthropic/claude-sonnet-4-6"    # LLM model for triage
max_findings = 20                         # Max findings to triage per run
timeout_seconds = 60
cache_ttl_days = 30
```

Global preferences are stored at `~/.depsec/config.toml` (created by `depsec setup`).

## Scoring

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

## Comparison

| Feature | depsec | gitleaks | TruffleHog | GuardDog | zizmor | snyk |
|---------|--------|----------|------------|----------|--------|------|
| Language | Rust | Go | Go | Python | Rust | SaaS |
| Single binary | Yes | Yes | Yes | No | Yes | No |
| Secrets (regex) | 20 patterns | 800+ | 800+ | - | - | Yes |
| Secrets (AST+entropy) | Yes | - | - | - | - | - |
| Malware detection | 15 rules | - | - | Yes | - | - |
| AST-aware analysis | tree-sitter | - | - | semgrep | - | - |
| Vulnerability scan | OSV (all ecosystems) | - | - | - | - | Yes |
| Workflow security | 5 rules | - | - | - | 34 rules | - |
| Network monitoring | Yes | - | - | - | - | - |
| Sandbox protection | Yes | - | - | - | - | - |
| LLM triage | Yes | - | - | - | - | - |
| Reachability | Yes | - | - | - | - | - |
| Auto-fix | Yes | - | - | - | - | Yes |
| Zero config | Yes | Yes | Yes | Yes | Yes | No |

## Design Principles

1. **Own the parsers** — no shelling out to `npm audit` or `cargo audit`
2. **Query OSV directly** — single API for all ecosystems
3. **AST over regex** — tree-sitter eliminates false positives
4. **No plugins** — closed attack surface
5. **No secrets required** — pure read-only analysis (tokens optional)
6. **15 direct dependencies** — minimal supply chain surface

## License

MIT
