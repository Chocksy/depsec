# DepSec — Design Spec

**Repo**: `chocksy/depsec`
**Language**: Rust (single static binary)
**Purpose**: Supply chain security scanner + CI network monitor for any GitHub project. Detects vulnerable dependencies, malicious code patterns, hardcoded secrets, workflow misconfigurations, and unexpected network connections during CI.

## CLI Interface

```bash
depsec scan .                              # All static checks
depsec scan . --checks workflows,deps      # Specific checks only
depsec fix .                               # Auto-fix what can be fixed
depsec baseline init                       # Generate network baseline
depsec baseline check                      # Compare CI run against baseline
depsec badge                               # Output badge markdown
```

**Exit codes**: 0 = all pass, 1 = failures found, 2 = error running scan.

### Output

Scorecard with grade + pass/fail checklist + fix suggestions:

```
depsec v0.1.0 — Supply Chain Security Scanner

Project: my-app (rust)
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
    node_modules/sketchy-pkg/lib.js:42 — base64.decode → eval chain
    node_modules/sketchy-pkg/postinstall.sh — downloads binary from raw IP
    → Review or remove sketchy-pkg

[Secrets]
  ✓ No hardcoded secrets found (scanned 234 files)

[Repo Hygiene]
  ✓ SECURITY.md exists
  ✗ No branch protection on main
    → Enable at github.com/owner/repo/settings/branches

Score: 7.8/10 (B)
Run 'depsec fix' to auto-fix 1 issue.
```

Also supports `--json` for machine-readable output.

## Check Modules

### A. Workflow Hardening (`checks/workflows.rs`)

Parses `.github/workflows/*.yml` and checks:

- Actions pinned to commit SHAs (not tags)
- `permissions` block set and minimal (not default `write-all`)
- No `pull_request_target` with `actions/checkout` (code injection risk)
- No `${{ github.event.issue.body }}` in `run:` blocks (injection)
- No `--no-verify` or `--force` in git commands

**Auto-fix**: `depsec fix` resolves action tags to commit SHAs via GitHub API and rewrites workflow files.

### B. Dependency Auditing (`checks/deps.rs`)

Auto-detects project type by lockfile:

| Lockfile | Ecosystem |
|----------|-----------|
| `Cargo.lock` | Rust |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | Node |
| `Gemfile.lock` | Ruby |
| `go.sum` | Go |
| `requirements.txt` / `poetry.lock` / `Pipfile.lock` | Python |

Parses lockfiles with our own parsers (no third-party CLI tools). Extracts package names + versions and batch queries the OSV API (`api.osv.dev`) for known vulnerabilities. Reports severity (critical/high/medium/low) with links to advisories.

### B+. Suspicious Pattern Scanner (`checks/patterns.rs`)

Scans dependency source files (`node_modules/`, `vendor/`, etc.) for malicious code patterns:

| Pattern | Rule ID | What it catches |
|---------|---------|----------------|
| `eval()` / `exec()` with decoded input | DEPSEC-P001 | Classic obfuscation |
| `base64` decode → execute chains | DEPSEC-P002 | Encoded payload execution |
| HTTP calls to raw IP addresses | DEPSEC-P003 | C2 server communication |
| File reads targeting `~/.ssh`, `~/.aws`, `~/.env`, `~/.gnupg` | DEPSEC-P004 | Credential theft |
| Binary file read → byte extraction → execution | DEPSEC-P005 | Steganography (Telnyx WAV attack) |
| `postinstall` scripts with network calls or binary downloads | DEPSEC-P006 | Install-time payload delivery |
| High-entropy strings (>200 chars, entropy > 4.5 bits/char) | DEPSEC-P007 | Encoded payloads |
| `new Function(...)` with dynamic input | DEPSEC-P008 | Dynamic code execution |

False positives can be suppressed per-rule in `depsec.toml`.

### C. Secrets Detection (`checks/secrets.rs`)

Regex-based scan of all tracked files. Our own patterns, no third-party scanning libraries.

| Secret Type | Pattern |
|-------------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `gh[ps]_[A-Za-z0-9_]{36,}` |
| Private Key | `-----BEGIN (RSA\|EC\|DSA )?PRIVATE KEY-----` |
| JWT | `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.` |
| Slack Webhook | `hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/` |
| Generic API Key | `(?i)(api[_\-]?key\|secret[_\-]?key)\s*[:=]\s*['"][A-Za-z0-9]{20,}` |
| Connection String | `(?i)(postgres\|mysql\|mongodb)://[^\s]+:[^\s]+@` |

Respects `.gitignore` — only scans files that would be committed. ~20-30 high-confidence patterns to minimize false positives.

### E. Repo Hygiene (`checks/hygiene.rs`)

- `SECURITY.md` exists
- `.gitignore` covers sensitive patterns (`.env`, `*.pem`, `*.key`, `credentials.json`)
- Lockfile committed (not gitignored)
- Branch protection on main (only with optional GitHub token)

## Network Monitor (GitHub Action)

The GitHub Action wraps the CLI and adds runtime network monitoring:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abc123

      - uses: chocksy/depsec@v1
        with:
          mode: full
          baseline: depsec.baseline.json

      - run: npm install
      - run: npm test
      # post-step runs automatically — stops monitor, checks baseline
```

### How it works

1. **Pre-step**: runs `depsec scan .` (static checks) + starts `tcpdump` in background
2. **User's steps**: run normally
3. **Post-step** (automatic): stops tcpdump, parses connections, diffs against baseline

### Baseline file (`depsec.baseline.json`)

```json
{
  "version": 1,
  "created": "2026-03-27",
  "allowed_hosts": [
    "github.com",
    "registry.npmjs.org",
    "crates.io",
    "api.osv.dev"
  ]
}
```

First run with `baseline: auto` generates the file. User commits it. Future runs diff against it.

New connections not in baseline fail the check:

```
[Network Monitor]
  ✓ github.com — in baseline
  ✓ registry.npmjs.org — in baseline
  ✗ 83.142.209.203:8080 — NOT in baseline!
```

## Scoring System

| Category | Weight | Full score criteria |
|----------|--------|-------------------|
| Workflows | 25 pts | All actions pinned, permissions minimal, no injection patterns |
| Dependencies | 30 pts | 0 vulnerabilities, 0 suspicious patterns, lockfile committed |
| Secrets | 25 pts | No hardcoded secrets found |
| Repo Hygiene | 10 pts | SECURITY.md, .gitignore, lockfile committed |
| Network (CI only) | 10 pts | No unexpected connections vs baseline |

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

Badge: `[![DepSec Score](https://img.shields.io/badge/depsec-A-brightgreen)](https://github.com/chocksy/depsec)`

## Project Structure

```
depsec/
├── Cargo.toml
├── deny.toml
├── depsec.baseline.json
├── depsec.toml
├── src/
│   ├── main.rs
│   ├── scanner.rs
│   ├── config.rs
│   ├── output.rs
│   ├── fixer.rs
│   ├── baseline.rs
│   ├── checks/
│   │   ├── mod.rs
│   │   ├── workflows.rs
│   │   ├── deps.rs
│   │   ├── patterns.rs
│   │   ├── secrets.rs
│   │   └── hygiene.rs
│   └── parsers/
│       ├── mod.rs
│       ├── cargo_lock.rs
│       ├── package_lock.rs
│       ├── gemfile_lock.rs
│       ├── go_sum.rs
│       └── pip.rs
├── action.yml
├── action/
│   ├── entrypoint.sh
│   └── post.sh
├── tests/
│   └── fixtures/
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── README.md
├── SECURITY.md
└── install.sh
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| clap (derive) | CLI parsing |
| regex | Pattern matching for secrets + suspicious code |
| reqwest (blocking, rustls-tls) | OSV API queries only |
| serde / serde_json | JSON parsing |
| serde_yaml | GitHub Actions workflow parsing |
| toml | Config file + Cargo.lock parsing |
| sha2 | SHA256 for action pinning verification |
| walkdir | Directory traversal for file scanning |

8 direct dependencies. No secrets scanning libraries, no audit tool dependencies, no plugin system.

## Configuration (`depsec.toml`)

```toml
[ignore]
patterns = ["DEPSEC-P003"]
secrets = ["tests/fixtures/*"]
hosts = ["internal-mirror.company.com"]

[checks]
enabled = ["workflows", "deps", "patterns", "secrets", "hygiene"]

[scoring]
workflows = 25
deps = 30
secrets = 25
hygiene = 10
network = 10
```

## Self-Protection

- All GitHub Actions pinned to commit SHAs
- `depsec scan .` runs in CI on every PR (eats its own dogfood)
- `depsec.baseline.json` committed — CI network connections monitored
- `deny.toml` restricts dependency sources to crates.io only
- `SECURITY.md` with vulnerability reporting instructions
- SHA256 checksums + SLSA attestation on every release
- `install.sh` verifies checksums before installing
- No secrets/tokens required to run — pure read-only static analysis
- No plugin system — closed attack surface
- 8 direct dependencies, all from crates.io

## Distribution

- Cross-compiled for 5 targets (linux musl x86_64/arm64, macos x86_64/arm64, windows x86_64)
- `curl -fsSL .../install.sh | sh` with checksum verification
- Homebrew tap
- `cargo install`
- GitHub Action: `uses: chocksy/depsec@v1`

## Key Design Decisions

1. **Own the parsers** — parse lockfiles ourselves instead of shelling out to `cargo audit`, `npm audit`, etc. Eliminates trust in third-party CLI tools.
2. **Query OSV directly** — single trusted API for vulnerability data across all ecosystems. No per-language audit tools.
3. **Own the secret patterns** — 20-30 high-confidence regex patterns. No dependency on scanning libraries.
4. **Static-first, runtime-second** — static analysis catches 95% of real attacks. Network monitor is a bonus layer for CI.
5. **No secrets needed** — the tool never requires tokens to run. Read-only file analysis. GitHub token is optional (only for branch protection check and auto-fix SHA resolution).
6. **No plugins** — closed surface area. Every line of detection logic is in this repo.
