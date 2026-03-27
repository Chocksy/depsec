---
title: "feat: DepSec v2 — Adaptive Supply Chain Security"
type: feat
date: 2026-03-27
---

# DepSec v2 — Adaptive Supply Chain Security

## Overview

Transform depsec from a static scanner into an adaptive security system with three improvement layers: built-in rules (static), live threat feeds (dynamic), and behavioral learning (runtime). The flagship features are `depsec monitor` (process-attributed network monitoring) and `depsec preflight` (pre-install threat analysis).

**Current state:** 4,460 LOC Rust, 19 source files, 98 transitive deps, 73 tests, Grade A (10/10).
**Goal:** 1000 GitHub stars through community-first adoption and the "own your security" philosophy — self-contained, no cloud, trust nothing.

## Problem Statement

DepSec v1 catches known vulnerabilities (CVEs) and static code patterns. But the attacks of 2026 — LiteLLM, StegaBin, SANDWORM, CanisterWorm — bypass static analysis entirely:

- **LiteLLM** used `.pth` files (Python startup hooks) that execute without any import
- **StegaBin** hid C2 addresses in zero-width Unicode characters inside Pastebin essays
- **SANDWORM** injected rogue MCP servers into AI assistant configs (Claude, Cursor, VS Code)
- **CanisterWorm** self-propagated by stealing npm tokens and republishing victim packages
- **Telnyx** hid payloads in WAV audio files, executing entirely in memory (fileless)

These attacks share one trait: **they're visible on the network but invisible to regex**. A postinstall script that phones home to `83.142.209.203:8080` won't match any static pattern, but it WILL show up as an unexpected network connection.

Meanwhile, the OSV database already contains **223,794 known malicious packages** with `MAL-*` IDs — data we query but don't surface.

## Proposed Solution

Five implementation phases building on the existing codebase:

1. **Adaptive Detection** — Surface MAL-* malware data from OSV (free), add 4+ new pattern rules for 2026 attack vectors
2. **`depsec monitor`** — Wrap any command, watch its network activity with process attribution, learn behavioral baselines
3. **`depsec preflight`** — Pre-install scanning via deps.dev API for package metadata, typosquatting, and install script analysis
4. **Self-Improving Rules** — External TOML rule files that evolve without recompiling the binary
5. **Trust & Output** — `depsec self-check`, shell hooks, SARIF output for GitHub Security tab

## Technical Approach

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     depsec CLI                            │
│                                                           │
│  ┌──────────────┐  ┌───────────────┐  ┌───────────────┐ │
│  │ Static Rules │  │ Dynamic Feeds │  │ Runtime       │ │
│  │ (built-in)   │  │ (fetched)     │  │ Monitor       │ │
│  └──────┬───────┘  └───────┬───────┘  └───────┬───────┘ │
│         │                  │                   │         │
│  W001-W005          OSV API (CVEs +     ss -tnp/lsof    │
│  P001-P012          MAL-* malware)      /proc/<pid>/    │
│  S001-S020                              cmdline          │
│  H001-H004          deps.dev API                        │
│                     (scorecard,          Behavioral      │
│  External rules     metadata)            baselines       │
│  (.depsec/rules/)                        (learns per     │
│                     C2 host blocklist     project)       │
│                     (community JSON)                     │
│                                                           │
│  Commands:                                                │
│  scan      — static analysis (existing)                  │
│  monitor   — wrap command + watch network (NEW)          │
│  preflight — pre-install threat check (NEW)              │
│  fix       — auto-fix SHA pinning (existing)             │
│  baseline  — network baseline management (existing)      │
│  rules     — manage external rules (NEW)                 │
│  self-check — verify own integrity (NEW)                 │
│  shell-hook — generate shell aliases (NEW)               │
│  badge     — output badge markdown (existing)            │
└──────────────────────────────────────────────────────────┘
```

### Dependency Strategy

**Zero new runtime dependencies.** All new features use:
- `std::process::Command` for `ss`, `lsof`, `dig` (same pattern as existing `git` calls)
- `ureq` for deps.dev API calls (already a dependency)
- `toml` for external rule files (already a dependency)
- Pure Rust for Levenshtein distance (~20 lines)

### Open Questions Resolved

| Question | Decision | Rationale |
|----------|----------|-----------|
| Rule ID for `.pth` detection | P009 | Typosquatting gets T001 (new prefix for trust/metadata checks) |
| Top-1000 package list for typosquatting | Bundled in binary as a const array | No network dep, updatable via releases |
| External rule format | TOML | serde_yaml was deliberately removed; toml crate is already present |
| deps.dev API stability | Add error handling for 404/5xx, graceful degradation | API is `v3alpha` — treat as unstable |
| Network monitoring approach | `ss -tnp` (Linux) / `lsof -i -n -P` (macOS) | Available everywhere, no root, no new deps |
| Baseline schema migration | Version 2 with per-process host maps | Backward-compatible: v1 files still parse |

---

## Implementation Phases

### Phase 1: Adaptive Detection

**Goal:** Surface 223K+ known malicious packages from OSV, add patterns for 2026's top attack vectors. Highest impact, lowest effort.

**Files to modify/create:**

```
src/checks/deps.rs         — Add MAL-* differentiation in OSV response handling
src/checks/patterns.rs     — Add P009-P012 rules
src/checks/trust.rs        — NEW: typosquatting, package metadata checks
src/checks/mod.rs          — Register new check module
src/scanner.rs             — Register TrustCheck
src/config.rs              — Add trust weight to ScoringConfig
depsec.baseline.json       — Add IMDS IPs to known-malicious list
```

#### 1a. MAL-* Malicious Package Detection

Currently `src/checks/deps.rs:160` reads `vuln["id"]` from OSV responses but doesn't differentiate between CVEs and malware reports. Change:

```rust
// src/checks/deps.rs — in the vulns loop
let id = vuln["id"].as_str().unwrap_or("UNKNOWN");
let is_malware = id.starts_with("MAL-");

let severity = if is_malware {
    Severity::Critical  // Always critical for known malware
} else {
    determine_severity(vuln)
};

let rule_id = if is_malware {
    format!("DEPSEC-MAL:{id}")
} else {
    format!("DEPSEC-V:{id}")
};

let message = if is_malware {
    format!("KNOWN MALICIOUS PACKAGE: {} {} — {summary}", pkg.name, pkg.version)
} else {
    format!("{severity}: {} {} — {summary}", pkg.name, pkg.version)
};
```

#### 1b. New Pattern Rules

| Rule ID | Name | Pattern | Catches | Source |
|---------|------|---------|---------|--------|
| P009 | `.pth` file with executable code | Scan `site-packages/**/*.pth` for `exec\|subprocess\|base64\|eval\|import os\|import sys` | LiteLLM 1.82.8 persistence | Snyk article |
| P010 | Cloud IMDS probing | `169\.254\.(169\.254\|170\.2)` in source code | AWS/GCP/ECS credential theft | LiteLLM payload |
| P011 | Environment serialization | `JSON\.stringify\(process\.env\)` and `os\.environ` patterns | StegaBin, SANDWORM | GuardDog `npm-serialize-environment` |
| P012 | Install script with remote fetch | Parse `package.json` `scripts.preinstall/postinstall` for `curl\|wget\|fetch\|node\s+\S+\.js` | StegaBin, CanisterWorm | Socket research |

#### 1c. Known-Malicious Network Indicators

Add to baseline checking — always flag these regardless of user baseline:

```rust
const KNOWN_MALICIOUS_IPS: &[&str] = &[
    "169.254.169.254",  // AWS IMDS — never contacted during builds
    "169.254.170.2",    // ECS credential endpoint
];
```

**Acceptance Criteria:**

- [ ] `MAL-*` OSV entries reported as "KNOWN MALICIOUS PACKAGE" with Critical severity
- [ ] `.pth` files in site-packages scanned for executable patterns (P009)
- [ ] IMDS IP patterns detected in source code (P010)
- [ ] `process.env` / `os.environ` serialization detected (P011)
- [ ] `package.json` install scripts with network calls flagged (P012)
- [ ] IMDS IPs always flagged in network baseline checks
- [ ] Tests for each new rule with positive and negative fixtures
- [ ] Self-scan still passes Grade A

---

### Phase 2: `depsec monitor` — Process-Attributed Network Monitoring

**Goal:** The flagship v2 feature. Wrap any command, watch its network activity, attribute connections to specific processes.

**Files to create/modify:**

```
src/monitor.rs             — NEW: core monitoring engine
src/monitor/poller.rs      — NEW: ss/lsof polling loop
src/monitor/baseline.rs    — NEW: behavioral baseline management
src/main.rs                — Add Monitor command
src/baseline.rs            — Extend Baseline struct for v2 schema
```

#### Command design:

```bash
depsec monitor npm install          # Watch network during npm install
depsec monitor --learn cargo build  # Record baseline (learning mode)
depsec monitor --strict pip install # Fail on unexpected connections
depsec monitor --json make test     # Machine-readable output
```

#### Technical approach:

**Linux (`ss -tnp` polling):**
```
1. Spawn child process (e.g., `npm install`)
2. Start polling loop: `ss -tnp` every 100ms
3. Parse output: local_addr, remote_addr, state, pid, process_name
4. For each new connection:
   a. Read /proc/<pid>/cmdline for full command
   b. Walk /proc/<pid>/.. parent chain to find root package manager
   c. Reverse DNS lookup on IP (with 2s timeout, cached)
5. Store: {timestamp, remote_host, remote_port, pid, process_name, cmdline}
6. When child exits: diff against baseline, report
```

**macOS (`lsof -i -n -P` polling):**
```
Same flow, but use `lsof -i -n -P +c0` instead of ss.
Parse: COMMAND, PID, USER, FD, TYPE, NODE, NAME (host:port).
Less granular parent chain — use `ps -o ppid= -p <pid>` to walk tree.
```

#### Behavioral baseline (v2 schema):

```json
{
  "version": 2,
  "created": "2026-03-27",
  "learned_from_runs": 5,
  "allowed": {
    "npm": ["registry.npmjs.org", "github.com"],
    "node": ["registry.npmjs.org"],
    "cargo": ["crates.io", "static.crates.io", "index.crates.io"],
    "python": ["pypi.org", "files.pythonhosted.org"],
    "*": ["github.com", "api.github.com", "api.osv.dev"]
  },
  "always_block": [
    "169.254.169.254",
    "169.254.170.2"
  ]
}
```

Backward-compatible: v1 baselines (flat `allowed_hosts`) still parse — treated as `"*": [...]`.

#### Learning mode:

```bash
depsec monitor --learn npm install
# Records all connections as "expected" for this project
# After 3-5 --learn runs, the baseline stabilizes
# Subsequent runs without --learn alert on deviations
```

Baselines stored in `.depsec/baselines/monitor-baseline.json` (per-project).

**Acceptance Criteria:**

- [ ] `depsec monitor <cmd>` wraps child process and captures network connections
- [ ] Each connection attributed to specific PID + process name + command line
- [ ] Linux: `ss -tnp` polling at 100ms intervals
- [ ] macOS: `lsof -i -n -P` fallback
- [ ] Reverse DNS for captured IPs (cached, 2s timeout)
- [ ] Diff against baseline with pass/fail report
- [ ] `--learn` mode records connections as expected
- [ ] `--strict` mode returns exit code 1 on unexpected connections
- [ ] `--json` output for machine consumption
- [ ] IMDS IPs always flagged regardless of baseline
- [ ] Handles short-lived connections (polling may miss <100ms connections — document limitation)
- [ ] Works without root/sudo (ss -tnp doesn't require it)
- [ ] Tests with mock `ss` output

---

### Phase 3: `depsec preflight` — Pre-Install Threat Analysis

**Goal:** Scan dependencies BEFORE installation. Answer: "Is it safe to `npm install` right now?"

**Files to create/modify:**

```
src/preflight.rs           — NEW: pre-install analysis engine
src/preflight/depsdev.rs   — NEW: deps.dev API client
src/preflight/typosquat.rs — NEW: Levenshtein distance checker
src/preflight/scripts.rs   — NEW: install script analyzer
src/main.rs                — Add Preflight command
data/popular_packages.rs   — NEW: bundled top-1000 package lists
```

#### Command design:

```bash
depsec preflight .                  # Full pre-install check
depsec preflight . --ecosystem npm  # Specific ecosystem
depsec preflight . --json           # Machine-readable
```

#### Sub-checks:

**3a. Install Script Analysis (`scripts.rs`)**

Parse `package.json` for scripts that execute during install:
```json
{
  "scripts": {
    "preinstall": "node ./scripts/setup.js",    // ← FLAG THIS
    "postinstall": "node ./scripts/build.js",   // ← FLAG THIS
    "prepare": "husky install"                   // ← OK (known tool)
  }
}
```

Flag scripts containing: `curl`, `wget`, `fetch`, `node <path>`, `python`, `sh`, `bash`, `powershell`, `eval`, `exec`.

Allowlist for known-safe scripts: `husky install`, `patch-package`, `node-gyp rebuild`, `tsc`, `esbuild`.

**3b. Typosquatting Detection (`typosquat.rs`)**

Pure Rust Levenshtein implementation (~20 lines). Bundle top-1000 packages per ecosystem as const arrays (compiled into binary — no network call needed):

```rust
// data/popular_packages.rs
pub const NPM_TOP_1000: &[&str] = &[
    "lodash", "express", "react", "axios", "chalk",
    "commander", "debug", "glob", "minimist", "semver",
    // ... generated from npm download stats
];

pub const PYPI_TOP_1000: &[&str] = &[
    "boto3", "requests", "urllib3", "setuptools", "certifi",
    // ... generated from PyPI download stats
];
```

For each dependency in the lockfile, compute Levenshtein distance against the top-1000 list. Flag if distance ≤ 2 AND the package name is NOT in the top-1000 itself.

New rule IDs: `DEPSEC-T001` (typosquat), `DEPSEC-T002` (new package < 7 days old), `DEPSEC-T003` (zero downloads), `DEPSEC-T004` (no source repo linked).

**3c. deps.dev API Integration (`depsdev.rs`)**

Query the free deps.dev API for package metadata:

```rust
// For each dependency:
let url = format!(
    "https://api.deps.dev/v3alpha/systems/{}/packages/{}/versions/{}",
    ecosystem, name, version
);
// Returns: publishedAt, licenses, advisoryKeys, slsaProvenances, links

// For scorecard:
let url = format!(
    "https://api.deps.dev/v3alpha/projects/github.com%2F{}%2F{}",
    owner, repo
);
// Returns: OpenSSF Scorecard with per-check scores
```

Flags:
- Package published < 7 days ago → `DEPSEC-T002` (Medium)
- Package has 0 SLSA provenances and no source repo link → `DEPSEC-T004` (Low)
- Scorecard "Dangerous-Workflow" score < 5 → `DEPSEC-T005` (Medium)
- Scorecard "Maintained" score = 0 → `DEPSEC-T006` (Low)

**3d. Lockfile Hash Verification**

Check that lockfiles include integrity hashes:
- `package-lock.json`: `integrity` field with `sha512-` prefix
- `yarn.lock`: `resolved` URL + `integrity` hash
- `Cargo.lock`: `checksum` field per package
- `Gemfile.lock`: no built-in hash support (skip)

Rule `DEPSEC-T007`: "Lockfile missing integrity hashes — packages not cryptographically verified."

**Acceptance Criteria:**

- [ ] `depsec preflight .` analyzes all dependencies before install
- [ ] Install scripts in `package.json` flagged with specific script content
- [ ] Typosquatting detection via Levenshtein distance against bundled top-1000 lists
- [ ] deps.dev API queried for package metadata (with graceful degradation on failure)
- [ ] Packages < 7 days old flagged
- [ ] Packages without source repos flagged
- [ ] OpenSSF Scorecard checks for dangerous workflows and maintenance status
- [ ] Lockfile hash verification across npm/yarn/Cargo ecosystems
- [ ] `--json` output
- [ ] No new dependencies added (pure Rust Levenshtein, ureq for API)
- [ ] Rate-limited API calls (1 req per package, max 50 concurrent)
- [ ] Tests with mock deps.dev responses

---

### Phase 4: Self-Improving Rules Infrastructure

**Goal:** Detection rules that evolve without recompiling the binary. Community-contributed rules.

**Files to create/modify:**

```
src/rules.rs               — NEW: rule loading, parsing, execution engine
src/rules/loader.rs        — NEW: TOML rule file parser
src/rules/engine.rs        — NEW: regex matching engine for external rules
src/main.rs                — Add Rules command
src/checks/patterns.rs     — Integrate external rules alongside built-in patterns
```

#### External Rule Format:

```toml
# .depsec/rules/pth-persistence.toml
[rule]
id = "COMMUNITY-001"
name = ".pth file with executable code"
severity = "critical"
description = "Python .pth startup hooks execute code on every interpreter launch"
category = "patterns"
references = ["https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/"]

[rule.match]
file_patterns = ["*.pth"]
content_patterns = ["subprocess", "exec\\(", "eval\\(", "base64", "import os", "import sys"]
scan_directories = ["site-packages"]
```

#### Commands:

```bash
depsec rules list              # Show all active rules (built-in + external)
depsec rules update            # Pull latest from github.com/chocksy/depsec-rules
depsec rules add ./my-rule.toml  # Add a custom rule
depsec rules test ./my-rule.toml # Test a rule against current project
```

#### Rule loading order:

1. Built-in rules (P001-P012, compiled into binary) — always active
2. Project rules (`.depsec/rules/*.toml`) — project-specific
3. Global rules (`~/.config/depsec/rules/*.toml`) — user-wide

Built-in rules cannot be overridden by external rules (security measure — an attacker who modifies `.depsec/rules/` can't disable built-in detection).

#### Community rules repo (`chocksy/depsec-rules`):

```
depsec-rules/
├── npm/
│   ├── serialize-environment.toml
│   ├── install-script-fetch.toml
│   └── dll-hijacking.toml
├── python/
│   ├── pth-persistence.toml
│   ├── setup-py-execution.toml
│   └── pickle-deserialization.toml
├── ruby/
│   ├── install-hook.toml
│   └── network-on-require.toml
└── meta/
    ├── mcp-config-tampering.toml
    ├── ide-config-integrity.toml
    └── git-hook-tampering.toml
```

**Acceptance Criteria:**

- [ ] TOML rule files parsed from `.depsec/rules/` directory
- [ ] External rules executed alongside built-in patterns
- [ ] `depsec rules list` shows all active rules with source (built-in/project/global)
- [ ] `depsec rules update` fetches from GitHub repo and writes to `.depsec/rules/`
- [ ] `depsec rules add` copies a rule file into the project rules directory
- [ ] Built-in rules cannot be overridden by external rules
- [ ] Malformed rule files produce clear error messages, not crashes
- [ ] Tests for rule loading, parsing, and execution

---

### Phase 5: Trust, Output & Developer Experience

**Goal:** Prove depsec's own integrity, make it invisible to use, and integrate with GitHub Security tab.

**Files to create/modify:**

```
src/selfcheck.rs           — NEW: self-integrity verification
src/sarif.rs               — NEW: SARIF 2.1.0 output formatter
src/shellhook.rs           — NEW: shell alias generator
src/main.rs                — Add SelfCheck, ShellHook commands; add --format sarif flag
README.md                  — Add "Why trust depsec?" section
```

#### 5a. `depsec self-check`

```bash
depsec self-check

# DepSec Self-Integrity Report
# ─────────────────────────────
# Binary:        depsec v0.2.0
# Dependencies:  98 crates (10 direct)
# Advisories:    0 known vulnerabilities (checked via OSV)
# Malware:       0 known malicious packages (checked via OSV MAL-*)
# Licenses:      all permissive (MIT, Apache-2.0, ISC, BSD-3, Unicode-3.0, CDLA-2.0)
# Sources:       all from crates.io (enforced by deny.toml)
# CI status:     ✓ fmt ✓ clippy ✓ 73 tests ✓ cargo-deny ✓ self-scan
# Network audit: ✓ CI connections monitored against baseline
#
# Trust chain:
#   ✓ Source: github.com/chocksy/depsec (public)
#   ✓ Dependencies: audited by cargo-deny + OSV on every commit
#   ✓ Network: build connections monitored in CI
#   ✗ Reproducible build: not yet implemented
#   ✗ SLSA attestation: not yet implemented
```

This runs `depsec scan .` on itself, checks OSV for MAL-* entries on its own deps, and reports the trust chain status. The `✗` items are honest about what's NOT yet implemented — transparency builds trust.

#### 5b. `depsec shell-hook`

```bash
eval "$(depsec shell-hook)"

# Outputs:
# alias npm='depsec monitor npm'
# alias npx='depsec monitor npx'
# alias yarn='depsec monitor yarn'
# alias pnpm='depsec monitor pnpm'
# alias pip='depsec monitor pip'
# alias pip3='depsec monitor pip3'
# alias cargo='depsec monitor cargo'
# alias go='depsec monitor go'
# alias bundle='depsec monitor bundle'
# echo "depsec: shell hooks active — all package installs monitored"
```

Add to `~/.zshrc` or `~/.bashrc` for always-on protection. Bypass with `\npm install` (backslash disables alias).

Detect shell type from `$SHELL` env var and output appropriate format (bash/zsh/fish).

#### 5c. SARIF Output

```bash
depsec scan . --format sarif > results.sarif
```

SARIF 2.1.0 schema. Map our Finding struct:

| Finding field | SARIF field |
|---------------|-------------|
| `rule_id` | `ruleId` |
| `severity` | `level` (error/warning/note) |
| `message` | `message.text` |
| `file` | `physicalLocation.artifactLocation.uri` |
| `line` | `physicalLocation.region.startLine` |
| `suggestion` | `fixes[].description.text` |

Enables uploading to GitHub Security tab via `github/codeql-action/upload-sarif`.

#### 5d. README "Why Trust DepSec?"

Add a section demonstrating our own security posture:

```markdown
## Why Trust DepSec?

DepSec audits itself with the same rigor it applies to your project:

| Check | Status | How |
|-------|--------|-----|
| Own dependencies | 0 advisories, 0 malware | OSV + MAL-* check on every CI run |
| Dependency sources | crates.io only | Enforced by deny.toml |
| Licenses | All permissive | Verified by cargo-deny |
| CI network | Monitored | tcpdump + baseline in every build |
| GitHub Actions | All SHA-pinned | depsec scans itself |
| Code quality | Clean | cargo fmt + clippy + 73 tests |

Run `depsec self-check` to verify independently.
```

**Acceptance Criteria:**

- [ ] `depsec self-check` reports own integrity with honest status for each trust chain link
- [ ] `depsec shell-hook` outputs correct aliases for bash/zsh/fish
- [ ] `depsec scan . --format sarif` produces valid SARIF 2.1.0 JSON
- [ ] SARIF output can be uploaded to GitHub Security tab via `upload-sarif` action
- [ ] README has "Why Trust DepSec?" section
- [ ] Shell hook only useful after `depsec monitor` exists (Phase 2)

---

## Alternative Approaches Considered

| Approach | Why Not Chosen |
|----------|---------------|
| eBPF for network monitoring | Requires kernel headers, root, compilation — breaks self-contained binary story |
| Cloud API for package reputation | Requires signup, API key — breaks "no cloud" philosophy |
| Plugin system for custom checks | Increases attack surface — contradicts security tool design |
| Async runtime for monitoring | Adds tokio back (~30 deps) — just removed it in v1 |
| YAML for external rules | serde_yaml was deliberately removed (deprecated + CVEs) |
| WebAssembly for rule execution | Over-engineering for v2, complex runtime |

## Acceptance Criteria

### Functional Requirements

- [ ] OSV MAL-* entries surfaced as "KNOWN MALICIOUS" with Critical severity
- [ ] 4+ new pattern rules for 2026 attack vectors (P009-P012)
- [ ] `depsec monitor <cmd>` with process-attributed network monitoring
- [ ] `depsec preflight .` with typosquatting + metadata + script analysis
- [ ] `depsec rules update/list/add` for external TOML rules
- [ ] `depsec self-check` proving own integrity
- [ ] `depsec shell-hook` for invisible protection
- [ ] `depsec scan . --format sarif` for GitHub Security tab
- [ ] Behavioral baselines that learn from repeated monitor runs

### Non-Functional Requirements

- [ ] Zero new runtime dependencies (all features use existing deps + std::process::Command)
- [ ] All 5 phases maintain Grade A self-scan
- [ ] Tests for every new rule and command
- [ ] `cargo clippy -- -D warnings` clean throughout
- [ ] Self-scan + cargo-deny pass in CI after each phase

### Quality Gates

- [ ] Each phase committed separately with passing CI
- [ ] Codex-investigator review after each phase
- [ ] `depsec self-check` reports 0 advisories + 0 malware after each phase

## Success Metrics

| Metric | Target |
|--------|--------|
| Detection coverage | Catch LiteLLM, StegaBin, SANDWORM, and CanisterWorm attack patterns |
| Self-scan grade | A (10/10) maintained throughout |
| New dependencies | 0 added |
| Test count | 100+ (up from 73) |
| `depsec monitor` viral moment | Process-attributed output showing a malicious postinstall phoning home |

## Dependencies & Prerequisites

- Existing v1 codebase (4,460 LOC, 73 tests, all passing)
- deps.dev API (free, no key, confirmed working)
- OSV API (already integrated, supports MAL-* queries)
- Top-1000 package lists (generate from npm/PyPI download stats)
- Community rules repo setup (chocksy/depsec-rules on GitHub)

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| deps.dev API changes (v3alpha) | Preflight metadata fails | Graceful degradation — skip metadata if API unavailable |
| `ss -tnp` not available on macOS | Monitor command broken on dev machines | Fallback to `lsof -i -n -P`; document platform differences |
| Short-lived connections missed by polling | False negatives in monitor | Document 100ms polling limitation; offer `--interval` flag |
| False positives in typosquatting | Noise for users | Require Levenshtein distance ≤ 2 AND package not in top-1000 |
| Community rules repo targeted by attackers | Malicious rules injected | Rules can only ADD detection, not disable built-in rules; PR review required |
| Rate limiting on deps.dev API | Preflight hangs on large projects | Batch queries, respect rate limits, cache responses |

## Future Considerations (v3+)

- **Community telemetry (opt-in)** — Anonymized scan summaries for anomaly detection across the user base
- **Crowd-sourced baselines** — `depsec baseline pull npm` for community-verified expected connections
- **Canary dependencies** — Plant fake package names to detect dependency confusion attacks
- **Time-travel scanning** — `depsec scan . --simulate-update` to preview upgrade safety
- **DNA fingerprinting** — Hash behavioral profiles of packages across versions
- **Reproducible builds** — Same source always produces same binary (bit-for-bit)
- **SLSA L3 attestation** — Cryptographic build provenance on releases
- **GitHub App** — Zero-config PR scanning without CI changes

## Documentation Plan

- Update README with new commands (monitor, preflight, rules, self-check, shell-hook)
- Add "Why Trust DepSec?" section to README
- Create `docs/rules.md` with complete rule reference (all DEPSEC-* IDs)
- Create `docs/monitor.md` with monitoring guide and platform differences
- Create `docs/preflight.md` with pre-install workflow guide
- Update `action.yml` to use `depsec monitor` for network capture

## References & Research

### Internal Research (read ALL before implementing)

- `docs/research/2026-03-27-supply-chain-attack-research.md` — 40+ attack vectors, gap analysis
- `docs/research/2026-03-27-attack-exploration-sources.md` — 23 data sources, GuardDog heuristics
- `docs/research/2026-03-27-competitive-landscape-and-network-differentiation.md` — Tool comparison, network monitoring levels
- `docs/research/2026-03-27-god-mode-brainstorm.md` — Monitor/preflight/shell-hook designs, deps.dev API
- `docs/research/2026-03-27-self-improving-system-design.md` — Adaptive architecture, rule files, self-check

### External References

- OSV API: https://google.github.io/osv.dev/api/ (batch query + MAL-* entries)
- deps.dev API: https://api.deps.dev (v3alpha — package metadata + scorecard)
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- GuardDog heuristics: https://github.com/DataDog/guarddog (MIT-licensed Semgrep rules)
- OpenSSF malicious packages: https://github.com/ossf/malicious-packages (223K+ entries)
- MITRE ATT&CK T1195: https://attack.mitre.org/techniques/T1195/ (supply chain taxonomy)
- Socket.dev blog: https://socket.dev/blog (real-time attack reports)
- StepSecurity harden-runner: https://github.com/step-security/harden-runner (CI network monitoring)

### Attack Reports Referenced

- LiteLLM backdoor (Snyk): `.pth` persistence, IMDS probing, encrypted exfil
- StegaBin (Socket): Steganographic C2, zero-width Unicode, 186-space IDE trick
- SANDWORM (Socket): MCP injection, bidirectional worm, polymorphic engine
- CanisterWorm (Socket): Token-based self-propagation, ICP blockchain C2
- Telnyx SDK (Socket): WAV steganography, fileless payload, memory-only execution
- TeamPCP campaign (Socket): Security tool targeting, disclosure suppression
