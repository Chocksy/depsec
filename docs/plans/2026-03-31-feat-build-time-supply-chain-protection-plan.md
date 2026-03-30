---
title: "feat: Build-Time Supply Chain Protection"
type: feat
date: 2026-03-31
brainstorm: docs/brainstorms/2026-03-31-build-time-protection-brainstorm.md
---

# Build-Time Supply Chain Protection

## Overview

Connect depsec's existing features (monitor, baseline, shellhook, preflight) into a layered build-time protection pipeline. Add file access monitoring, sandbox pre-check, and build attestation. Default behavior is zero-friction monitoring; sandbox and attestation are opt-in.

## Problem Statement

`npm install` runs postinstall scripts with full developer permissions. The biggest supply chain attacks (event-stream, ua-parser-js, colors) happened at install/build time. depsec v0.4.1 labels build tools as "build-only" in scan output, but doesn't actually protect against build-time attacks.

The pieces exist but aren't connected: `monitor` captures network, `baseline` stores allowlists, `shellhook` intercepts installs, `preflight` checks typosquatting. This plan wires them together and fills the gaps.

## Technical Approach

### Architecture

```
Developer runs: npm install

Shell hook intercepts (shellhook.rs — already exists)
  │
  ├─ [Pre-check] depsec preflight (existing — typosquatting)
  │
  ├─ [During install] Enhanced Monitor (Layer 1)
  │   ├─ Network monitoring (existing — monitor.rs)
  │   ├─ File access watchdog (NEW — watch ~/.ssh, ~/.aws, etc.)
  │   └─ Write boundary check (NEW — writes outside node_modules/)
  │
  ├─ [Optional] Sandbox pre-check (Layer 2)
  │   ├─ Auto-detect: bubblewrap → Docker → skip
  │   └─ Run install in isolation first, verify, then real install
  │
  └─ [After install] Build Attestation (Layer 3)
      ├─ Generate depsec.attestation.json
      ├─ Record: network hosts, file access, sandbox result
      └─ Verify command for CI
```

---

## Implementation Phases

### Phase 1: Enhanced Monitor — File Watchdog

**Files to modify:** `src/monitor.rs`
**New file:** `src/watchdog.rs`

Extend the existing monitor to track sensitive file access alongside network connections.

**Approach: Process file descriptor monitoring**

Instead of OS-specific `fswatch`/`inotifywait` (which add dependencies and can't reliably detect reads), periodically scan `/proc/{child_pid}/fd` (Linux) or use `lsof -p {child_pid}` (macOS) to check if the child process has open file handles to sensitive paths.

```rust
// src/watchdog.rs
pub struct FileWatchdog {
    sensitive_paths: Vec<PathBuf>,
    alerts: Vec<FileAlert>,
}

pub struct FileAlert {
    pub path: String,
    pub pid: u32,
    pub process_name: String,
    pub access_type: String,  // "read" | "write"
}

const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.env",
    "~/.npmrc",
    "~/.config/gh",
    "~/.docker/config.json",
    "~/.kube/config",
];
```

**Integration with monitor.rs:**

```rust
// In run_monitor(), alongside the network polling thread:
// 1. Start file watchdog thread
// 2. Poll /proc/PID/fd or lsof every POLL_INTERVAL_MS
// 3. Check for open handles to SENSITIVE_PATHS
// 4. Collect alerts
// 5. Include in MonitorResult
```

**Update MonitorResult:**
```rust
pub struct MonitorResult {
    pub command: String,
    pub exit_code: i32,
    pub duration_secs: f64,
    pub connections: Vec<Connection>,
    pub expected: Vec<Connection>,
    pub unexpected: Vec<Connection>,
    pub critical: Vec<Connection>,
    pub file_alerts: Vec<FileAlert>,      // NEW
    pub write_violations: Vec<String>,     // NEW — writes outside expected dirs
}
```

**Acceptance criteria:**
- [ ] Monitor detects when child process opens ~/.ssh/id_rsa
- [ ] Monitor detects writes outside node_modules/ during install
- [ ] FileAlert includes PID, process name, and path
- [ ] Works on macOS (lsof) and Linux (/proc/pid/fd)
- [ ] Zero new crate dependencies (uses Command to call lsof/ls /proc)
- [ ] Polling interval matches existing network polling (100ms)

---

### Phase 2: Enhanced Monitor Output

**Files to modify:** `src/monitor.rs`, `src/main.rs`

Update the monitor output to show file access alerts alongside network connections:

```
depsec monitor — npm install completed (14.2s)

  Network: 3 connections
    ✓ registry.npmjs.org (expected)
    ✓ github.com (expected)
    ⚠ 45.33.32.156:443 (UNEXPECTED — not in baseline)

  File Access: 1 alert
    🔴 READ ~/.ssh/id_rsa — by node postinstall.js (pid 12345)

  Write Boundary: clean ✓
    All writes within node_modules/
```

**Acceptance criteria:**
- [ ] File alerts shown in human output with process attribution
- [ ] Write boundary violations listed
- [ ] JSON output includes `file_alerts` and `write_violations` arrays
- [ ] `--learn` mode adds file access patterns to baseline

---

### Phase 3: Install Config & Shell Hook Enhancement

**Files to modify:** `src/config.rs`, `src/shellhook.rs`

Add install configuration:

```toml
[install]
mode = "monitor"      # monitor | sandbox | report-only | none
preflight = true      # Run typosquatting check before install

[install.watch_paths]
# Additional sensitive paths to monitor (beyond defaults)
extra = ["~/.kube/config", "~/.docker/config.json"]

[install.network.allow]
# Per-package network allowlist
"puppeteer" = ["storage.googleapis.com"]
"playwright" = ["playwright.azureedge.net"]
"esbuild" = ["registry.npmjs.org"]
```

Enhance shell hooks to support the config:

```bash
# Current: alias npm='depsec monitor npm'
# Enhanced: alias npm='depsec install-guard npm'
```

New `install-guard` command orchestrates the pipeline:
1. Load config
2. If `preflight = true`: run preflight check on new packages
3. Run `monitor` with file watchdog enabled
4. Generate attestation if configured

**Acceptance criteria:**
- [ ] `[install]` config section in depsec.toml
- [ ] Shell hooks use `install-guard` instead of raw `monitor`
- [ ] Per-package network allowlist works
- [ ] Extra watch paths configurable

---

### Phase 4: Sandbox Pre-Check

**New file:** `src/sandbox.rs`

Opt-in sandbox that runs install in isolation before the real install.

**Auto-detection order:**
1. `bubblewrap` (Linux) — check: `which bwrap`
2. `docker` — check: `which docker && docker info`
3. None available → skip sandbox, warn user

**bubblewrap command:**
```bash
bwrap \
  --ro-bind / / \
  --tmpfs /root \
  --tmpfs $HOME/.ssh \
  --tmpfs $HOME/.aws \
  --tmpfs $HOME/.gnupg \
  --bind $SANDBOX_DIR/node_modules $SANDBOX_DIR/node_modules \
  --dev /dev \
  --proc /proc \
  --unshare-pid \
  -- npm install --prefix $SANDBOX_DIR
```

**Docker command:**
```bash
docker run --rm \
  -v $PROJECT_DIR/package.json:/app/package.json:ro \
  -v $PROJECT_DIR/package-lock.json:/app/package-lock.json:ro \
  -w /app \
  node:lts-slim \
  npm ci --ignore-scripts=false
```

**Flow:**
```
depsec install-guard --sandbox npm install new-pkg
  1. Copy package.json + lockfile to temp dir
  2. Detect sandbox technology
  3. Run install in sandbox with monitoring
  4. Analyze: any unexpected network? File access violations?
  5. If clean → proceed with real install
  6. If suspicious → warn, ask to continue (interactive) or fail (CI)
```

**Acceptance criteria:**
- [ ] Auto-detects bubblewrap or Docker
- [ ] Runs npm install in sandbox with restricted file access
- [ ] Monitors sandbox install for network and file access
- [ ] Reports sandbox results before proceeding
- [ ] `--sandbox` flag or `install.sandbox = "auto"` config
- [ ] Graceful skip if no sandbox available

---

### Phase 5: Build Attestation

**New file:** `src/attestation.rs`

Generate a signed JSON report after monitored installs/builds.

**Attestation format:**
```json
{
  "version": 1,
  "tool": "depsec",
  "tool_version": "0.5.0",
  "timestamp": "2026-03-31T10:00:00Z",
  "command": "npm install",
  "project": "pos-app",
  "lockfile_hash": "sha256:abc123...",
  "duration_secs": 14.2,
  "result": "CLEAN",
  "network": {
    "total": 3,
    "expected": 3,
    "unexpected": 0,
    "critical": 0,
    "hosts": ["registry.npmjs.org", "github.com", "api.github.com"]
  },
  "file_access": {
    "sensitive_reads": 0,
    "write_violations": 0
  },
  "sandbox": {
    "used": true,
    "type": "bubblewrap",
    "result": "CLEAN"
  },
  "signature": "sha256-hmac:def456..."
}
```

**Commands:**
```bash
# Generate attestation (happens automatically with monitor)
depsec monitor -- npm ci
# Creates depsec.attestation.json

# Verify attestation in CI
depsec attestation verify
# Checks: file exists, signature valid, result is CLEAN
# Exit 0 = clean, exit 1 = failed

# Show attestation summary (for PR comments)
depsec attestation summary
# Human-readable one-liner
```

**Signing:** HMAC-SHA256 with `DEPSEC_ATTESTATION_KEY` env var. If no key, attestation is unsigned (still useful, just not tamper-proof).

**Acceptance criteria:**
- [ ] `depsec.attestation.json` generated after monitored install
- [ ] Includes network hosts, file access, sandbox result
- [ ] `depsec attestation verify` checks attestation
- [ ] `depsec attestation summary` outputs human-readable line
- [ ] HMAC signing with DEPSEC_ATTESTATION_KEY
- [ ] Unsigned attestations work (warning but not error)
- [ ] Lockfile hash included for reproducibility check

---

### Phase 6: CI Integration

**New file:** `.github/actions/depsec-install/action.yml` (example)

GitHub Action that uses depsec for protected installs:

```yaml
# In user's CI workflow:
- uses: chocksy/depsec-install@v1
  with:
    command: npm ci
    sandbox: auto
    attestation: true
    fail-on-unexpected: true
```

This is documentation + an example action, not a code change to depsec itself.

**Acceptance criteria:**
- [ ] Example GitHub Action in docs/
- [ ] README section on CI integration
- [ ] `depsec attestation verify` works in CI (non-interactive)

---

## Files to Create/Modify

| File | Change |
|------|--------|
| `src/watchdog.rs` | **NEW** — file access monitoring |
| `src/sandbox.rs` | **NEW** — sandbox pre-check with auto-detect |
| `src/attestation.rs` | **NEW** — build attestation generation + verification |
| `src/monitor.rs` | Add file watchdog integration, write boundary check |
| `src/config.rs` | Add `[install]` config section |
| `src/shellhook.rs` | Update hooks to use `install-guard` |
| `src/main.rs` | Add `install-guard`, `attestation verify/summary` commands |

## Acceptance Criteria

### Functional
- [ ] `depsec monitor -- npm install` captures network + file access
- [ ] File access to ~/.ssh detected and reported
- [ ] Writes outside node_modules/ detected and reported
- [ ] Sandbox runs install in isolation (bubblewrap or Docker)
- [ ] Attestation JSON generated with network + file + sandbox data
- [ ] `depsec attestation verify` works in CI
- [ ] Config-driven behavior (`depsec.toml [install]` section)

### Non-Functional
- [ ] Zero new crate dependencies (use lsof/proc + existing ureq/sha2)
- [ ] Monitor overhead < 5% of install time
- [ ] Sandbox adds < 30s overhead for typical npm install
- [ ] Works on macOS and Linux

## Dependencies & Prerequisites

- Existing: `monitor.rs`, `baseline.rs`, `shellhook.rs`, `preflight.rs`
- bubblewrap: `apt install bubblewrap` (Linux) — optional
- Docker: optional, for sandbox fallback
- macOS: `lsof` (pre-installed), `sandbox-exec` (deprecated but still works through macOS 15)

## Risk Analysis

| Risk | Mitigation |
|------|------------|
| lsof/proc polling misses fast file access | Poll at 100ms + check file mtimes before/after |
| sandbox-exec deprecated on macOS | Use Docker as fallback, or lsof-based monitoring only |
| bubblewrap not installed on user's Linux | Graceful skip with suggestion to install |
| Docker daemon not running | Graceful skip, fall back to monitor-only |
| HMAC key not set | Generate unsigned attestation with warning |

## References

- Brainstorm: `docs/brainstorms/2026-03-31-build-time-protection-brainstorm.md`
- Existing monitor: `src/monitor.rs:64-92` (run_monitor function)
- Existing shellhook: `src/shellhook.rs` (alias generation)
- Existing baseline: `src/baseline.rs` (host allowlists)
- Existing preflight: `src/preflight.rs` (typosquatting)
- Socket.dev's `socket-npm` — similar concept (proxy-based install protection)
- Sandworm — runtime capability monitoring for Node.js
