# Brainstorm: Build-Time Supply Chain Protection

**Date:** 2026-03-31
**Status:** Draft
**Goal:** Protect developers from supply chain attacks that happen during `npm install` and `npm run build` — the attack vector behind event-stream, ua-parser-js, and colors.

---

## The Problem

depsec v0.4.1 correctly labels build tools as "BUILD TOOLS — not imported by your app." But this understates the risk:

**Build-time attacks are how the biggest compromises happened:**
- `event-stream` (2018): postinstall script stole bitcoin wallets
- `ua-parser-js` (2021): postinstall downloaded cryptominers
- `colors`/`faker` (2022): destructive code ran during require at build time
- `@lottiefiles/lottie-player` (2024): postinstall injected crypto drain into builds

**The attack chain:**
```
npm install
  → runs postinstall scripts with YOUR permissions
  → can read ~/.ssh, ~/.aws, GITHUB_TOKEN, .env
  → can modify node_modules (inject backdoors into other packages)
  → can phone home to attacker's C2 server
  → can modify build output (inject code into your bundle)
```

**Current depsec has the pieces but they're not connected:**
- `depsec scan` detects patterns but labels build tools as low risk
- `depsec monitor` captures network connections during commands
- `depsec baseline` stores expected network hosts
- `depsec shellhook` intercepts npm/pip/cargo install via zsh aliases
- `depsec preflight` checks for typosquatting before install

---

## What We're Building

A **layered build-time protection system** that connects existing features into a pipeline:

### Layer 1: Monitor (Default — Zero Friction)

**What:** Automatically monitor network connections + sensitive file access during `npm install`.

**How:** Shell hooks (`depsec shellhook`) already intercept install commands. Extend the monitor to:
1. Capture network connections (existing)
2. Watch for access to sensitive paths: `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.env`, `~/.npmrc` tokens
3. Watch for writes outside `node_modules/` (unexpected file modifications)
4. Report after install completes — never blocks

**File watchlist** (new — using `inotifywait` on Linux / `fswatch` on macOS):
```
~/.ssh/*           — SSH private keys
~/.aws/credentials — AWS credentials
~/.gnupg/*         — GPG keys
~/.env             — Environment secrets
~/.npmrc           — npm tokens
~/.config/gh/      — GitHub CLI tokens
```

**Output after install:**
```
depsec install monitor — npm install completed

  Network: 3 connections (all expected)
    ✓ registry.npmjs.org (package downloads)
    ✓ github.com (git dependencies)
    ✓ api.github.com (release assets)

  File access: No sensitive files accessed ✓

  Unexpected writes: None ✓
```

If something suspicious:
```
  ⚠ UNEXPECTED: Connection to 45.33.32.156:443 (unknown host)
    Process: node postinstall.js (pid 12345)
    Package: suspicious-pkg@1.0.0

  🔴 ALERT: Read access to ~/.ssh/id_rsa
    Process: node postinstall.js (pid 12345)
    Package: suspicious-pkg@1.0.0
```

### Layer 2: Sandbox Pre-Check (Opt-in)

**What:** Before installing, run the install in an isolated sandbox to see what it would do. If clean, proceed with the real install.

**How:** Auto-detect available sandboxing:
1. **bubblewrap** (Linux) — lightest, no daemon
2. **sandbox-exec** (macOS) — Apple's native sandbox
3. **Docker** — universal fallback

**Flow:**
```bash
# User enables in depsec.toml:
[install]
sandbox = "auto"  # auto | docker | bubblewrap | none

# Then:
npm install new-package
  → depsec intercepts via shellhook
  → Copies package.json + lockfile to temp dir
  → Runs install in sandbox with:
    - Network: allowed only to registries
    - File system: read-only except node_modules/
    - No access to home directory secrets
  → Captures all activity
  → If clean: proceeds with real install
  → If suspicious: warns and asks to continue
```

**Sandbox profiles:**

```
[sandbox-exec profile for macOS]
(deny default)
(allow network* (remote tcp "*:443"))     ; HTTPS only
(allow file-read* (subpath "/tmp/depsec-sandbox"))
(allow file-write* (subpath "/tmp/depsec-sandbox/node_modules"))
(deny file-read* (subpath (param "HOME") "/.ssh"))
(deny file-read* (subpath (param "HOME") "/.aws"))
```

```
[bubblewrap for Linux]
bwrap \
  --ro-bind / / \
  --bind /tmp/sandbox/node_modules /tmp/sandbox/node_modules \
  --tmpfs $HOME/.ssh \
  --tmpfs $HOME/.aws \
  --dev /dev \
  npm install
```

### Layer 3: Build Attestation (Core Feature)

**What:** After a monitored build, generate a signed report proving what happened. Attach to PRs, check into repo, verify in CI.

**Format: `depsec.attestation.json`**
```json
{
  "version": 1,
  "timestamp": "2026-03-31T10:00:00Z",
  "command": "npm install",
  "project": "pos-app",
  "lockfile_hash": "sha256:abc123...",
  "result": "CLEAN",
  "network": {
    "total_connections": 3,
    "expected": 3,
    "unexpected": 0,
    "hosts": ["registry.npmjs.org", "github.com"]
  },
  "file_access": {
    "sensitive_reads": 0,
    "unexpected_writes": 0
  },
  "sandbox": {
    "type": "bubblewrap",
    "profile": "strict"
  },
  "signature": "sha256-hmac:..."
}
```

**Use in CI (GitHub Actions):**
```yaml
- name: Install dependencies
  run: depsec monitor -- npm ci

- name: Verify build attestation
  run: depsec attestation verify
  # Fails CI if unexpected connections or file access detected
```

**Use in PR reviews:**
```yaml
- name: Attach attestation to PR
  run: |
    depsec monitor -- npm ci
    gh pr comment $PR_NUMBER --body "$(depsec attestation summary)"
```

### Layer 4: Configuration

```toml
# depsec.toml
[install]
# Default behavior when shellhook intercepts npm install
mode = "monitor"          # monitor | sandbox | report-only | none

# Sandbox settings
sandbox = "auto"          # auto | docker | bubblewrap | sandbox-exec | none

# File watchlist (additional paths to monitor)
watch_paths = [
    "~/.kube/config",     # Kubernetes credentials
    "~/.docker/config.json"
]

# Attestation
[install.attestation]
enabled = true
output = "depsec.attestation.json"
sign = true               # HMAC sign with DEPSEC_ATTESTATION_KEY

# Network allowlist (per-package overrides)
[install.network.allow]
"puppeteer" = ["storage.googleapis.com"]   # Puppeteer downloads Chromium
"esbuild" = ["registry.npmjs.org"]         # esbuild downloads platform binary
"playwright" = ["playwright.azureedge.net"] # Playwright downloads browsers
```

---

## Why This Approach

1. **Layered security** — each layer catches different attacks, none blocks the developer
2. **Connects existing features** — monitor, baseline, shellhook, preflight already exist, just need wiring
3. **Attestation is the differentiator** — no other CLI tool generates build attestations
4. **Auto-detect sandbox** — works everywhere without requiring Docker
5. **Config-driven** — developers choose their protection level, power users get full sandbox

---

## Key Decisions

1. **Default = monitor, never block** — zero friction for casual use
2. **Sandbox is opt-in** — developers explicitly choose to sandbox their installs
3. **Auto-detect sandbox technology** — bubblewrap → sandbox-exec → Docker → skip
4. **Build attestation is a core feature** — generates proof that builds are clean
5. **File watchlist uses OS-native tools** — fswatch (macOS) / inotifywait (Linux)
6. **Shell hooks are the entry point** — already intercept npm/pip/cargo install
7. **Config-driven behavior** — everything configurable in depsec.toml

---

## How It Connects to Existing Features

```
depsec shellhook (zsh aliases)
  │
  ├─ intercepts: npm install, pip install, cargo install
  │
  ├─ Layer 1: depsec monitor (existing)
  │  ├─ network monitoring (existing)
  │  ├─ file watchlist (NEW)
  │  └─ writes outside node_modules (NEW)
  │
  ├─ Layer 2: depsec sandbox (NEW)
  │  ├─ bubblewrap / sandbox-exec / Docker
  │  └─ runs install in isolation
  │
  ├─ Layer 3: depsec attestation (NEW)
  │  ├─ generates attestation JSON
  │  └─ verify command for CI
  │
  └─ depsec preflight (existing)
     └─ typosquatting + metadata checks
```

---

## Open Questions

1. **fswatch/inotifywait dependency** — should we ship our own file watching or use these as optional dependencies? Alternatively: just check file mtimes before/after install (simpler but less granular).
2. **Sandbox network filtering** — how to allow registry access but block arbitrary IPs in sandbox-exec profiles?
3. **HMAC signing** — what key? Environment variable `DEPSEC_ATTESTATION_KEY`? Or derive from lockfile hash?
4. **Windows support** — bubblewrap and sandbox-exec don't exist on Windows. Docker-only? Or skip sandbox on Windows?
5. **Performance** — does file watching add noticeable latency to `npm install`?
6. **Monorepo support** — `npm install` in a workspace root affects multiple packages. How to track per-workspace?
