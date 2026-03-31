---
title: "refactor: CLI simplification — 16 commands to 10"
type: refactor
date: 2026-03-31
---

# refactor: CLI simplification — 16 commands to 10

## Overview

Restructure depsec's CLI from 16 top-level commands to 10, organized around 5 core commands + 5 utility commands. The goal: a vibe coder runs `depsec scan .` and understands the result. Power users get params, not separate commands.

## Problem Statement

Current CLI has 16 commands. Users don't know the difference between `scan`, `secrets-check`, `preflight`, `monitor`, `install-guard`, `baseline check`, `self-check`. These are implementation concepts leaking into the UX.

## Command Mapping

### Before (16 commands) → After (10 commands)

| Old Command | New Command | How |
|-------------|-------------|-----|
| `scan` | `scan` | Unchanged — all checks by default |
| `secrets-check --staged` | `scan --staged --checks secrets` | Absorbed into scan |
| `audit shelljs` | `audit shelljs` | Kept |
| `monitor npm test` | `protect npm test` | Renamed |
| `preflight .` | `protect --preflight-only .` | Absorbed into protect |
| `install-guard npm i` | `protect npm i` | Renamed (protect = preflight + monitor + watchdog) |
| `fix .` | `fix .` | Unchanged |
| `hook install` | `setup --hook` | Absorbed into setup |
| `hook uninstall` | `setup --unhook` | Absorbed into setup |
| `baseline init` | `setup --baseline` | Absorbed into setup |
| `baseline check` | `ci` (automatic) | Absorbed into ci |
| `shell-hook` | `setup --shell` | Absorbed into setup |
| `self-check` | `setup --self-check` | Absorbed into setup |
| `scorecard .` | `scorecard .` | Kept |
| `badge .` | `badge .` | Kept |
| `rules list/update/add` | `rules list/update/add` | Kept |
| `cache clear/stats` | `cache clear/stats` | Kept |
| `attestation verify/summary` | `attestation verify/summary` | Kept (power command) |
| (new) | `ci .` | New — CI-optimized scan |

### New --help Output

```
depsec v0.10.0 — Supply Chain Security Scanner

COMMANDS:
    scan         Scan project for security issues
    protect      Safe package installs with monitoring
    fix          Auto-fix security issues
    ci           CI-optimized scan (SARIF, exit codes)
    setup        Configure hooks, baselines, shell aliases

    scorecard    Generate SVG scorecard image
    badge        Output badge markdown
    audit        Deep LLM-powered package audit
    rules        Manage detection rules
    cache        Manage triage cache

OPTIONS:
    --no-color   Disable colored output
    -h, --help   Print help
    -V, --version Print version
```

## Implementation Phases

### Phase 1: Add `protect` command (absorbs install-guard + monitor + preflight)

`protect` wraps any command with full protection: preflight check → network monitoring → file watchdog → report.

- [ ] Create `src/commands/protect.rs`
  - `pub fn run(command: &[String], opts: &ProtectOpts) -> ExitCode`
  - `ProtectOpts { json, sandbox, learn, strict, preflight_only }`
  - Internally calls: `preflight::run_preflight` (if install command), `monitor::run_monitor`, reports results
  - `--sandbox` flag to opt into sandbox mode
  - `--learn` flag to record baseline
  - `--strict` flag to fail on unexpected connections
  - `--preflight-only` to just run typosquat checks without monitoring
- [ ] Add `Commands::Protect` variant to main.rs
- [ ] Wire into main.rs dispatch
- [ ] Tests: verify protect calls preflight + monitor in sequence

### Phase 2: Add `ci` command (scan + SARIF + baseline check)

`ci` runs a scan with CI-friendly defaults: SARIF output, no color, baseline network check, proper exit codes.

- [ ] Create `src/commands/ci.rs`
  - `pub fn run(root: &Path, checks: Option<&[String]>) -> ExitCode`
  - Internally calls `scanner::run_scan` with SARIF output
  - Runs `baseline::check_baseline` if baseline file exists
  - Exit code: 0 = clean, 1 = findings, 2 = error
  - Auto-enables `--no-color`
- [ ] Add `Commands::Ci` variant to main.rs
- [ ] Wire into main.rs dispatch
- [ ] Update `.github/workflows/ci.yml` to use `depsec ci .`
- [ ] Tests: verify ci produces SARIF and checks baseline

### Phase 3: Add `setup` command (absorbs hook + baseline init + shell-hook + self-check)

`setup` handles one-time configuration tasks.

- [ ] Create `src/commands/setup.rs`
  - `pub fn run(opts: &SetupOpts) -> ExitCode`
  - `SetupOpts { hook, unhook, baseline, shell, self_check, path }`
  - `--hook` → install pre-commit hook (current `hook install`)
  - `--unhook` → remove pre-commit hook (current `hook uninstall`)
  - `--baseline` → init baseline file (current `baseline init`)
  - `--shell` → print shell aliases (current `shell-hook`)
  - `--self-check` → run self-integrity check (current `self-check`)
  - No flags → run all setup steps interactively
- [ ] Add `Commands::Setup` variant to main.rs
- [ ] Wire into main.rs dispatch
- [ ] Tests: verify each flag calls the right function

### Phase 4: Absorb secrets-check into scan

- [ ] Add `--staged` flag to `Commands::Scan`
  - When `--staged` is set: get staged files from git, run only secrets check on them
  - This is what the pre-commit hook calls
- [ ] Update pre-commit hook content in `commands/setup.rs`:
  - Old: `exec depsec secrets-check --staged`
  - New: `exec depsec scan --staged --checks secrets`
- [ ] Keep `SecretsCheck` as hidden alias for backward compat (deprecated)

### Phase 5: Remove old commands + update help

- [ ] Remove `Commands::Monitor` (replaced by `protect`)
- [ ] Remove `Commands::Preflight` (replaced by `protect --preflight-only`)
- [ ] Remove `Commands::InstallGuard` (replaced by `protect`)
- [ ] Remove `Commands::Hook` (replaced by `setup --hook/--unhook`)
- [ ] Remove `Commands::Baseline` (Init → `setup --baseline`, Check → `ci`)
- [ ] Remove `Commands::ShellHook` (replaced by `setup --shell`)
- [ ] Remove `Commands::SelfCheck` (replaced by `setup --self-check`)
- [ ] Mark `Commands::SecretsCheck` as `#[command(hide = true)]` for backward compat
- [ ] Delete `src/commands/hook.rs` and `src/commands/secrets.rs` (code moved to setup.rs and scan.rs)
- [ ] Update `src/commands/mod.rs`
- [ ] Verify `--help` shows exactly the 10 commands in correct grouping
- [ ] Update README.md Usage section

### Phase 6: Update documentation + test on real apps

- [ ] Update README.md with new command structure
- [ ] Update depsec.toml example in README
- [ ] Test on ~/Development/pos — `depsec scan .` works
- [ ] Test on ~/Development/hubstaff-cli — `depsec scan .` works
- [ ] Test `depsec protect npm install lodash` on a test dir
- [ ] Test `depsec ci .` produces SARIF
- [ ] Test `depsec setup --hook` installs hook
- [ ] Run full test suite — all 292+ tests pass
- [ ] Run clippy + fmt
- [ ] Build release binary and verify `--help` output

## Acceptance Criteria

- [ ] `depsec --help` shows exactly 10 commands grouped as designed
- [ ] `depsec scan .` runs all checks (unchanged behavior)
- [ ] `depsec scan --staged --checks secrets` replaces secrets-check
- [ ] `depsec protect npm install lodash` runs preflight + monitor + watchdog
- [ ] `depsec ci .` outputs SARIF + checks baseline + proper exit codes
- [ ] `depsec setup --hook` installs pre-commit hook
- [ ] `depsec setup --baseline` initializes baseline file
- [ ] `depsec setup --shell` prints shell aliases
- [ ] Old commands still work as hidden aliases (backward compat)
- [ ] All existing tests pass
- [ ] CI workflow updated to use `depsec ci .`

## Technical Considerations

- **Backward compatibility**: Keep old command names as `#[command(hide = true)]` aliases for one major version. Users who scripted `depsec install-guard npm install` won't break.
- **Pre-commit hook update**: Existing hooks in user repos call `depsec secrets-check --staged`. The hidden alias ensures they keep working. New installs via `setup --hook` use the new syntax.
- **No core module changes**: All changes are in `main.rs` and `commands/*.rs`. The core scan/monitor/triage logic is untouched.

## References

- Brainstorm: `docs/brainstorms/2026-03-31-cli-simplification-brainstorm.md`
- CLI research: gitleaks (4 cmd), semgrep (11 cmd), trivy (17 cmd), cargo (20 cmd)
- Current main.rs: `src/main.rs` (339 lines)
- Command modules: `src/commands/{scan,audit_cmd,hook,misc,secrets}.rs`
