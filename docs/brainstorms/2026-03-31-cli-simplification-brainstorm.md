# Brainstorm: CLI Simplification — From 16 Commands to 5

**Date:** 2026-03-31
**Status:** Decided

## Problem

depsec has 16 CLI commands. For a tool aimed at "vibe coders" who just want to know if they're safe, this is overwhelming. Commands like `install-guard`, `preflight`, `secrets-check`, `monitor`, `baseline`, `attestation`, `shell-hook`, and `self-check` are confusing — users don't know which to run.

**Current commands:** scan, fix, monitor, preflight, install-guard, audit, hook, secrets-check, baseline, scorecard, badge, self-check, shell-hook, rules, attestation, cache

## What We're Building

Restructure the CLI around **5 primary commands** that cover 95% of usage, with power commands still accessible but not cluttering `--help`.

### The 5 Commands

```
depsec scan .              # Scan project for all security issues
depsec protect npm i       # Safe install with monitoring
depsec fix .               # Auto-fix security issues
depsec ci .                # CI-optimized scan (SARIF + exit codes)
depsec setup               # One-time configuration (hooks, baseline)
```

### Visible Utility Commands

```
depsec scorecard .         # Generate SVG scorecard
depsec badge .             # Output badge markdown
```

### Power Commands (available, not in main --help)

```
depsec cache clear         # Manage triage cache
depsec rules list          # Manage detection rules
```

## Command Mapping (Old → New)

| Old Command | New Location | Notes |
|-------------|-------------|-------|
| `scan` | `scan` | Unchanged — runs all checks by default |
| `scan --checks secrets` | `scan --checks secrets` | Same — filter to specific checks |
| `scan --triage` | `scan --triage` | Same |
| `scan --format sarif` | `ci` (default) or `scan --format sarif` | CI command defaults to SARIF |
| `secrets-check --staged` | `scan --staged --checks secrets` | Absorbed into scan |
| `audit shelljs` | `scan --deep shelljs` | Deep scan of one package, not a separate verb |
| `monitor` | `protect` | Absorbed |
| `preflight` | `protect` (runs automatically) | Absorbed |
| `install-guard` | `protect` | Renamed |
| `fix` | `fix` | Unchanged |
| `hook install` | `setup --hook` | Absorbed |
| `hook uninstall` | `setup --unhook` | Absorbed |
| `baseline init` | `setup --baseline` | Absorbed |
| `baseline check` | `ci` (runs automatically) | Absorbed |
| `shell-hook` | `setup --shell` | Absorbed |
| `self-check` | `scan --self` or removed | Niche |
| `attestation verify` | Power command | Kept but hidden |
| `attestation summary` | Power command | Kept but hidden |
| `cache clear/stats` | Power command | Kept but hidden |
| `rules list/update/add` | Power command | Kept but hidden |
| `scorecard` | `scorecard` | Visible utility |
| `badge` | `badge` | Visible utility |

## Key Decisions

1. **`scan` does everything by default** — all 5 check modules run. Use `--checks` to narrow.
2. **`protect` replaces install-guard/monitor/preflight** — one command wraps any package install with full protection (preflight + network monitoring + file watchdog).
3. **`ci` is a separate command** (not `scan --ci`) because CI behavior is fundamentally different: SARIF output, baseline network check, specific exit codes.
4. **`setup` is interactive one-time config** — installs hooks, initializes baselines, generates shell aliases. Subflags for specific pieces.
5. **`fix` stays as-is** — auto-pins GitHub Actions to SHAs.
6. **Deep audit is `scan --deep <pkg>`** — not a separate command. It's still scanning, just deeper on one package.
7. **Pre-commit hook calls `depsec scan --staged --checks secrets`** — no separate secrets-check command needed.
8. **Scorecard and badge are visible** — they produce user-facing artifacts.
9. **All commands visible in --help** — grouped by purpose (core / utilities / management) but all shown. No hidden commands.

## --help Output Design

All commands visible — no hidden commands. Grouped by purpose.

```
depsec v0.10.0 — Supply Chain Security Scanner

COMMANDS:
    scan       Scan project for security issues (all checks by default)
    protect    Monitor package installs for threats
    fix        Auto-fix security issues (pin actions to SHA)
    ci         CI-optimized scan (SARIF output, exit codes)
    setup      Configure hooks, baselines, and shell aliases

    scorecard  Generate SVG scorecard image
    badge      Output badge markdown
    audit      Deep LLM-powered audit of a specific package
    rules      Manage detection rules
    cache      Manage triage cache

Run 'depsec scan .' to get started.
```

## Open Questions

- Should `depsec` with no args run `scan .`? (semgrep does this)
- Should `setup` be interactive (wizard-style) or flag-based?
- Should we keep backward compatibility aliases for old commands during transition?

## Why This Approach

- **Trivy pattern** for scan targets (everything under `scan`)
- **Semgrep pattern** for CI separation (different command, not flag)
- **Cargo pattern** for aliases and discoverability
- **YAGNI** for power commands — don't show complexity users don't need
