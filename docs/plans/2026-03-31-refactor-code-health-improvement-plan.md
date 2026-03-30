---
title: "refactor: Code Health Improvement — Coverage, Dedup, Dead Code"
type: refactor
date: 2026-03-31
---

# Code Health Improvement Plan

## Overview

depsec grew from v0.2.0 → v0.8.0 in 2 sessions (13,562 lines, 25 files, 182 tests). Fast growth left code health debt: 44.66% test coverage, duplicated functions, 17 `#[allow(dead_code)]` annotations, and large files needing split.

## Current State

**Coverage:** 44.66% (2,176/4,872 lines) — target: 70%+
**Dead code:** 17 `#[allow(dead_code)]` annotations across 7 files
**Duplicated code:** `shannon_entropy()` duplicated, Finding construction boilerplate (35+ instances)
**Large files:** main.rs (932 lines), audit.rs (727), output.rs (689)

## Phase 0: Wire Scaffolded Features (NOT Dead Code!)

These features have modules built and tested in isolation but are NOT wired into the main pipeline. They were presented as "shipped" but are actually incomplete:

| Feature | Module | What's Missing |
|---------|--------|----------------|
| Canary tokens | `canary.rs` | Call `generate_canary_tokens()` from sandbox before sandboxed install |
| Attestation generation | `attestation.rs` | Call `generate_attestation()` + `save_attestation()` from install-guard after monitor completes |
| Python AST analysis | `tree-sitter-python` dep | Implement Python AST scanning in `secrets_ast.rs` (currently uses regex) |
| Import location display | `reachability.rs` | Show "Your app imports this at file:line" in output.rs for runtime findings |
| External rules engine | `rules.rs` | Wire `apply_rules()` into scanner.rs `run_scan()` |
| Config watch_paths | `config.rs` | Add integration test verifying extra paths are monitored |

**Acceptance criteria:**
- [ ] Canary tokens placed in sandbox before install
- [ ] Attestation generated after install-guard completes
- [ ] Python AST scanning implemented (not just regex)
- [ ] Import locations shown in pattern output for runtime findings
- [ ] External rules applied during scan
- [ ] Integration test for watch_paths config

## Phase 1: Eliminate Dead Code

Remove `#[allow(dead_code)]` and either use the code or delete it:

| File | Annotation | Action |
|------|-----------|--------|
| `main.rs:2` | `mod attestation` | Wire attestation into install-guard (generates after monitored install) |
| `main.rs:6` | `mod canary` | Wire canary into sandbox (place tokens before sandboxed install) |
| `main.rs:19` | `mod sandbox` | Already wired into install-guard — remove allow |
| `llm.rs:5,7` | `DEFAULT_MODEL`, `DEFAULT_TIMEOUT_SECS` | Used by `from_env()` — move into that function or use them |
| `llm.rs:49` | `ChatResponse.model` | Return model info in triage output |
| `llm.rs:70` | `from_env()` | Used in tests — keep, remove allow |
| `rules.rs:19,35,46,105` | Multiple fields | External rule format — keep fields, remove allows |
| `audit.rs:344,507` | Response fields | Used via serde — keep, use `#[allow(dead_code)]` only on serde structs |
| `patterns.rs:11,15` | PatternRule.name/narrative | Used by output.rs rule_info() — misdetection, remove allow |
| `install_guard.rs:128` | InstallGuardResult fields | Return to caller — use in output or remove struct |
| `reachability.rs:12` | AppImports.locations | Use for "Your app imports this at file:line" display |

**Acceptance criteria:**
- [ ] Reduce `#[allow(dead_code)]` from 17 → ≤3 (only justified serde struct fields)
- [ ] Wire attestation into install-guard (generate after install)
- [ ] Wire canary into sandbox (place before sandboxed install)
- [ ] Use reachability locations in output ("imported at file:line")

## Phase 2: Centralize Duplicated Code

### 2.1: Shared `shannon_entropy()`

Create `src/utils.rs` with shared utilities:

```rust
// src/utils.rs
pub fn shannon_entropy(s: &str) -> f64 { ... }
pub fn mask_value(value: &str, max_visible: usize) -> String { ... }
pub fn truncate_line(line: &str, max: usize) -> String { ... }
```

Remove duplicates from `patterns.rs` and `secrets_ast.rs`.

### 2.2: Finding builder

Create a builder to reduce Finding construction boilerplate:

```rust
impl Finding {
    pub fn new(rule_id: &str, severity: Severity, message: String) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            confidence: None,
            message,
            file: None,
            line: None,
            suggestion: None,
            package: None,
            reachable: None,
            auto_fixable: false,
        }
    }

    pub fn with_file(mut self, file: &str, line: usize) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self
    }

    pub fn with_confidence(mut self, conf: Confidence) -> Self {
        self.confidence = Some(conf);
        self
    }
    // etc.
}
```

Reduces 10-line Finding construction to 3-4 lines.

**Acceptance criteria:**
- [ ] `src/utils.rs` with shared entropy/mask/truncate functions
- [ ] Finding builder pattern reduces construction boilerplate
- [ ] Zero duplicated functions across codebase

## Phase 3: Improve Test Coverage (44% → 70%+)

Priority by impact (modules with 0% or <30% coverage):

| Module | Current | Target | What to Test |
|--------|---------|--------|-------------|
| `triage.rs` | 0% | 50%+ | Context extraction, prompt building, result parsing |
| `selfcheck.rs` | 0% | 50%+ | Binary integrity check |
| `sandbox.rs` | 18% | 50%+ | Detection logic, profile generation (not actual sandbox) |
| `preflight.rs` | 19% | 40%+ | Typosquatting detection, metadata checks |
| `main.rs` | 29% | 40%+ | CLI argument parsing, command routing |
| `watchdog.rs` | 37% | 60%+ | Path matching, process tree parsing |
| `output.rs` | 47% | 60%+ | Rendering functions, aggregation, glossary |

**Acceptance criteria:**
- [ ] Overall coverage ≥ 70%
- [ ] No module at 0% coverage
- [ ] Coverage report in CI (cargo-tarpaulin in GitHub Actions)

## Phase 4: Code Organization

### 4.1: Split `main.rs` (932 lines → ~200 lines)

Extract command handlers into separate modules:

```
src/
├── main.rs              # CLI definition + routing only (~200 lines)
├── commands/
│   ├── mod.rs
│   ├── scan.rs          # Scan command handler
│   ├── audit.rs         # Audit command handler
│   ├── install_guard.rs # (already separate)
│   ├── hook.rs          # Hook install/uninstall
│   └── cache.rs         # Cache management
```

### 4.2: Split `output.rs` (689 lines)

```
src/
├── output/
│   ├── mod.rs           # ScanReport, render_human dispatch
│   ├── human.rs         # Human output rendering
│   ├── scorecard.rs     # ASCII scorecard (currently in separate file — merge or keep)
│   └── glossary.rs      # Rule guide rendering
```

**Acceptance criteria:**
- [ ] `main.rs` under 250 lines
- [ ] No file over 500 lines (except generated/data files)

## Phase 5: Tooling — Code Quality Dashboard

### Rust Code Health Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `cargo-tarpaulin` | Test coverage (HTML report like SimpleCov) | ✅ Already installed |
| `cargo-udeps` | Find unused dependencies | `cargo install cargo-udeps` |
| `cargo-bloat` | Find what's making the binary big | `cargo install cargo-bloat` |
| `cargo-machete` | Fast unused dependency detection | `cargo install cargo-machete` |
| `cargo-geiger` | Count unsafe code | `cargo install cargo-geiger` |

### CI Integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: Coverage
  run: |
    cargo install cargo-tarpaulin
    cargo tarpaulin --out Xml
    # Upload to codecov.io or similar

- name: Unused deps
  run: |
    cargo install cargo-machete
    cargo machete
```

**Acceptance criteria:**
- [ ] Coverage report generated in CI
- [ ] Unused dependencies detected and removed
- [ ] Binary bloat analysis run once

## Phase 6: README Update

The README needs a major update to reflect v0.8.0 capabilities:

- Benchmark results (2000/2000 detection rate)
- Feature overview (AST engine, reachability, LLM triage, sandbox, canary tokens)
- Quick start guide
- Configuration reference
- Comparison with gitleaks/TruffleHog/GuardDog

## Success Metrics

| Metric | Before | Target |
|--------|--------|--------|
| Test coverage | 44.66% | ≥70% |
| `#[allow(dead_code)]` | 17 | ≤3 |
| Duplicated functions | 2+ | 0 |
| Largest file | 932 lines | ≤500 lines |
| Unused deps | Unknown | 0 |
