---
title: "fix: Address code review findings from 4-agent review"
type: fix
date: 2026-03-31
---

# fix: Address Code Review Findings

## Overview

4 parallel review agents (Codex Investigator, Security Sentinel, Performance Oracle, Code Simplicity) identified 22 deduplicated findings across correctness, security, performance, and simplification. This plan addresses all quick wins and medium-effort fixes.

## Phase 1: Security Quick Wins

- [ ] Add `.follow_links(false)` to WalkDir in patterns.rs, capabilities.rs, secrets.rs
- [ ] Validate sandbox path chars in sandbox.rs (reject `"`, `(`, `)`)
- [ ] Add `--` separator before user args in bwrap/sandbox-exec invocations
- [ ] Sanitize `..` from package names in triage_cache.rs

## Phase 2: Correctness Quick Wins

- [ ] Guard OSV batch response with `chunk.get(i)` in deps.rs:159
- [ ] Add P014 to `is_ast_rule()` in patterns.rs:523
- [ ] Fix secret masking to use `.chars()` instead of byte slicing in secrets.rs:361
- [ ] Replace `date` shell-out with pure Rust `SystemTime` in preflight.rs:538
- [ ] Remove duplicate `"dotenv"` in NPM_TOP_PACKAGES in preflight.rs
- [ ] Fix `is_binary_ext` to avoid format! allocation in patterns.rs:541

## Phase 3: Scoring Determinism

- [ ] Sort findings by severity before scoring to ensure deterministic results in scoring.rs
- [ ] Remove `Severity::deduction_multiplier()` dead code (scoring uses inline logic)

## Phase 4: Performance Wins

- [ ] Pre-compile tree-sitter queries once in AstAnalyzer struct (ast/mod.rs, ast/javascript.rs)
- [ ] Move reachability scanning inside spinner scope (commands/scan.rs)
- [ ] Add `max_depth(10)` to patterns WalkDir
- [ ] Add recursion depth limit to collect_v1_deps in parsers/package_lock.rs

## Phase 5: Code Simplification

- [ ] Consolidate rule metadata: patterns.rs as single source, remove output.rs::rule_info() duplication
- [ ] Collapse 3 pseudo_random functions in canary.rs into 1 parameterized function
- [ ] Remove misleading `#[allow(dead_code)]` on attestation/canary/sandbox modules in main.rs
- [ ] Remove unused `LlmClient::from_env()` in llm.rs
- [ ] Remove `finding_visible()` wrapper in output.rs, use `finding_passes_persona()` directly
- [ ] Remove double filter for `--` flags in install_guard.rs:297

## Phase 6: Validate

- [ ] `cargo test` — 367+ tests pass
- [ ] `cargo clippy` — 0 warnings
- [ ] `depsec scan ~/Development/pos` — verify output quality maintained
