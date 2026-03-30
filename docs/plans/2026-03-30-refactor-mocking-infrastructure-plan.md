---
title: "refactor: Add mocking infrastructure for 80%+ test coverage"
type: refactor
date: 2026-03-30
---

# refactor: Add mocking infrastructure for 80%+ test coverage

## Overview

Currently at **55% coverage** (265 tests, 2569/4677 lines). The gap is I/O-heavy code that can't be unit tested without mocks: LLM API calls, OSV HTTP queries, process spawning, and CLI handlers.

## Problem Statement

| Module | Coverage | Blocker | Uncovered LOC |
|--------|----------|---------|---------------|
| `audit.rs` | 0% | LLM API calls (ureq) | 332 |
| `commands/*.rs` | 0% | CLI dispatch, no logic | ~260 |
| `checks/deps.rs` | 26% | OSV API calls (ureq) | 104 |
| `triage.rs` | 59% | LLM API calls | 59 |
| `preflight.rs` | 18% | deps.dev API + `date` subprocess | 146 |
| `monitor.rs` | partial | process spawning + network polling | ~100 |
| `watchdog.rs` | 65% | lsof/proc filesystem | 56 |
| `hygiene.rs` | partial | GitHub API + git subprocess | ~60 |

## Proposed Solution

Two dev-dependencies, four trait boundaries, zero production dep changes.

### New dev-dependencies

```toml
[dev-dependencies]
mockall = "0.13"    # Trait-based mocking with #[automock]
httpmock = "0.8"    # Sync HTTP server mocking (works with ureq)
```

### Trait boundaries to introduce (priority order)

| # | Trait | Where | Unlocks |
|---|-------|-------|---------|
| 1 | `LlmApi` | `llm.rs` | triage (65 LOC) + audit (180 LOC) |
| 2 | URL injection on `query_osv_batch()` | `checks/deps.rs` | deps check (90 LOC) |
| 3 | URL injection on `check_package_metadata()` | `preflight.rs` | preflight metadata (65 LOC) |
| 4 | Replace `date` subprocess | `baseline.rs` + `preflight.rs` | 48 LOC (use std::time) |
| 5 | `GitRunner` trait | shared | hygiene + deps lockfile checks (45 LOC) |

## Implementation Phases

### Phase 1: Foundation — dev-deps + LlmApi trait

- [x] Add `mockall = "0.13"` and `httpmock = "0.8"` to `[dev-dependencies]` in `Cargo.toml`
- [x] Extract `LlmApi` trait from `LlmClient` in `src/llm.rs`
  - `fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse>`
  - `fn model(&self) -> &str`
  - `fn estimate_cost(&self, input_tokens: u32, output_tokens: u32) -> f64`
  - Use `#[cfg_attr(test, mockall::automock)]` on the trait
  - Move `chat_json<T>` to a free function `chat_json(client: &dyn LlmApi, ...)` — mockall can't handle generics on traits
  - `impl LlmApi for LlmClient` — keeps all existing code working
- [ ] Update `triage.rs`: `triage_findings(... client: &dyn LlmApi ...)` instead of `&LlmClient`
- [ ] Update `audit.rs`: `run_audit(... client: &dyn LlmApi ...)` instead of `&LlmClient`
- [ ] Update `commands/scan.rs` and `commands/audit_cmd.rs` to pass `&client as &dyn LlmApi`
- [ ] Write mock-based tests for `triage_findings()`:
  - `test_triage_classifies_true_positive` — mock returns TP
  - `test_triage_classifies_false_positive` — mock returns FP
  - `test_triage_handles_llm_error` — mock returns Err
  - `test_triage_respects_max_findings` — config.max_findings limit
  - `test_triage_uses_cache` — verify cache hit skips LLM call
- [ ] Write mock-based tests for `run_audit()`:
  - `test_audit_basic_analysis` — mock returns findings
  - `test_audit_self_verification_round` — mock returns verification
  - `test_audit_handles_llm_failure` — graceful error
- [ ] Run tarpaulin — target: 62%+

### Phase 2: httpmock for HTTP APIs

- [ ] Make `OSV_BATCH_URL` injectable in `query_osv_batch()`:
  - Add `osv_url: &str` parameter (or default to const when None)
  - Pass through from `DepsCheck::run()` via config or parameter
- [ ] Write httpmock tests for `query_osv_batch()`:
  - `test_osv_returns_vulnerability` — mock returns GHSA vuln
  - `test_osv_returns_malware` — mock returns MAL- prefixed vuln
  - `test_osv_no_vulns` — mock returns empty results
  - `test_osv_api_error` — mock returns 500
  - `test_osv_batch_pagination` — multiple packages, verify batching
- [ ] Make deps.dev URL injectable in `check_package_metadata()`:
  - Add `deps_dev_url: &str` parameter
- [ ] Write httpmock tests for `check_package_metadata()`:
  - `test_metadata_recently_published`
  - `test_metadata_no_repo`
  - `test_metadata_api_error`
- [ ] Make OpenRouter URL injectable in `LlmClient` (already `base_url` field — just expose in test constructors)
- [ ] Write httpmock tests for `LlmClient::chat()`:
  - `test_chat_parses_response` — mock returns valid JSON
  - `test_chat_handles_timeout` — mock delays
  - `test_chat_handles_malformed_json` — mock returns garbage
- [ ] Run tarpaulin — target: 72%+

### Phase 3: Process + git mocking

- [ ] Replace `date` subprocess in `baseline.rs` and `preflight.rs` with `std::time::SystemTime`
  - Delete `chrono_date()` function
  - Use `chrono` or manual formatting (no new deps — format YYYY-MM-DD manually)
- [ ] Extract `GitRunner` trait:

  ```rust
  #[cfg_attr(test, mockall::automock)]
  pub trait GitRunner {
      fn output(&self, args: &[&str], cwd: &Path) -> Result<std::process::Output>;
  }
  ```

  - Default impl calls `Command::new("git")`
  - Used by: `check_lockfile_committed` (deps + hygiene), `collect_scannable_files` (secrets), `check_branch_protection` (hygiene)
- [ ] Write mock-based tests for git-dependent functions:
  - `test_lockfile_committed_yes` — mock git check-ignore returns non-zero
  - `test_lockfile_committed_no` — mock git check-ignore returns zero
  - `test_branch_protection_no_token` — env var absent
  - `test_collect_scannable_files_fallback` — git fails, walkdir fallback
- [ ] Run tarpaulin — target: 78%+

### Phase 4: Final push to 80%+

- [ ] Add tests for `output.rs` rendering paths:
  - `test_render_ascii_scorecard`
  - `test_render_package_aggregate`
  - `test_render_deps_summary`
  - `test_render_rule_glossary`
- [ ] Add tests for `fixer.rs` edge cases:
  - `test_fix_already_pinned_action`
  - `test_fix_local_action_skipped`
- [ ] Add tests for `baseline.rs` uncovered paths:
  - `test_check_baseline_with_unexpected_hosts`
  - `test_parse_capture_file`
- [ ] Add integration tests for `commands/scan.rs` using httpmock (mock OSV) + mockall (mock LLM):
  - `test_scan_json_output`
  - `test_scan_sarif_output`
  - `test_scan_exit_code_with_findings`
- [ ] Run tarpaulin — target: **80%+**

## Acceptance Criteria

- [ ] Coverage reaches 80%+ (from 55%)
- [ ] No new production dependencies (mockall + httpmock are dev-only)
- [ ] All 265+ existing tests still pass
- [ ] `cargo clippy -- -D warnings` clean
- [ ] No `#[automock]` without `#[cfg_attr(test, ...)]` (zero production overhead)
- [ ] LlmApi trait is the only breaking internal API change

## Technical Considerations

### mockall + generics limitation

`mockall::automock` cannot handle generic methods. Solution: extract `chat_json<T>` from the trait into a free function that calls `client.chat()` and parses the response. The trait only needs `fn chat() -> Result<ChatResponse>`.

### httpmock is sync

Unlike wiremock (async-only), httpmock works with plain `#[test]` — perfect for ureq. No tokio dependency needed.

### Production code stays clean

- Traits use `#[cfg_attr(test, mockall::automock)]` — mock code compiled away in release
- URL injection uses default parameters or config, not test-specific flags
- No `#[cfg(test)]` in production logic paths

## References

- [mockall docs](https://docs.rs/mockall/latest/mockall/) — `#[automock]` attribute
- [httpmock docs](https://docs.rs/httpmock/latest/httpmock/) — sync HTTP mocking
- [Rust Design-for-Testability](https://alastairreid.github.io/rust-testability/)
- Current coverage: `coverage/tarpaulin-report.html`
- I/O boundary analysis: 5 HTTP call sites, 12 process spawn sites, 3 LLM usage sites
