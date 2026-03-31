---
title: "feat: Wire Up All Broken/Dead Features"
type: feat
date: 2026-03-31
brainstorm: docs/brainstorms/2026-03-31-wire-everything-brainstorm.md
---

# Wire Up All Broken/Dead Features

## Overview

23 issues spanning silently ignored CLI flags, dead code modules, missing scanner integration, phantom scoring weights, stale README claims, and unfinished Python AST support. Every feature is already implemented or scaffolded — this plan wires them into production code paths.

## Problem Statement

Users trust the CLI to do what it advertises. Today:
- `--sandbox`, `--learn`, `--strict` on `protect` are silently ignored (hardcoded `false`)
- `--budget` on `audit` is parsed and discarded
- External rules can be downloaded but are never applied during scans
- Canary tokens are fully implemented but never called
- Attestation generation exists but is hidden behind deprecated commands
- README documents features that don't work

## Implementation Phases

### Phase 1: Protect Command Wiring (Critical Path)

**Goal:** Make `--sandbox`, `--learn`, `--strict` actually work on `depsec protect`.

#### 1.1 Pass CLI flags through main.rs

**File:** `src/main.rs` lines 375-391

Replace the destructured `_` discards with real variable names and pass them to `ProtectOpts`:

```rust
Commands::Protect {
    json,
    sandbox,      // was: sandbox: _
    learn,        // was: learn: _
    strict,       // was: strict: _
    preflight_only,
    command,
} => commands::protect::run(
    &command,
    &commands::protect::ProtectOpts {
        json,
        sandbox,    // was: false
        learn,      // was: false
        strict,     // was: false
        preflight_only,
    },
),
```

#### 1.2 Remove dead_code annotations from ProtectOpts

**File:** `src/commands/protect.rs` lines 5-14

Remove `#[allow(dead_code)]` from `sandbox`, `learn`, `strict` fields. These are now live.

#### 1.3 Expand install_guard signature

**File:** `src/install_guard.rs` line 10-15

Add `learn`, `strict`, `sandbox` parameters to `run_install_guard()`:

```rust
pub fn run_install_guard(
    args: &[String],
    root: &Path,
    config: &InstallConfig,
    json_output: bool,
    learn: bool,      // NEW
    strict: bool,     // NEW
    sandbox: bool,    // NEW
) -> Result<InstallGuardResult>
```

#### 1.4 Wire sandbox activation

**File:** `src/install_guard.rs` lines 66-89

When `sandbox` CLI flag is true OR `config.mode == "sandbox"`:
1. Call `sandbox::detect_sandbox(&config.sandbox)` (or `"auto"` if CLI flag)
2. If sandbox detected, run the actual install inside the sandbox via `sandbox::run_sandboxed()`
3. If sandbox detection fails, warn and fall through to unsandboxed monitor

#### 1.5 Wire learn/strict to monitor

**File:** `src/install_guard.rs` line 94

Pass `learn` and `strict` through to `monitor::run_monitor()`:

```rust
let monitor_result = monitor::run_monitor(
    args,
    baseline_path,   // was: None — derive from config or .depsec/baseline.json
    learn,           // was: false
    json_output,
)?;
```

For `strict`: after monitor completes, if `strict && monitor_result.unexpected > 0`, set `exit_code = 1` and `has_issues = true`.

#### 1.6 Update protect.rs run() to pass flags

**File:** `src/commands/protect.rs` lines 43-56

Thread `opts.sandbox`, `opts.learn`, `opts.strict` into the `install_guard::run_install_guard()` call.

#### 1.7 Remove module-level dead_code allows

**File:** `src/main.rs` lines 20-21

Remove `#[allow(dead_code)]` from `mod sandbox` — it's now live code.

---

### Phase 2: Canary Tokens + Attestation

**Goal:** Plant honeypot files in sandbox, auto-generate attestation after protect.

#### 2.1 Wire canary tokens into sandbox flow

**File:** `src/install_guard.rs` (new code in sandbox section)

Before sandboxed install:
1. `let tokens = canary::generate_canary_tokens(&sandbox_home)?;`
2. Run sandboxed install
3. Check if canary files were accessed (via monitor's file_alerts)
4. `canary::cleanup_canary_tokens(&tokens);`
5. If canary accessed → **fail the install** with clear message about credential theft attempt

Remove `#[allow(dead_code)]` from `mod canary` in `src/main.rs` line 6-7.

#### 2.2 Wire attestation into protect flow

**File:** `src/install_guard.rs` (after monitor phase, ~line 97+)

After monitor completes:
```rust
if config.attestation {
    let attestation = attestation::generate_attestation(
        &monitor_result, project_name, root
    );
    let path = attestation::save_attestation(&attestation, root)?;
    if !json_output {
        println!("  Attestation saved to {}", path);
    }
}
```

Remove `#[allow(dead_code)]` from `mod attestation` in `src/main.rs` line 2-3.

#### 2.3 Integrate attestation verify into scan output

Instead of hidden `depsec attestation verify/summary` commands, check attestation as part of hygiene:

**File:** `src/checks/hygiene.rs`

Add rule H005: "Install attestation exists and is valid" — check for `depsec.attestation.json`, verify signature if key is set. This makes attestation part of the score, no separate command needed.

Remove `#[command(hide = true)]` from attestation subcommand in `src/main.rs` line 197, OR remove the subcommand entirely if hygiene check covers it. Preference: keep `depsec attestation verify` as a utility but unhide it.

---

### Phase 3: External Rules + Scanner Integration

**Goal:** Downloaded rules actually get applied during scans.

#### 3.1 Wire apply_rules() into run_scan()

**File:** `src/scanner.rs` lines 41-87

After the existing check loop (line ~55), add:

```rust
// Apply external rules (loaded from .depsec/rules/ and ~/.config/depsec/rules/)
let external_rules = crate::rules::load_external_rules(root);
if !external_rules.is_empty() {
    let ext_findings = crate::rules::apply_rules(&external_rules, root);
    if !ext_findings.is_empty() {
        results.push(CheckResult {
            category: "external_rules".to_string(),
            findings: ext_findings,
            ..Default::default()
        });
    }
}
```

#### 3.2 Add scoring weight for external_rules

**File:** `src/config.rs`

Add `external_rules: u32` to `ScoringConfig` with default 0 (opt-in weight). Users can set it in `depsec.toml`:
```toml
[scoring]
external_rules = 5
```

#### 3.3 Remove dead_code from rules.rs

**File:** `src/rules.rs` line 105

Remove `#[allow(dead_code)]` from `apply_rules()` and any struct field annotations that are now live.

---

### Phase 4: Budget Enforcement on Audit

**Goal:** `--budget 5.0` caps LLM spend in USD.

#### 4.1 Thread budget into audit flow

**File:** `src/main.rs` lines 446-455

Pass `budget` instead of discarding it:
```rust
Commands::Audit {
    package,
    path,
    dry_run,
    budget,       // was: budget: _
} => {
    // ...
    commands::audit_cmd::run(&package, &root, dry_run, color, budget)
}
```

**File:** `src/commands/audit_cmd.rs`

Add `budget: f64` parameter to `run()`, thread it to `audit::run_audit()`.

#### 4.2 Implement cost gate in audit loop

**File:** `src/audit.rs` ~line 389

Add budget parameter to `run_audit()`. Track cumulative cost:

```rust
let mut total_cost = 0.0;
// Before each LLM call:
if total_cost >= budget {
    eprintln!("Budget limit ${:.2} reached (spent ${:.2}). Stopping.", budget, total_cost);
    break;
}
// After each LLM response:
if let Some(usage) = &response.usage {
    total_cost += client.estimate_cost(usage.prompt_tokens, usage.completion_tokens);
}
```

#### 4.3 Fix max_rounds misleading code

**File:** `src/audit.rs` line 539

`rounds: max_rounds.min(2)` always returns 2. Either increase the actual max or remove the `.min(2)` cap so the audit can do up to `max_rounds` if budget allows.

#### 4.4 Multi-ecosystem locate_package()

**File:** `src/audit.rs` line 81

Extend `locate_package()` to find packages in:
- `node_modules/<name>/` (existing)
- `target/release/build/` or via `cargo metadata` for Cargo crates
- `venv/lib/python*/site-packages/<name>/` or `pip show <name>` for pip
- `vendor/bundle/ruby/*/gems/<name>-*/` for gems
- `$GOPATH/pkg/mod/` or `go list -m -json <name>` for Go

Auto-detect ecosystem from package name format or add `--ecosystem` flag.

---

### Phase 5: Output + Scoring Fixes

**Goal:** Complete rule narratives, fix phantom weights.

#### 5.1 Add P013-P019 narratives to output.rs

**File:** `src/output.rs` lines 13-28

Add entries for P013 (dynamic-require), P014 (prototype-pollution), P015 (suspicious-postinstall), P017 (steganography-load), P018 (env-exfil), P019 (shadowed-builtin). Copy the narrative text from `PatternRule` definitions in `src/checks/patterns.rs`.

#### 5.2 Remove phantom network weight

**File:** `src/config.rs` line 75

Remove the `network: u32` field from `ScoringConfig` (default 10). No check produces "network" results, so this weight inflates the denominator. If network monitoring becomes a scan check later, re-add it.

Also remove `"network" => self.network` from `weight_for()` (~line 103).

#### 5.3 Fix capabilities weight in README config example

The README config example omits `capabilities` from the enabled checks list. Add it. Also add `capabilities = 10` to the scoring example.

---

### Phase 6: Shell Hooks + Legacy Cleanup

**Goal:** Fix deprecated command references.

#### 6.1 Fix shellhook.rs aliases

**File:** `src/shellhook.rs` line 21-22

Change `depsec install-guard {cmd}` to `depsec protect {cmd}`.

#### 6.2 Fix legacy hook.rs

**File:** `src/commands/hook.rs` line 10

Change `exec depsec secrets-check --staged` to `exec depsec scan --staged --checks secrets`.

#### 6.3 Fix selfcheck.rs trust claims

**File:** `src/selfcheck.rs` lines 73-78

Make trust chain claims conditional:
- "Dependencies: audited by cargo-deny" → only show checkmark if `deny.toml` was found (line 54 already checks this, reuse the result)
- "Network: build connections monitored in CI" → check for CI env var or `.github/workflows/` presence
- Keep the two `✗` items as-is (they're honest about not being implemented)

---

### Phase 7: Python AST with tree-sitter

**Goal:** Wire `tree-sitter-python` for AST-aware secret detection and pattern matching.

#### 7.1 Create src/ast/python.rs

Mirror the structure of `src/ast/javascript.rs`. Use `tree-sitter-python` to parse Python files and extract:
- Variable assignments with string literals (for secret detection)
- Import statements (for reachability)
- Function calls matching dangerous patterns (eval, exec, subprocess)

**Gotcha:** Use `while let Some(m) = matches.next()` pattern — tree-sitter's `QueryMatches` uses `StreamingIterator`, not standard `Iterator`.

#### 7.2 Replace regex scanning in secrets_ast.rs

**File:** `src/secrets_ast.rs` lines 191-206

Replace `scan_python_assignments()` regex approach with tree-sitter AST parsing:
- Parse the file with `tree-sitter-python`
- Query for `assignment` nodes where the right side is a `string` literal
- Extract variable name and value for entropy/pattern checking
- Handle f-strings, dict assignments, multi-line strings

#### 7.3 Add Python pattern rules

**File:** `src/checks/patterns.rs`

Add Python-specific pattern rules using AST:
- P020: `eval()` / `exec()` with string arguments
- P021: `subprocess.Popen` with `shell=True`
- P022: `os.system()` calls
- P023: `__import__()` dynamic imports

#### 7.4 Wire Python AST into reachability

**File:** `src/reachability.rs`

Add Python import resolution alongside existing JS/TS support. Parse `import X`, `from X import Y`, `__import__('X')`.

#### 7.5 Remove cargo-machete ignore

**File:** `Cargo.toml` line 30

Remove `tree-sitter-python` from `[package.metadata.cargo-machete] ignored` list — it's now used.

---

### Phase 8: README Accuracy

**Goal:** README matches reality.

#### 8.1 Capabilities check documentation

Add a section documenting the 8 combination rules (CAP:credential-exfiltration, dropper, etc.) and their 10pt weight.

#### 8.2 Document --staged flag

Add to the Secrets/Scan section: `depsec scan --staged --checks secrets` for pre-commit hooks.

#### 8.3 Fix sandbox documentation

Document `--sandbox` as `protect`-only. Show config + CLI usage:
```bash
depsec protect --sandbox npm install express
```

#### 8.4 Fix config example

Add `capabilities` to the enabled checks list. Fix scoring weights to match reality (remove `network`, add `capabilities`).

#### 8.5 Fix --learn and --strict docs

These will now actually work after Phase 1. Verify the documented behavior matches implementation.

#### 8.6 Document external rules end-to-end

Show the full workflow: `depsec rules update` → rules downloaded → applied automatically on next `depsec scan`.

#### 8.7 Document --budget on audit

Show usage with cost cap: `depsec audit lodash --budget 2.0`

---

## File Change Summary

| File | Changes |
|------|---------|
| `src/main.rs` | Pass protect flags, pass audit budget, remove 3x `#[allow(dead_code)]` on modules, unhide attestation |
| `src/commands/protect.rs` | Remove 3x `#[allow(dead_code)]`, wire flags to install_guard |
| `src/install_guard.rs` | Expand signature (+learn/strict/sandbox), wire sandbox+canary+attestation |
| `src/scanner.rs` | Add external rules call after check loop |
| `src/rules.rs` | Remove `#[allow(dead_code)]` from apply_rules() |
| `src/commands/audit_cmd.rs` | Add budget parameter, thread to audit |
| `src/audit.rs` | Add budget gate, fix max_rounds, expand locate_package() for all ecosystems |
| `src/llm.rs` | Add response `id` capture for future generation stats |
| `src/output.rs` | Add P013-P019 rule narratives |
| `src/config.rs` | Remove network weight, add external_rules weight |
| `src/selfcheck.rs` | Make trust claims conditional |
| `src/shellhook.rs` | Fix deprecated install-guard reference |
| `src/commands/hook.rs` | Fix deprecated secrets-check reference |
| `src/secrets_ast.rs` | Replace Python regex with tree-sitter AST |
| `src/ast/python.rs` | **NEW** — Python AST module |
| `src/checks/patterns.rs` | Add P020-P023 Python pattern rules |
| `src/reachability.rs` | Add Python import resolution |
| `src/checks/hygiene.rs` | Add H005 attestation check |
| `Cargo.toml` | Remove tree-sitter-python from machete ignore |
| `README.md` | Fix all documentation gaps |

## Acceptance Criteria

### Functional Requirements

- [ ] `depsec protect --sandbox npm install express` actually runs inside sandbox
- [ ] `depsec protect --learn npm install express` records connection baseline
- [ ] `depsec protect --strict npm install express` fails on unexpected connections
- [ ] `depsec audit lodash --budget 2.0` stops LLM calls when $2.00 is reached
- [ ] `depsec scan .` applies external rules from `.depsec/rules/`
- [ ] Canary tokens planted in sandbox, install fails if package reads them
- [ ] Attestation auto-generated after protect (when config.attestation = true)
- [ ] P013-P019 show narratives in scan output
- [ ] Python files scanned with tree-sitter AST for secrets
- [ ] Python pattern rules P020-P023 detect dangerous calls
- [ ] `depsec audit <pkg>` works for npm, Cargo, pip, gem, Go packages
- [ ] Shell hooks reference `protect` not `install-guard`
- [ ] Legacy pre-commit hook uses `scan --staged` not `secrets-check`
- [ ] Selfcheck trust claims are conditional on actual evidence
- [ ] Scoring weights sum correctly (no phantom network)
- [ ] README accurately reflects all features

### Quality Gates

- [ ] `cargo test` passes
- [ ] `cargo clippy` clean (no warnings)
- [ ] No remaining `#[allow(dead_code)]` on wired-up code (serde fields excepted)
- [ ] `cargo build --release` succeeds

## Risk Analysis

| Risk | Mitigation |
|------|------------|
| Sandbox backends may not be available in CI | Auto-detect gracefully falls through to unsandboxed with warning |
| tree-sitter StreamingIterator API confusion | Use `while let Some(m) = matches.next()` pattern (documented gotcha) |
| OpenRouter pricing hardcoded | Start with hardcoded, add live `/api/v1/models` fetch as follow-up |
| Multi-ecosystem audit scope creep | Start with npm+Cargo, add pip/gem/Go as incremental PRs if too large |
| Python AST queries may be complex | Mirror JavaScript AST patterns, start with assignments only |

## Implementation Order

Execute phases in order. Each phase should compile and pass tests independently:

1. **Phase 1** (protect wiring) — highest value, unblocks Phase 2
2. **Phase 2** (canary + attestation) — depends on Phase 1 sandbox wiring
3. **Phase 3** (external rules) — independent, can parallel with Phase 2
4. **Phase 4** (audit budget) — independent
5. **Phase 5** (output + scoring) — independent, quick wins
6. **Phase 6** (shell hooks) — independent, quick wins
7. **Phase 7** (Python AST) — most complex, save for last
8. **Phase 8** (README) — do after all code changes land

## References

- Brainstorm: `docs/brainstorms/2026-03-31-wire-everything-brainstorm.md`
- Tree-sitter plan: `docs/plans/2026-03-29-feat-tree-sitter-ast-integration-plan.md`
- Code health plan: `docs/plans/2026-03-31-refactor-code-health-improvement-plan.md`
- CLI simplification plan: `docs/plans/2026-03-31-refactor-cli-simplification-plan.md`
