---
title: "feat: Behavioral layering — compound risk scoring and noise reduction"
type: feat
date: 2026-03-31
---

# feat: Behavioral Layering — Compound Risk Scoring and Noise Reduction

## Overview

Transform depsec from a flat finding-dumper into a behavioral analysis tool that uses **compound risk scoring** to surface meaningful threats and suppress noise. Real-world testing against a POS app (Svelte+Tauri+Rust monorepo, 555 npm packages) revealed 6,731 lines of output, 212 false positives from one regex rule, and an F grade for a perfectly legitimate app.

Two sprints: Sprint 1 fixes bugs and reduces noise. Sprint 2 adds compound risk tiers, package-level aggregation, and scoring recalibration.

## Problem Statement

The current scanner treats every finding equally — a `regex.exec()` match gets the same red X as a credential exfiltration pattern. This makes output unusable for real projects:

- **6,731 lines** of verbose output (93% from patterns check alone)
- **212 false positives** from P001 regex matching `regex.exec()` as shell execution
- **Same package listed 6 times** for 6 different advisories (no dedup)
- **F grade (0.6/10)** for a legitimate app with no actual security issues
- **"Remove immediately"** for vitest, playwright, typescript (build tools doing build-tool things)

Research confirms: Socket.dev's answer is to **turn off capability alerts by default**. Our answer is smarter — use compound risk to make them meaningful.

## Technical Approach

### Architecture: Finding Flow After Changes

```
Check modules produce findings with .package field
    ↓
Reachability tagging (scan_app_imports)
    ↓
Package category detection (devDeps/deps/transitive)     ← NEW
    ↓
Compound risk tier assignment                             ← NEW
    ↓
Output aggregation (group by package, collapse low-tier)  ← NEW
    ↓
Scoring (tier-weighted deductions)                        ← MODIFIED
    ↓
Render (human/json/sarif)
```

### Key Files

| File | Changes |
|------|---------|
| `src/checks/patterns.rs` | Fix P001 AST gating, add .tsbuildinfo skip |
| `src/checks/deps.rs` | Add `.package` field to findings |
| `src/checks/capabilities.rs` | Compound risk tiers, category-aware severity |
| `src/checks/secrets.rs` | Path exclusions for git ls-files path |
| `src/checks/mod.rs` | No Severity enum change (use existing Low for INFO-equivalent) |
| `src/output.rs` | Package-level aggregation, reachability sections, deps dedup |
| `src/scoring.rs` | Tier-weighted deductions, MEDIUM-floor cap |
| `src/reachability.rs` | Expose `read_dev_dependencies()`, add package category |
| `src/preflight.rs` | Minimum name length for typosquat |
| `src/triage.rs` | Fix token estimation for findings without file context |
| `src/commands/misc.rs` | Fix badge output |
| `src/config.rs` | No changes needed (existing allow system stays) |

---

## Implementation Phases

### Phase 1: P001 AST Gating Fix (Sprint 1)

**File: `src/checks/patterns.rs`**

**Root cause:** `needs_ast` at line 308 only triggers for files containing `child_process`/`shelljs`/`execa`/`cross-spawn`. Files with `regex.exec()` never trigger AST, so the dumb P001 regex catches them.

**Fix: Gate P001 regex on dangerous module presence (Option A from brainstorm).**

Before the regex loop at line 343, add a check: if the file is JS/TS and does NOT contain any dangerous exec module string, skip P001 regex entirely. The AST path already handles files WITH dangerous modules correctly.

```rust
// src/checks/patterns.rs — inside the per-file regex loop
let has_dangerous_exec_module = content.contains("child_process")
    || content.contains("shelljs")
    || content.contains("execa")
    || content.contains("cross-spawn");

for (rule, re) in &compiled {
    // If AST analyzed this file, skip AST-handled rules
    if ast_handled && is_ast_rule(rule.rule_id) {
        continue;
    }
    // NEW: Skip P001 regex for JS/TS files without dangerous modules
    // regex.exec(), db.exec(), cursor.exec() are all benign
    if rule.rule_id == "DEPSEC-P001"
        && is_js_or_ts(path)
        && !has_dangerous_exec_module
    {
        continue;
    }
    // ... rest of matching
}
```

Also add `is_js_or_ts()` helper that checks file extension.

**Impact:** Kills 212 false positives. Zero false negatives — every real `child_process.exec()` file contains "child_process".

- [ ] Add `has_dangerous_exec_module` check before regex loop
- [ ] Add `is_js_or_ts()` helper function
- [ ] Gate P001 regex on module presence for JS/TS files
- [ ] Test: file with `regex.exec()` produces zero P001 findings
- [ ] Test: file with `child_process.exec(variable)` still flagged
- [ ] Test: file with `eval(variable)` still flagged (eval is NOT gated)

### Phase 2: File and Path Exclusions (Sprint 1)

**File: `src/checks/patterns.rs`**

Add to `SKIP_EXTENSIONS` array:
```rust
const SKIP_EXTENSIONS: &[&str] = &[
    ".map",
    ".d.ts",
    ".d.mts",
    ".d.cts",
    ".tsbuildinfo",  // NEW: TypeScript build cache, never executable
];
```

Add `.svelte-kit` to `SKIP_DIR_NAMES`:
```rust
const SKIP_DIR_NAMES: &[&str] = &[
    ".vite",
    ".svelte-kit",  // NEW: SvelteKit generated output, duplicates source
];
```

**File: `src/checks/secrets.rs`**

The `is_in_hidden_dir()` check already skips `.cursor/` and `.svelte-kit/` for the walkdir fallback path. But the `git ls-files` primary path at line 253 does NOT apply this filter.

Fix: Apply `is_in_hidden_dir()` to the git ls-files results too:

```rust
// src/checks/secrets.rs — in collect_scannable_files, git ls-files path
let files: Vec<PathBuf> = output
    .lines()
    .map(|l| root.join(l.trim()))
    .filter(|p| p.is_file())
    .filter(|p| !is_in_hidden_dir(p, root))  // NEW: apply hidden dir filter
    .filter(|p| !is_ignored(p, root, ignores))
    .filter(|p| !is_large_file(p))
    .collect();
```

Also skip `.tsbuildinfo` in secrets (it contains hashes but not secrets).

- [ ] Add `.tsbuildinfo` to `SKIP_EXTENSIONS` in patterns.rs
- [ ] Add `.svelte-kit` to `SKIP_DIR_NAMES` in patterns.rs
- [ ] Apply `is_in_hidden_dir()` to git ls-files results in secrets.rs
- [ ] Test: .tsbuildinfo files produce zero pattern findings
- [ ] Test: .cursor/ files produce zero secret findings

### Phase 3: Typosquat Fix (Sprint 1)

**File: `src/preflight.rs`**

Add minimum name length filter. Both the candidate AND the popular package must be >= 4 characters for Levenshtein comparison:

```rust
// src/preflight.rs — in check_typosquatting
for pkg in &packages {
    let pkg_name = &pkg.name;
    if pkg_name.len() < 4 { continue; }  // NEW: skip short names

    for popular in top_packages {
        if popular.len() < 4 { continue; }  // NEW: skip short targets too
        let dist = levenshtein(pkg_name, popular);
        if dist > 0 && dist <= 2 {
            // ... flag as typosquat
        }
    }
}
```

This kills false positives for `h2`, `ws`, `ms`, `slab`, `wasi`, etc.

- [ ] Add minimum length 4 filter for both candidate and target
- [ ] Test: "h2" no longer flagged as typosquat of "sha2"
- [ ] Test: "lodas" (5 chars, distance 1 from "lodash") still flagged

### Phase 4: Fix Badge and Triage Dry-Run (Sprint 1)

**Badge — File: `src/commands/misc.rs`**

Debug the badge command. Current code at line 250-266 should produce output. Verify:
1. Does `run_scan()` succeed for the target path?
2. Is `report.grade` populated?
3. Is the `println!` macro actually reached?

Fix: ensure badge always outputs to stdout, even on scan error.

**Triage dry-run — File: `src/triage.rs`**

At line 165-197, `dry_run_findings` calculates `total_chars` from `build_context()` which requires `.file` and `.line`. Deps findings (OSV advisories) lack these fields, so they contribute 0 chars.

Fix: for findings without file context, use the finding message + suggestion as prompt text estimate:

```rust
// src/triage.rs — in dry_run_findings
let context_text = if let Some(ctx) = build_context(finding, root, triage_config) {
    ctx
} else {
    // Fallback: use finding message + suggestion as context estimate
    format!("{}\n{}", finding.message, finding.suggestion.as_deref().unwrap_or(""))
};
total_chars += context_text.len();
```

- [ ] Debug badge empty output, add fallback stdout output on error
- [ ] Fix triage dry-run to estimate tokens for findings without file context
- [ ] Test: badge outputs markdown for POS app
- [ ] Test: triage dry-run shows non-zero token count for deps findings

### Phase 5: Add `.package` to Deps Findings (Sprint 2)

**File: `src/checks/deps.rs`**

This is the prerequisite for all Sprint 2 output improvements. Currently deps findings embed the package name in the message string but not in the `.package` field.

At the point where findings are created (around line 200), add `.with_package()`:

```rust
// src/checks/deps.rs — where vulnerability findings are created
Finding::new(rule_id, severity, message)
    .with_suggestion(suggestion)
    .with_package(Some(format!("{}@{}", pkg_name, pkg_version)))  // NEW
```

Note: use `name@version` format since deps findings are version-specific (different versions of the same package may have different vulnerabilities).

- [ ] Add `.with_package()` to all vulnerability findings in deps.rs
- [ ] Add `.with_package()` to malware findings in deps.rs
- [ ] Test: deps findings have `.package` field set
- [ ] Test: reachability tagging now works for deps findings

### Phase 6: Package Category Detection (Sprint 2)

**File: `src/reachability.rs`**

Expose the already-scaffolded `read_dev_dependencies()` function (currently `#[allow(dead_code)]`). Extend it to return a `PackageCategories` struct:

```rust
pub struct PackageCategories {
    pub production: HashSet<String>,      // in "dependencies"
    pub dev: HashSet<String>,             // in "devDependencies"
    pub all_declared: HashSet<String>,    // production + dev
}

pub fn read_package_categories(root: &Path) -> PackageCategories {
    let package_json = root.join("package.json");
    // Parse dependencies and devDependencies fields
    // Also check packages/*/package.json for monorepo workspaces
}
```

**For npm only in this sprint.** Scaffolded for Cargo.toml `[dev-dependencies]` and Gemfile groups later.

**File: `src/commands/scan.rs`**

After `scan_app_imports()`, also call `read_package_categories()` and use it to enrich the reachability tagging:

```rust
let categories = reachability::read_package_categories(root);
for result in &mut report.results {
    for finding in &mut result.findings {
        if let Some(pkg) = &finding.package {
            let pkg_base = pkg.split('@').next().unwrap_or(pkg);
            let is_imported = app_imports.packages.contains(pkg_base);
            let is_dev = categories.dev.contains(pkg_base);
            finding.reachable = Some(is_imported && !is_dev);
            // NEW: store category for output rendering
            // Use a convention: reachable=Some(true) = runtime imported
            //                   reachable=Some(false) = not imported / dev only
            //                   reachable=None = unknown
        }
    }
}
```

Note: We keep the existing `reachable` field semantics. Runtime-imported = `Some(true)`. Dev/build/transitive = `Some(false)`. Unknown = `None`.

- [ ] Expose and extend `read_dev_dependencies()` to `read_package_categories()`
- [ ] Handle monorepo workspace package.json files
- [ ] Wire into scan.rs post-processing
- [ ] Test: vitest finding has reachable=false (devDependency)
- [ ] Test: @supabase/supabase-js finding has reachable=true (production dep, imported)

### Phase 7: Package-Level Output Aggregation (Sprint 2)

**File: `src/output.rs`**

#### Deps Aggregation

Replace per-advisory listing with per-package grouping:

```
Before:
  ⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-34x7-hfp2-rc4v
  ⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-83g3-92jg-28cx
  ⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-8qq5-rm4j-mr97
  ... (6 lines for tar alone)

After:
  ⚠ tar@6.2.1 — 6 medium advisories
    → Run npm audit fix or update tar
```

Implementation: in `render_deps_section()`, group findings by `.package` field, show package once with advisory count + max severity.

#### Patterns Aggregation

Group by package, show rule summary:

```
Before:
  ✗ eval()/exec() ... (node_modules/@sveltejs/kit/src/runtime/client/client.js:1414)
  ✗ eval()/exec() ... (node_modules/@sveltejs/kit/src/runtime/client/parse.js:18)
  ✗ eval()/exec() ... (node_modules/@sveltejs/kit/src/runtime/server/respond.js:308)
  ... (15 lines for @sveltejs/kit alone)

After:
  ✗ @sveltejs/kit — 15 pattern findings (P001×12, P013×2, P014×1)
    → Build tool (devDependency), reachable=false
```

#### Capabilities Already Aggregated

The capabilities output already groups by package with the ACTION REQUIRED / BUILD TOOLS split. No changes needed beyond adjusting messaging (see Phase 8).

- [ ] Implement `group_findings_by_package()` utility function
- [ ] Rewrite deps human output to use per-package grouping
- [ ] Rewrite patterns human output to use per-package grouping with rule summary
- [ ] Keep `--verbose` flag showing all individual findings
- [ ] Update JSON output to include package grouping metadata
- [ ] Test: tar with 6 advisories shows as 1 grouped line
- [ ] Test: --verbose still shows all 6 individual advisories

### Phase 8: Compound Risk Tiers for Capabilities (Sprint 2)

**File: `src/checks/capabilities.rs`**

Instead of adding a new INFO severity (which would be a cross-cutting change), use the existing severity levels but assign them based on **package category + capability combination**:

```rust
// Tier mapping based on package category
fn tier_severity(
    combination: &CombinationRule,
    is_dev: bool,
    is_imported: bool,
) -> Severity {
    if is_dev && !is_imported {
        // Build tool / dev dependency: expected to have capabilities
        // Downgrade everything by 1-2 levels
        match combination.severity {
            Severity::Critical => Severity::Medium,  // dropper in devDep = suspicious not critical
            Severity::High => Severity::Low,
            _ => Severity::Low,
        }
    } else if is_imported {
        // Runtime dependency imported by app: full severity
        combination.severity
    } else {
        // Transitive: moderate
        match combination.severity {
            Severity::Critical => Severity::High,
            s => s,
        }
    }
}
```

This requires passing package category info into the capabilities check. Two options:
- **(A)** Pass `PackageCategories` into `CapabilitiesCheck::run()` via `ScanContext`
- **(B)** Do tier adjustment post-hoc in `commands/scan.rs` after reachability tagging

**Decision: Option B.** Keep the check pure (doesn't need external state). Adjust severity in the scan command after reachability and category are known:

```rust
// src/commands/scan.rs — after reachability tagging
for result in &mut report.results {
    if result.category == "capabilities" {
        for finding in &mut result.findings {
            if finding.reachable == Some(false) {
                // Downgrade build-tool capability findings
                finding.severity = downgrade_severity(finding.severity);
            }
        }
    }
}
```

Also update the capabilities output messaging:
- Replace "Remove immediately" with contextual messages:
  - Runtime: "Review — this production dependency has dangerous capability combinations"
  - Build: "Build tool — expected capabilities, verify if concerned"

- [ ] Add `downgrade_severity()` function
- [ ] Apply severity downgrade post-hoc for non-imported capability findings
- [ ] Update capability finding suggestion text based on package category
- [ ] Remove/soften "Remove immediately" messaging for build tools
- [ ] Keep existing CAPABILITY_ALLOWLIST as fallback (not replacing with categories)
- [ ] Test: vitest capability findings downgraded to Low (devDep)
- [ ] Test: ws capability findings stay at original severity (runtime dep, imported)

### Phase 9: Scoring Recalibration (Sprint 2)

**File: `src/scoring.rs`**

Current formula: `base_deduction = max_points / (num_findings + 1.0)`, then `per_finding = base_deduction * severity_multiplier * reachability_multiplier`.

Problems:
1. 68 medium advisories → each has severity_multiplier 1.0 → score drops to near 0
2. Build-tool findings only get 0.3x reduction, still significant at scale

Changes:

**A. Add MEDIUM-floor cap**: If ALL findings in a category are MEDIUM-or-below, score cannot drop below 30% of max:

```rust
// src/scoring.rs
let score = max(floor, max_points - sum_deductions);
let floor = if has_high_or_critical { 0.0 } else { max_points * 0.3 };
```

**B. Increase reachability discount**: Build-only findings get 0.1x multiplier (was 0.3x):

```rust
let reachability_multiplier = match finding.reachable {
    Some(false) => 0.1,  // was 0.3 — build tools barely affect score
    _ => 1.0,
};
```

**C. Adjust severity multipliers** for diminishing returns at scale:

```rust
// Apply diminishing returns: each additional finding of same severity has less impact
let severity_multiplier = match finding.severity {
    Critical => 3.0,
    High => 2.0,
    Medium => 1.0 / (1.0 + (medium_count as f64 * 0.1)),  // 10th medium finding = 0.5x
    Low => 0.3,  // was 0.5
};
```

**Expected POS app scores after changes:**
- Workflows: 1 unpinned (MEDIUM) + 2 permissions (LOW) → ~85% → B
- Deps: 68 medium advisories, no high/critical → floor 30% + diminishing → ~45% → D
- Patterns: ~50 findings after P001 fix, mostly Low (build tools at 0.1x) → ~80% → B
- Secrets: 4 findings (2 JWT in cursor=hidden, 2 key names=Low) → ~85% → B
- Hygiene: 2 LOW findings → ~95% → A
- Capabilities: 59 findings but 48 at 0.1x (build tools) → ~70% → C+
- **Estimated total: ~65-70% → C+ to B-** (was F at 0.6/10)

- [ ] Add MEDIUM-floor cap (30% if no HIGH/CRITICAL findings)
- [ ] Increase reachability discount from 0.3x to 0.1x for build-only
- [ ] Add diminishing returns for same-severity findings
- [ ] Reduce Low severity multiplier from 0.5 to 0.3
- [ ] Test: POS app scores in C-B range (not F)
- [ ] Test: project with actual critical findings still scores F
- [ ] Test: clean project still scores A

### Phase 10: Validation (Sprint 2)

Re-run ALL depsec commands against POS app and verify:

- [ ] `depsec scan ~/Development/pos` — output under 200 lines (was 6,731)
- [ ] `depsec scan ~/Development/pos --verbose` — shows everything but grouped
- [ ] `depsec scan ~/Development/pos --persona auditor` — shows all including low-confidence
- [ ] `depsec scan ~/Development/pos --format json` — valid JSON with package grouping
- [ ] `depsec scan ~/Development/pos --format sarif` — valid SARIF
- [ ] `depsec badge ~/Development/pos` — non-empty output
- [ ] `depsec scorecard ~/Development/pos` — SVG generated
- [ ] `depsec scan ~/Development/pos --triage-dry-run` — non-zero token estimate
- [ ] `depsec protect --preflight-only -- npm ls` — no false typosquat for h2/slab
- [ ] `depsec scan ~/Development/pos --checks capabilities` — tiered severity for build tools
- [ ] Grade is C+ to B- range for POS app (not F)
- [ ] Zero `regex.exec()` false positives
- [ ] No .tsbuildinfo entropy findings
- [ ] No .cursor/ secret findings
- [ ] `cargo test` — all existing tests pass
- [ ] `cargo clippy` — zero warnings

---

## Acceptance Criteria

### Functional Requirements

- [ ] P001 regex does not fire on JS/TS files without dangerous exec modules
- [ ] .tsbuildinfo, .svelte-kit/ files skipped in pattern scanning
- [ ] .cursor/ and hidden dirs skipped in secrets scanning via git ls-files path
- [ ] Typosquat check requires minimum 4-char package names
- [ ] Badge command produces non-empty output
- [ ] Triage dry-run shows realistic token estimate for all finding types
- [ ] Deps findings grouped by package in human output (advisory count, not individual listing)
- [ ] Pattern findings grouped by package with rule summary
- [ ] Deps findings have `.package` field for reachability tagging
- [ ] Package category (dev/prod/transitive) detected from package.json
- [ ] Capability finding severity adjusted based on package category
- [ ] Build-tool capability findings use descriptive messaging (not "Remove immediately")
- [ ] Scoring floor prevents all-MEDIUM categories from scoring 0
- [ ] Build-only findings have 0.1x score impact

### Non-Functional Requirements

- [ ] No new dependencies added
- [ ] Scan performance: no regression >10% on POS app
- [ ] All 367+ existing tests pass
- [ ] Zero clippy warnings
- [ ] JSON output schema backwards compatible (new fields only, no removed fields)

### Quality Gates

- [ ] POS app scan output under 200 lines (default persona)
- [ ] POS app grade C+ to B- (realistic, not demoralizing)
- [ ] Zero regex.exec() false positives across POS app scan
- [ ] Real project with actual malware dependencies still scores F

---

## Success Metrics

Run against POS app before and after:

| Metric | Before (v0.13.1) | Target |
|--------|----------|--------|
| Total output lines (default) | 6,731 | <200 |
| P001 false positives | 212 | 0 |
| Deps lines (tar×6, svelte×4) | 68 individual | ~20 grouped |
| Grade | F (0.6/10) | C+ to B- |
| Capabilities "Remove immediately" for build tools | 48 findings | 0 (contextual messaging) |
| Typosquat false positives (h2, slab, socket2) | 10 | 0 |
| Triage dry-run tokens | "~0" | Realistic estimate |
| Badge output | Empty | Shields.io markdown |

---

## Dependencies & Risks

**Risk: Scoring changes break CI pipelines**
Mitigation: Grade thresholds stay the same (A>=90, B>=75, etc.). Only the deduction formula changes. Document in changelog.

**Risk: JSON output schema changes break consumers**
Mitigation: Only add new fields (`.package` on deps findings). Never remove fields. Grouped output is human-format only; JSON still has individual findings array.

**Risk: P001 gating misses a real vulnerability**
Mitigation: The gate only suppresses P001 regex for files WITHOUT dangerous module strings. Every file that uses `child_process.exec()` contains the string "child_process" — the gate is correct by construction. eval() is NOT gated.

**Risk: Package category detection fails for non-npm projects**
Mitigation: npm-only in this sprint. Non-npm projects fall back to existing behavior (no category, no downgrade).

---

## Future Considerations (Layer 3, not this sprint)

- **Capability version diffing** — Track capability profiles per package@version, alert on new capabilities. The strongest zero-day signal per Capslock research (<2% of updates introduce new caps).
- **Provenance check** — npm provenance attestation as risk multiplier. One HTTP call per package.
- **Install-time stratification** — Capabilities in postinstall are 3-5x more suspicious than runtime code.
- **Multi-ecosystem categories** — Extend package category detection to Cargo.toml [dev-dependencies], Gemfile groups, Python.

---

## References

### Internal
- Brainstorm: `docs/brainstorms/2026-03-31-behavioral-layering-brainstorm.md`
- Prior brainstorm: `docs/brainstorms/2026-03-28-smart-analysis-brainstorm.md`
- Prior brainstorm: `docs/brainstorms/2026-03-28-layer1-smart-filtering.md`
- Capability analysis: `docs/brainstorms/2026-03-31-capability-analysis-brainstorm.md`
- Pattern rules: `src/checks/patterns.rs:22-170`
- AST engine: `src/ast/javascript.rs:1-50`
- Capabilities check: `src/checks/capabilities.rs`
- Scoring: `src/scoring.rs`
- Output rendering: `src/output.rs`
- Reachability: `src/reachability.rs`
- Preflight/typosquat: `src/preflight.rs:338-363`

### External Research
- Socket.dev: Default policy ignores most capability alerts — [docs.socket.dev](https://docs.socket.dev/docs/security-policy-default-enabled-alerts)
- Google Capslock: <2% of updates gain capabilities — [github.com/google/capslock](https://github.com/google/capslock)
- Cerebro: Behavior sequences, install-time stratification — [ACM TOSEM 2025](https://dl.acm.org/doi/10.1145/3705304)
- Sandworm: TOFU capability baseline — [github.com/sandworm-hq](https://github.com/sandworm-hq/sandworm-guard-js)
- LavaMoat: Per-package SES compartments — [github.com/LavaMoat](https://github.com/LavaMoat/LavaMoat)
