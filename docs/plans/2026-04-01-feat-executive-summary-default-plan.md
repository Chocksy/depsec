---
title: "feat: Executive summary as default scan output"
type: feat
date: 2026-04-01
---

# feat: Executive Summary as Default Scan Output

## Overview

Replace the current category-by-category listing (146 lines for POS app) with a prioritized executive summary as the default `depsec scan` output. The current detailed view moves to `--full`. Scorecard and glossary are kept.

## Problem Statement

`depsec scan .` currently outputs every finding grouped by check category. Even after behavioral layering (v0.14.0), the POS app produces 146 lines. Developers want 10-15 lines of "what to do next" — not a wall of findings to parse mentally.

## Proposed Solution

### New Default Output Format

```
depsec v0.14.0 — pos-app                                    Grade: D (4.0/10)

🔴 Actions needed:
  1. Pin workflow actions to SHA (1 unpinned) → run: depsec fix
  2. Remove leaked JWT tokens (2 found)
     → .cursor/plans/sup-00d0b27d.plan.md:49

🟡 Review:
  3. 68 dependency advisories across 22 packages → run: npm audit fix
  4. 11 suspicious patterns in 5 runtime packages
  5. Missing SECURITY.md → create with vuln reporting instructions

🟢 Passing:
  ✓ Capabilities: build tools properly isolated (91%)
  ✓ Lockfiles committed and verified
  ✓ No malware detected

5 ambiguous findings → run 'depsec scan --triage' for AI classification

┌──────────────────────────────────────────────┐
│ DEPSEC SCORECARD                    4.0/10 D │
├──────────────────────────────────────────────┤
│ Workflows    ░░░░░░░░░░░░░░░░░░░░   2% 3    │
│ Deps         ███████████████████░  97% 68   │
│ ...                                          │
└──────────────────────────────────────────────┘

Run 'depsec scan --full' for detailed breakdown.
```

### New CLI Flags

```
depsec scan [PATH]                 # Executive summary (NEW default)
depsec scan [PATH] --full          # Current detailed category-by-category output
depsec scan [PATH] --verbose       # Everything including build tools (unchanged)
depsec scan [PATH] --strict        # Auditor-level findings (alias for --persona auditor)
depsec scan [PATH] --relaxed       # Pedantic-level findings (alias for --persona pedantic)
depsec scan [PATH] --persona X     # REMOVED — replaced by --strict/--relaxed
depsec scan [PATH] --json/--sarif  # Machine output (unchanged, always full detail)
```

**PATH defaults to `.` (already the case).**

## Implementation Phases

### Phase 1: Add `--full` flag and wire routing

**File: `src/main.rs`**

Add `--full` flag to Scan command:
```rust
/// Show full detailed output (default shows executive summary)
#[arg(long)]
full: bool,

/// Strict mode: show all findings including low-confidence (alias for --persona auditor)
#[arg(long)]
strict: bool,

/// Relaxed mode: show medium+ confidence findings (alias for --persona pedantic)
#[arg(long)]
relaxed: bool,
```

**File: `src/commands/scan.rs`**

Update `ScanOpts` to include `full: bool`. Wire `--strict` → `Persona::Auditor`, `--relaxed` → `Persona::Pedantic`, with `--persona` taking precedence if explicitly set.

- [ ] Add `full`, `strict`, `relaxed` flags to Scan command in main.rs
- [ ] Add `full` field to `ScanOpts` struct in scan.rs
- [ ] Wire --strict/--relaxed as persona aliases
- [ ] Pass `full` through to output rendering

### Phase 2: Build `render_executive()` function

**File: `src/output.rs`**

New function: `render_executive(report, use_color, persona, verbose) -> String`

**Step 2a: Collect and prioritize actions**

Group all findings into "actions" — each action is one line representing a category of work:

```rust
struct Action {
    priority: ActionPriority,  // Red, Yellow, Green
    summary: String,           // "Pin workflow actions to SHA (1 unpinned)"
    suggestion: Option<String>, // "→ run: depsec fix"
    count: usize,              // number of individual findings
    category: String,          // source check
}

enum ActionPriority {
    Red,    // Critical/High severity, or auto-fixable
    Yellow, // Medium severity in runtime deps
    Green,  // Passing / no issues
}
```

**Grouping rules:**
- Workflow findings → group by type (unpinned actions, missing permissions)
- Deps findings → ONE action: "N advisories across M packages"
- Pattern findings → group by reachability (runtime vs build)
- Secret findings → group by type (JWT, API key, etc.)
- Hygiene findings → individual (small count)
- Capability findings → summarize: "build tools isolated" or "N dangerous runtime deps"
- Auto-fixable → always Red with `→ run: depsec fix`
- Malware → always Red, first in list

**Priority assignment:**
- Red: Critical/High severity, malware, auto-fixable items
- Yellow: Medium severity in runtime deps, secrets, hygiene gaps
- Green: Checks with zero findings, build-tool-only findings

- [ ] Define `Action` and `ActionPriority` structs
- [ ] Implement `collect_actions(report, persona) -> Vec<Action>` that groups findings into actions
- [ ] Implement priority assignment logic
- [ ] Number actions sequentially (1, 2, 3...)

**Step 2b: Render the executive output**

```rust
fn render_executive(report, use_color, persona, verbose) -> String {
    // 1. Header: version + project name + grade
    // 2. Red section: "🔴 Actions needed:" (numbered)
    // 3. Yellow section: "🟡 Review:" (numbered, continuing from red)
    // 4. Green section: "🟢 Passing:" (bullet points, not numbered)
    // 5. Triage suggestion (if ambiguous findings exist)
    // 6. Scorecard (same ASCII box as current)
    // 7. "Run 'depsec scan --full' for detailed breakdown."
    // 8. Rule glossary (same as current, only for triggered rules)
}
```

- [ ] Implement `render_executive()` with all 8 sections
- [ ] Red/Yellow use numbered list, Green uses bullet points
- [ ] Include file paths for actionable items (secrets, specific findings)
- [ ] Include inline commands for auto-fixable items (`→ run: depsec fix`)
- [ ] Add triage suggestion line when medium-confidence findings exist
- [ ] Reuse existing `render_scorecard()` and `render_glossary()` functions
- [ ] Add "Run 'depsec scan --full' for detailed breakdown." footer

### Phase 3: Wire executive as default

**File: `src/commands/scan.rs`**

Change the output routing:
```rust
let output = if opts.json || opts.format.is_some() {
    // JSON/SARIF: unchanged, always full detail
    match fmt { ... }
} else if opts.full || opts.verbose {
    // --full or --verbose: current detailed output
    output::render_human(&report, opts.color, opts.persona, opts.verbose)
} else {
    // Default: executive summary
    output::render_executive(&report, opts.color, opts.persona)
};
```

- [ ] Route default output to `render_executive()`
- [ ] Route `--full` to existing `render_human()`
- [ ] JSON/SARIF always use full detail (unchanged)
- [ ] `--verbose` uses existing `render_human()` with verbose=true

### Phase 4: Tests and validation

- [ ] Test: `depsec scan .` on depsec itself produces executive summary
- [ ] Test: `depsec scan . --full` produces current detailed output
- [ ] Test: `depsec scan . --strict` shows all findings (auditor)
- [ ] Test: `depsec scan . --relaxed` shows medium+ (pedantic)
- [ ] Test: `depsec scan . --json` unchanged
- [ ] Test: `depsec scan . --persona auditor` still works (backwards compat)
- [ ] Test: executive output for POS app is under 40 lines
- [ ] Test: executive output includes scorecard box
- [ ] Test: executive output includes rule glossary
- [ ] Test: actions are numbered and prioritized (red before yellow)
- [ ] Test: auto-fixable items show `→ run: depsec fix`
- [ ] Test: triage suggestion appears when medium-confidence findings exist
- [ ] `cargo fmt && cargo clippy && cargo test` — zero warnings, 367+ pass

## Acceptance Criteria

- [ ] Default `depsec scan .` produces executive summary (not category listing)
- [ ] `--full` flag produces current detailed output
- [ ] `--strict` and `--relaxed` work as persona aliases
- [ ] `--persona` still works for backwards compatibility
- [ ] Executive output includes: header, red/yellow/green sections, scorecard, glossary
- [ ] Actions are grouped (not individual findings) and numbered
- [ ] Auto-fixable items include inline command suggestion
- [ ] Triage suggestion appears when appropriate
- [ ] JSON/SARIF output unchanged
- [ ] POS app executive output under 40 lines
- [ ] All existing tests pass

## Success Metrics

| Metric | Before (v0.14.0) | Target |
|--------|----------|--------|
| Default output lines (POS app) | 146 | <40 |
| Time to understand "what to do" | Minutes (scan output) | Seconds (numbered actions) |
| New user onboarding | "what do these lines mean?" | "oh, fix these 5 things" |

## References

- Brainstorm: `docs/brainstorms/2026-03-31-executive-summary-default-brainstorm.md`
- Current output rendering: `src/output.rs:100-340` (render_human)
- Scorecard rendering: `src/output.rs:270-325`
- Glossary rendering: `src/output.rs:335-375`
- CLI flags: `src/main.rs:65-92`
- Scan command dispatch: `src/commands/scan.rs:18-136`
