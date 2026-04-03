---
title: "feat: Sprint 2 — Package-Level Capability Aggregation + Import Graph"
type: feat
date: 2026-04-03
---

# Sprint 2: Package-Level Capability Aggregation + Import Graph

## Overview

Fix the detection gap where malicious logic split across multiple files within a single
package evades detection. The solution is **layered and obfuscation-resistant**:

1. **Layer 1 (obfuscation-proof):** Fix the cross-file capability aggregation bug in
   `capabilities.rs` so credential_read fires when `.ssh` is in one file and `readFileSync`
   is in another. Add package-level signal combination to `patterns.rs`.
2. **Layer 2 (best-effort):** Build an intra-package import graph that traces which files
   require/import each other, enhancing the attribution of WHY a package is suspicious.
3. **Layer 3 (bonus):** Also fix E14 (defineProperty getter) and E22 (Python alias) as
   quick wins within this sprint.

**Detection target:** 78.4% → ~89% (close 4 of 8 remaining gaps)

## Problem Statement

The Hornets Nest scorecard shows 8 remaining evasion gaps. Two are caused by cross-file
scatter attacks:

- **E06** (`hn-multi-file-scatter`): credential path in `path.js`, readFileSync in `reader.js`,
  decode in `decoder.js` — no single file triggers any combination rule
- **E12** (`hn-json-payload`): malicious code string in `config.json`, loaded and eval'd by
  `index.js` — P001 regex actually catches `eval(config.cmd)` in index.js, so E12 is already
  partially detected. The cross-file data flow is the architectural gap.

### Root causes identified:

1. **`capabilities.rs:468-476`** — `credential_read` only fires if `caps.fs_read` AND
   `.ssh` appear in the **same file**. But `scan_package()` already aggregates across files,
   so `caps.fs_read` may be set by file A while `.ssh` is in file B. The check runs per-file
   but tests `caps.fs_read` which was set by a previous file → timing dependency.

2. **`patterns.rs:1047-1091`** — `apply_signal_combination` groups findings by `f.file`,
   not `f.package`. Cross-file escalation rules never fire.

### The obfuscation concern

The user raised a critical concern: if the import graph relies on parsing `require()`/`import`,
attackers can obfuscate those. The solution must NOT depend solely on import parsing.

**Layer 1 (capability aggregation) is obfuscation-proof** because it doesn't care HOW files
connect — it just says "this package has files that read credentials AND files that do network
calls." No import parsing needed.

**Layer 2 (import graph) is best-effort** — it adds precision for attribution but detection
works without it.

## Technical Approach

### Phase 1: Fix Cross-File Capability Bug (the critical fix)

**File:** `src/checks/capabilities.rs:468-476`

The bug: `detect_capabilities()` is called per-file, checking `caps.fs_read && content.contains(".ssh")`.
Since `caps.fs_read` is set by a previous file, but `.ssh` is in the current file, the check CAN
work — but only if files are processed in the right order (fs_read file before credential path file).
This is a timing dependency that can cause false negatives.

- [ ] **1.1** Decouple `credential_read` from per-file content by doing a two-pass approach:
  - Pass 1: Walk all files, detect capabilities (sets `fs_read`, `network`, etc.)
  - Pass 2: If `caps.fs_read` is true, re-scan all files for credential path strings
  - This ensures `credential_read` fires regardless of file processing order

  ```rust
  fn scan_package(pkg_dir: &Path) -> Option<PackageCapabilities> {
      let mut caps = PackageCapabilities::default();
      let mut file_contents: Vec<String> = Vec::new();

      // Pass 1: detect base capabilities
      for entry in WalkDir::new(pkg_dir)... {
          let content = std::fs::read_to_string(path)?;
          detect_capabilities(&content, &mut caps);
          file_contents.push(content);
      }

      // Pass 2: credential path check using aggregated fs_read
      if caps.fs_read {
          for content in &file_contents {
              if CREDENTIAL_PATHS.iter().any(|p| content.contains(p)) {
                  caps.credential_read = true;
                  break;
              }
          }
      }

      if caps.has_any() { Some(caps) } else { None }
  }
  ```

- [ ] **1.2** Similarly decouple `credential_read` for env-access patterns:
  - If `caps.env_access` and ANY file has network → `env-exfiltration` fires
  - This already works via COMBINATION_RULES, just verify with a test

**Expected impact:** E06 should now be caught by `credential-exfiltration` CAP rule
(credential_read + network detected at package level).

### Phase 2: Package-Level Signal Combination in patterns.rs

**File:** `src/checks/patterns.rs:1047-1091` (`apply_signal_combination`)

Currently groups by file. Add a parallel grouping by package.

- [ ] **2.1** Add package-level grouping alongside file-level grouping:

  ```rust
  fn apply_signal_combination(findings: &mut Vec<Finding>) {
      // Existing: group by file
      let mut rules_by_file: HashMap<String, HashSet<String>> = HashMap::new();
      // NEW: group by package
      let mut rules_by_package: HashMap<String, HashSet<String>> = HashMap::new();

      for f in findings.iter() {
          if let Some(file) = &f.file {
              rules_by_file.entry(file.clone()).or_default().insert(f.rule_id.clone());
          }
          if let Some(pkg) = &f.package {
              rules_by_package.entry(pkg.clone()).or_default().insert(f.rule_id.clone());
          }
      }

      // Existing file-level escalation...

      // NEW: Package-level escalation
      for (pkg, rules) in &rules_by_package {
          // Cross-file credential exfiltration: credential read + network in same package
          let has_credential = rules.contains("DEPSEC-P004");
          let has_network = rules.contains("DEPSEC-P003")
              || rules.contains("DEPSEC-P006")
              || rules.contains("DEPSEC-P010");
          let has_exec = rules.contains("DEPSEC-P001");
          let has_obfuscation = rules.contains("DEPSEC-P014")
              || rules.contains("DEPSEC-P017");

          if has_credential && has_network {
              findings.push(
                  Finding::new("DEPSEC-COMBO-001", Severity::Critical,
                      format!("Cross-file exfiltration pattern in {pkg}: credential read + network call in different files"))
                  .with_package(Some(pkg.clone()))
              );
          }

          if has_exec && has_obfuscation {
              findings.push(
                  Finding::new("DEPSEC-COMBO-002", Severity::Critical,
                      format!("Cross-file dropper pattern in {pkg}: code execution + obfuscation in different files"))
                  .with_package(Some(pkg.clone()))
              );
          }
      }
  }
  ```

- [ ] **2.2** Add rule info for DEPSEC-COMBO-001 and DEPSEC-COMBO-002 in `src/output.rs`

### Phase 3: Intra-Package Import Graph (best-effort enhancement)

**New file:** `src/graph.rs` (~150 lines)

This is the Layer 2 enhancement — builds a file-to-file import graph within a package.
It enhances findings with "call chain" information but detection works without it.

- [ ] **3.1** Create `src/graph.rs` with:

  ```rust
  use std::collections::{HashMap, HashSet};
  use std::path::Path;

  /// Intra-package import graph: which files require/import which other files
  pub struct PackageImportGraph {
      /// file → set of files it imports (relative paths within the package)
      pub edges: HashMap<String, HashSet<String>>,
  }

  impl PackageImportGraph {
      /// Build the import graph for a package directory
      pub fn build(pkg_dir: &Path) -> Self { ... }

      /// Get all files transitively reachable from a given entry point
      pub fn transitive_deps(&self, file: &str) -> HashSet<String> { ... }

      /// Render as mermaid diagram
      pub fn to_mermaid(&self) -> String { ... }
  }
  ```

- [ ] **3.2** The `build()` function:
  - Walk all `.js/.ts/.py/.rb` files in the package
  - For each file, extract local imports (those starting with `./` or `../`)
  - Use existing tree-sitter parsers: reuse the `find_dangerous_imports` approach but
    capture ALL require/import targets, not just dangerous modules
  - Resolve relative paths to actual files (handle `./decoder` → `decoder.js`)
  - Skip external package imports (those without `./` prefix)

- [ ] **3.3** Wire the import graph into capabilities output for enhanced finding messages:
  - When `credential-exfiltration` CAP fires, include the file chain if the graph found one
  - E.g.: "Credential exfiltration chain: reader.js → decoder.js → path.js (credential path)"

### Phase 4: Quick Fixes (E14, E22)

- [ ] **4.1** E14 — defineProperty getter detection
  - **File:** `src/ast/javascript.rs`
  - Add AST query for `Object.defineProperty` calls
  - Check if the descriptor argument's body contains dangerous calls (child_process, etc.)
  - The E14 test content has `require('child_process').exec('whoami')` in the getter —
    the `needs_ast` gate already triggers because of `child_process` in the content.
    The issue is that P001 doesn't fire because `exec('whoami')` has a string literal argument.
    Fix: detect the `require('child_process').exec(...)` pattern as a chained call within
    `find_dangerous_calls` (member_expression chain)

- [ ] **4.2** E22 — Python alias resolution
  - **File:** `src/ast/python.rs`
  - Before running P021 (subprocess shell check), scan for `import X as Y` aliases
  - Build alias map: `{'sp': 'subprocess', 'o': 'os'}`
  - In the subprocess query, check both canonical name AND aliases
  - Use tree-sitter query for `import_statement` with `alias` field:
    ```
    (import_statement
      name: (aliased_import
        name: (dotted_name) @module
        alias: (identifier) @alias))
    ```

### Phase 5: Update Hornets Nest + Scorecard

- [ ] **5.1** Update E06 expected from Miss → Detect
- [ ] **5.2** Update E14 expected from Miss → Detect (if Phase 4.1 succeeds)
- [ ] **5.3** Update E22 expected from Miss → Detect (if Phase 4.2 succeeds)
- [ ] **5.4** Add new scan test for DEPSEC-COMBO-001 (cross-file exfiltration)
- [ ] **5.5** Run full scorecard, verify ≥85%
- [ ] **5.6** Run full unit test suite (431+ tests), verify no regressions

## Acceptance Criteria

- [ ] `credential_read` fires when `.ssh` is in one file and `readFileSync` in another
- [ ] `apply_signal_combination` escalates findings across files within the same package
- [ ] E06 (multi-file scatter) is detected via package-level capability aggregation
- [ ] Import graph built for packages that have cross-file imports
- [ ] E14 (defineProperty getter) detected via chained call pattern
- [ ] E22 (Python alias) detected via alias resolution pre-pass
- [ ] Hornets Nest scorecard shows ≥85% detection
- [ ] All existing unit tests still pass
- [ ] `cargo fmt --check` + `cargo clippy -- -D warnings` clean

## Key Design Decision: Layered Defense

```
Layer 1: Package-level capability aggregation (OBFUSCATION-PROOF)
  ↓ Catches E06 regardless of how files import each other
  ↓ detect_capabilities + COMBINATION_RULES at package scope

Layer 2: Import graph (BEST-EFFORT ENHANCEMENT)
  ↓ Adds "call chain" to finding messages for attribution
  ↓ Fails gracefully if imports are obfuscated

Layer 3: Per-file pattern matching (EXISTING)
  ↓ Catches single-file attacks as before
  ↓ apply_signal_combination at file scope
```

An attacker who obfuscates require() still gets caught by Layer 1 because the
capabilities (readFileSync, http.request, .ssh) are detected by string matching
in the raw file content — no import parsing needed.

## Dependencies & Risks

| Risk | Mitigation |
|---|---|
| Two-pass scan_package doubles file reads | Buffer file contents in Vec<String> on first pass |
| Package-level combo rules fire false positives | Only fire when BOTH signals are findings, not just capability booleans |
| Import graph resolution fails for complex paths | Graph is best-effort — detection works without it via Layer 1 |
| Large packages slow down with cross-file analysis | Skip packages with >100 files (heuristic: legitimate large packages rarely malicious) |

## References

### Files to Modify

| File | Changes |
|---|---|
| `src/checks/capabilities.rs` | Two-pass scan_package, decouple credential_read |
| `src/checks/patterns.rs` | Package-level signal combination |
| `src/graph.rs` (NEW) | Intra-package import graph |
| `src/ast/javascript.rs` | E14 defineProperty, import graph extraction |
| `src/ast/python.rs` | E22 alias resolution |
| `src/output.rs` | COMBO rule info |
| `src/main.rs` | Register graph module |
| `tests/hornets_nest/evasion_tests.rs` | Flip E06, E14, E22 |

### Brainstorm
- `docs/brainstorms/2026-04-02-detection-improvement-roadmap-brainstorm.md`
- Sprint 1 plan: `docs/plans/2026-04-02-feat-sprint1-detection-quick-wins-ast-extensions-plan.md`
