---
title: "feat: tree-sitter AST Integration for Pattern Detection"
type: feat
date: 2026-03-29
parent: docs/plans/2026-03-29-feat-smart-analysis-engine-plan.md
brainstorm: docs/brainstorms/2026-03-28-layer1-smart-filtering.md
---

# tree-sitter AST Integration for Pattern Detection

## Overview

Add tree-sitter to depsec's pattern detection engine so it can structurally distinguish `regex.exec()` (benign) from `child_process.exec(variable)` (dangerous). This eliminates 592 false positive P001 findings on the POS project and upgrades P001/P002/P008 from Low/Medium confidence to High confidence when AST analysis confirms the pattern is real.

## Problem Statement

After Phase 1 (file exclusions, persona model, package aggregation), the POS project still has **592 P001 exec() findings** and **39 P002 base64→exec findings** in auditor mode. All are Low/Medium confidence because the regex engine cannot distinguish:

```javascript
/pattern/.exec(string)       // regex.exec() — benign, 95% of P001 hits
child_process.exec(userInput) // shell exec — dangerous, 5% of P001 hits
```

The persona model hides these in regular mode, but they're still detected and stored. tree-sitter provides the structural understanding to **not detect them at all** — a true fix, not a filter.

## Proposed Solution

Add tree-sitter with JS/TS/Python grammars. Create a new `src/ast/` module that runs alongside the existing regex engine. For rules P001, P002, and P008, use tree-sitter's AST queries to check:

1. **What object** is `.exec()` being called on? (regex vs child_process)
2. **Where was that object imported from?** (require/import context)
3. **What type of argument** was passed? (string literal vs variable vs template)

Rules that don't need structural understanding (P003, P005, P007, P009, P010, P012) stay regex-based.

## Technical Approach

### Architecture

```
PatternsCheck::run()
│
├── For each file in dep dirs:
│   │
│   ├── detect_language(path) → JS/TS/Python/Rust/None
│   │
│   ├── If JS/TS/Python:
│   │   ├── Parse with tree-sitter → AST
│   │   ├── Run AST queries for P001/P002/P008 → ast_findings
│   │   ├── Run regex for P003/P005/P006/P010/P011 → regex_findings
│   │   └── Merge (AST findings override regex for same rules)
│   │
│   ├── If unknown language:
│   │   └── Run regex for ALL rules (fallback, same as today)
│   │
│   └── Run P007 entropy check (always regex, content-based)
│
├── Run P009 .pth check (always regex)
├── Run P012 install script check (always regex)
└── Apply per-package allow rules
```

### New Dependencies

```toml
# Cargo.toml additions
tree-sitter = "0.24"
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.23"
```

**No tree-sitter-rust** — Rust deps are in Cargo.lock (binary crates), not source code in vendor/. We'd only need it for scanning Rust source in `src/`, which is not what the patterns check does. Dropped to minimize deps.

| Impact | Value |
|--------|-------|
| New direct deps | +4 crates |
| New transitive deps | ~5 (most shared with existing `regex` crate) |
| Binary size | +1.2MB (3 grammars instead of 4) |
| Build time | +6s (C compilation of grammars) |
| Requires | C compiler at build time (`cc` crate, auto-resolved) |

---

## Implementation Phases

### Phase 2.1: Add Dependencies + Verify Build

**Files:** `Cargo.toml`

Add the 4 crates. Verify:
- `cargo build` succeeds
- `cargo deny check` passes (MIT/Apache licenses)
- CI build still works (C compiler available in GitHub Actions)

```toml
[dependencies]
# ... existing ...
tree-sitter = "0.24"
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.23"
```

**Acceptance criteria:**
- [ ] `cargo build --release` succeeds
- [ ] `cargo deny check` passes
- [ ] Binary size increase ≤ 1.5MB
- [ ] Existing 106 tests still pass

---

### Phase 2.2: AST Module Scaffold

**New files:**

```
src/ast/
├── mod.rs           # AstAnalyzer struct + language dispatch
└── javascript.rs    # JS/TS query definitions and analysis
```

Note: Python analysis (`python.rs`) and Rust analysis (`rust_lang.rs`) are deferred — the POS project's false positives are all in JS/TS. Python can be added later when we have a Python test project.

**`src/ast/mod.rs`:**

```rust
use std::path::Path;
use tree_sitter::Parser;
use crate::checks::{Confidence, Severity};

mod javascript;

/// Languages we can parse with tree-sitter
#[derive(Debug, Clone, Copy)]
pub enum Lang {
    JavaScript,
    TypeScript,
}

/// A finding produced by AST analysis
pub struct AstFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub line: usize,       // 1-indexed
    pub receiver: Option<String>,
    pub import_source: Option<String>,
}

pub struct AstAnalyzer {
    js_parser: Parser,
    ts_parser: Parser,
}

impl AstAnalyzer {
    pub fn new() -> Self {
        let mut js_parser = Parser::new();
        js_parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("failed to set JS language");

        let mut ts_parser = Parser::new();
        ts_parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to set TS language");

        Self { js_parser, ts_parser }
    }

    /// Analyze a file for security patterns using AST
    pub fn analyze(&mut self, path: &Path, source: &str) -> Vec<AstFinding> {
        match detect_language(path) {
            Some(Lang::JavaScript) => javascript::analyze(&mut self.js_parser, source),
            Some(Lang::TypeScript) => javascript::analyze(&mut self.ts_parser, source),
            None => vec![],
        }
    }
}

fn detect_language(path: &Path) -> Option<Lang> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    match ext {
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::JavaScript),
        "ts" | "mts" | "cts" | "tsx" => Some(Lang::TypeScript),
        _ => None,
    }
}
```

**Acceptance criteria:**
- [ ] `mod ast` declared in `main.rs`
- [ ] `AstAnalyzer::new()` initializes JS and TS parsers
- [ ] `detect_language()` correctly maps extensions
- [ ] Module compiles, unit test for `detect_language()`

---

### Phase 2.3: P001 AST Detection — The Core Fix

**File:** `src/ast/javascript.rs`

This is the most critical piece — the two-pass import-aware exec detection.

```rust
pub fn analyze(parser: &mut Parser, source: &str) -> Vec<AstFinding> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut findings = Vec::new();

    // Pass 1: Find dangerous module imports
    let dangerous_aliases = find_dangerous_imports(&tree, source);

    // Pass 2: Find exec/spawn calls on those aliases
    find_dangerous_exec_calls(&tree, source, &dangerous_aliases, &mut findings);

    // P002: Find base64 decode → execute chains
    find_base64_exec_chains(&tree, source, &mut findings);

    // P008: Find new Function() with variable args
    find_dynamic_function_constructor(&tree, source, &mut findings);

    findings
}
```

**Pass 1 — Import detection:**

Dangerous modules: `child_process`, `shelljs`, `execa`, `cross-spawn`

Detect patterns:
- `const cp = require('child_process')` → alias `cp`
- `const { exec, spawn } = require('child_process')` → aliases `exec`, `spawn`
- `import { exec } from 'child_process'` → alias `exec`
- `import cp from 'child_process'` → alias `cp`

tree-sitter query (S-expression):
```scheme
;; CommonJS require with simple binding
(variable_declarator
  name: (identifier) @alias
  value: (call_expression
    function: (identifier) @_req
    arguments: (arguments (string (string_fragment) @module)))
  (#eq? @_req "require")
  (#match? @module "^(child_process|shelljs|execa|cross-spawn)$"))
```

Additional query for destructured require:
```scheme
;; CommonJS require with destructured binding
(variable_declarator
  name: (object_pattern
    (shorthand_property_identifier_pattern) @destructured)
  value: (call_expression
    function: (identifier) @_req
    arguments: (arguments (string (string_fragment) @module)))
  (#eq? @_req "require")
  (#match? @module "^(child_process|shelljs|execa|cross-spawn)$"))
```

ES import query:
```scheme
;; ES import
(import_statement
  (import_clause
    [(identifier) @alias
     (named_imports (import_specifier name: (identifier) @alias))])
  source: (string (string_fragment) @module)
  (#match? @module "^(child_process|shelljs|execa|cross-spawn)$"))
```

Result: `HashSet<String>` of local names bound to dangerous modules.

**Pass 2 — Dangerous call detection:**

```scheme
;; Method call: cp.exec(arg)
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  arguments: (arguments . (_) @first_arg)
  (#match? @method "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"))
```

Programmatic filtering (Rust side):
1. For each match, check if `@obj` is in `dangerous_aliases`
2. If not → skip (it's `regex.exec()`, `db.exec()`, etc.)
3. If yes → check `@first_arg` node type for severity:
   - `string` / `template_string` without substitutions → **Medium** (static command)
   - `template_string` with `template_substitution` → **Critical** (interpolated)
   - `identifier` or other → **High** (variable input)
4. Create `AstFinding` with rule_id `DEPSEC-P001`, `confidence: High`

Also handle direct calls from destructured imports:
```scheme
;; Direct call: exec(arg) — only if 'exec' was destructured from dangerous module
(call_expression
  function: (identifier) @func
  arguments: (arguments . (_) @first_arg)
  (#match? @func "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"))
```

Same programmatic check: `@func` must be in `dangerous_aliases`.

**Acceptance criteria:**
- [ ] `regex.exec()` → NOT detected (the core fix!)
- [ ] `child_process.exec(variable)` → detected, High confidence, High severity
- [ ] `child_process.exec("literal")` → detected, High confidence, Medium severity
- [ ] `` child_process.exec(`cmd ${var}`) `` → detected, High confidence, Critical severity
- [ ] `const cp = require('child_process'); cp.exec(x)` → detected (alias resolved)
- [ ] `const { exec } = require('child_process'); exec(x)` → detected (destructured)
- [ ] `import { exec } from 'child_process'; exec(x)` → detected (ES import)
- [ ] `db.exec()`, `cursor.execute()` → NOT detected
- [ ] File with no dangerous imports → zero findings from AST (fast path)

---

### Phase 2.4: Integration with PatternsCheck

**File:** `src/checks/patterns.rs`

The key integration point: for each file, run AST analysis for P001/P002/P008, then regex for the remaining rules. Deduplicate.

```rust
// In PatternsCheck::run():
let mut ast_analyzer = crate::ast::AstAnalyzer::new();

for file in walk_dep_files(ctx.root) {
    let content = read_file(&file)?;
    let rel_path = relative_path(&file, ctx.root);

    // AST analysis for rules that benefit from structure (P001, P002, P008)
    let ast_findings = ast_analyzer.analyze(&file, &content);

    // Track which rules the AST handled for this file
    let ast_handled_rules: HashSet<&str> = ast_findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();

    // Convert AST findings to standard Finding
    for af in ast_findings {
        findings.push(Finding {
            rule_id: af.rule_id,
            severity: af.severity,
            confidence: Some(af.confidence),
            message: af.message,
            file: Some(rel_path.clone()),
            line: Some(af.line),
            suggestion: Some("Review or remove this dependency".into()),
            package: extract_package_name(&rel_path),
            auto_fixable: false,
        });
    }

    // Regex analysis ONLY for rules NOT handled by AST
    for (line_num, line) in content.lines().enumerate() {
        for (rule, re) in &compiled {
            // Skip P001/P002/P008 if AST analyzed this file
            if ast_handled_rules.contains(rule.rule_id)
                || (has_ast_language(&file) && is_ast_upgradeable(rule.rule_id))
            {
                continue;
            }
            // ... existing regex matching ...
        }
    }
}
```

**Key logic:** If the file is JS/TS (AST-parseable), skip regex for P001/P002/P008 entirely — the AST engine handles them with higher confidence. If the file is NOT JS/TS (e.g., a shell script), fall back to regex for those rules.

`is_ast_upgradeable()` returns true for `DEPSEC-P001`, `DEPSEC-P002`, `DEPSEC-P008`.

**Acceptance criteria:**
- [ ] JS/TS files: P001/P002/P008 use AST detection, other rules use regex
- [ ] Non-JS files: ALL rules use regex (same behavior as today)
- [ ] AST findings have `confidence: High`, regex findings keep their original confidence
- [ ] No duplicate findings (AST and regex don't both fire for same rule+file)
- [ ] If tree-sitter parse fails (malformed file), fall back to regex gracefully

---

### Phase 2.5: P002 AST Upgrade — Base64→Exec Chain

**File:** `src/ast/javascript.rs`

P002 detects `atob(...) → eval(...)` or `Buffer.from(..., 'base64') → exec(...)` chains. The regex fires on lines that mention both base64 and exec, causing false positives in source maps and documentation.

AST approach: look for actual function call chains where decoded data flows into an execution sink.

```scheme
;; atob() or Buffer.from(x, 'base64') in same scope as eval/exec/Function
;; This is a simplified structural check — not full taint analysis
(call_expression
  function: (identifier) @func
  (#match? @func "^(eval|exec|Function)$"))
```

Combined with presence of base64 decode in the same function scope. If both exist in the same function body → flag.

**Acceptance criteria:**
- [ ] `atob(x); eval(decoded)` in same function → detected
- [ ] `Buffer.from(x, 'base64')` followed by `eval()` → detected
- [ ] Source map `.map` files with "base64" and "exec" in stringified content → NOT detected (already excluded by Phase 1 file filters, and AST won't parse JSON)
- [ ] Confidence: High (structural confirmation)

---

### Phase 2.6: P008 AST Upgrade — new Function()

**File:** `src/ast/javascript.rs`

P008 detects `new Function(variable)`. The AST can distinguish:
- `new Function("return 1")` → static string → Medium (less dangerous)
- `new Function(userInput)` → variable → High (dangerous)
- References to `Function.prototype` → NOT a constructor call → skip

tree-sitter query:
```scheme
(new_expression
  constructor: (identifier) @ctor
  arguments: (arguments . (_) @first_arg)
  (#eq? @ctor "Function"))
```

Check `@first_arg` node type same as P001.

**Acceptance criteria:**
- [ ] `new Function(variable)` → detected, High confidence
- [ ] `new Function("static string")` → detected, Medium severity
- [ ] `Function.prototype.bind(...)` → NOT detected

---

### Phase 2.7: Tests

**New test files and additions:**

```
src/ast/mod.rs      — unit test for detect_language()
src/ast/javascript.rs — unit tests for each query:
  - test_exec_on_regex_not_flagged
  - test_exec_on_child_process_flagged
  - test_exec_destructured_import
  - test_exec_es_import
  - test_exec_static_string_medium
  - test_exec_template_literal_critical
  - test_exec_no_imports_no_findings
  - test_base64_eval_chain
  - test_new_function_variable
  - test_new_function_static
```

Also update `src/checks/patterns.rs` integration tests to verify AST+regex coexistence.

**Acceptance criteria:**
- [ ] At least 10 new unit tests for AST analysis
- [ ] All existing 106 tests still pass
- [ ] Integration test: scan a temp dir with JS files containing both regex.exec() and child_process.exec()

---

### 🧪 Phase 2 Testing Checkpoint

**Run against POS project:**

```bash
# P001 finding count — should be near zero
cargo run -- scan ~/Development/pos --persona auditor --format json 2>/dev/null | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
  print(sum(1 for r in d['results'] if r['category']=='patterns' \
  for f in r['findings'] if f['rule_id']=='DEPSEC-P001'))"

# Expected: <10 (only non-JS files or edge cases)

# Overall finding count in auditor mode
cargo run -- scan ~/Development/pos --persona auditor 2>&1 | grep -c "✗\|⚠"
# Expected: ~2300 (down from 2895, P001 eliminated)

# Regular mode should still be clean
cargo run -- scan ~/Development/pos 2>&1 | grep "Patterns"
# Expected: Patterns 100% ✓
```

**Performance:**
```bash
# Scan time comparison
time cargo run --release -- scan ~/Development/pos --persona auditor > /dev/null 2>&1
# Expected: <5s additional vs regex-only
```

**🔍 codex-investigator review:** After implementation, review:
- tree-sitter query correctness (do queries match intended patterns?)
- Edge cases: minified code, webpack bundles, CJS/ESM interop
- Memory: are we holding trees in memory unnecessarily?
- Performance: any O(n²) in query execution?
- Fallback: does regex take over gracefully when AST parse fails?

---

## Acceptance Criteria

### Functional Requirements

- [ ] `regex.exec()` calls produce zero P001 findings (the core fix)
- [ ] `child_process.exec(variable)` is detected with High confidence
- [ ] Destructured and aliased imports are resolved
- [ ] Static string arguments downgrade severity to Medium
- [ ] Template literals with interpolation upgrade severity to Critical
- [ ] Non-JS/TS files fall back to regex detection (no regression)
- [ ] P001 findings on POS project drop from 592 to <10

### Non-Functional Requirements

- [ ] Binary size increase ≤ 1.5MB
- [ ] Scan time increase ≤ 2s on POS project
- [ ] New crate dependencies ≤ 5 transitive
- [ ] C compiler required at build time (acceptable — documented)
- [ ] All 106+ existing tests pass

### Quality Gates

- [ ] `cargo clippy` passes
- [ ] `cargo deny check` passes
- [ ] `cargo test` passes (106 existing + 10+ new)
- [ ] codex-investigator review completed
- [ ] POS project tested in all three personas

---

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| tree-sitter queries don't match minified code | Minified variable names break import resolution | Fall back to regex for `.min.js` files |
| tree-sitter parse fails on malformed JS | No AST findings for that file | Graceful fallback to regex with warning |
| Grammar crate versions incompatible | Build failure | Pin exact versions in Cargo.toml |
| C compiler missing in CI | Build failure | Document requirement, test in CI early |
| Query predicates (`#match?`) silently fail | Queries return no matches | Unit test every query pattern |
| Bundled code (webpack) has different AST structure | Missed detections | Test against actual bundled files from POS |

---

## Dependencies & Prerequisites

- Phase 1 complete (file exclusions, confidence, persona, aggregation, config) ✅
- C compiler available at build time
- tree-sitter crate v0.24+ (MIT license)
- tree-sitter-javascript v0.23+ (MIT license)
- tree-sitter-typescript v0.23+ (MIT license)
- tree-sitter-python v0.23+ (MIT license)

---

## References

### Internal
- Parent plan: `docs/plans/2026-03-29-feat-smart-analysis-engine-plan.md`
- Brainstorm: `docs/brainstorms/2026-03-28-layer1-smart-filtering.md` §1.4-1.6
- Current patterns check: `src/checks/patterns.rs`
- Current findings: POS project has 592 P001, 39 P002, 2 P008 findings

### External
- tree-sitter Rust crate: docs.rs/tree-sitter/0.24
- tree-sitter query syntax: tree-sitter.github.io/tree-sitter/using-parsers/queries
- tree-sitter-javascript grammar: github.com/tree-sitter/tree-sitter-javascript
- Semgrep detect-child-process rule: github.com/semgrep/semgrep-rules (import-aware pattern)
- StreamingIterator gotcha: tree-sitter QueryMatches uses StreamingIterator, not Iterator
