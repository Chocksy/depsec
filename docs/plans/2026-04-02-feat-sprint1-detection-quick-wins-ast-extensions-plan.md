---
title: "feat: Sprint 1 — Detection Quick Wins + AST Extensions (45.9% → 81%)"
type: feat
date: 2026-04-02
---

# Sprint 1: Detection Quick Wins + AST Extensions

## Overview

Close 13 of the 20 evasion gaps identified by the Hornets Nest adversarial test suite,
raising depsec's static analysis detection rate from 45.9% to ~81%. This sprint addresses
6 quick fixes (regex/config/bug) and 7 AST query extensions.

**Brainstorm:** `docs/brainstorms/2026-04-02-detection-improvement-roadmap-brainstorm.md`
**Hornets Nest:** `tests/hornets_nest/` (37 vectors, 22 tests)

## Problem Statement

The Hornets Nest scorecard shows 20 known evasion gaps. 13 of them can be fixed without
architectural changes — just pattern additions, config tweaks, and broader tree-sitter queries.

## Implementation Phases

### Phase 1: Fix the needs_ast Gate (Bug Fix — unlocks Python/Ruby AST)

**File:** `src/checks/patterns.rs:312-321`

The `needs_ast` condition only checks JS-specific keywords (`child_process`, `require(`, etc.).
Python `.py` and Ruby `.rb` files pass `AstAnalyzer::can_analyze()` but none of the content
probes match, so AST analysis (P020-P033) is **never executed** for Python/Ruby files.

- [ ] **1.1** Refactor `needs_ast` to be language-aware

  ```rust
  // src/checks/patterns.rs — replace lines 312-321
  let lang = crate::ast::detect_language_from_ext(path);
  let needs_ast = lang.is_some() && match lang {
      Some(Lang::JavaScript | Lang::TypeScript) => {
          content.contains("child_process")
              || content.contains("shelljs")
              || content.contains("execa")
              || content.contains("cross-spawn")
              || content.contains("new Function")
              || content.contains("require(")
              || content.contains("fromCharCode")
              || content.contains("unlinkSync")
              || content.contains("rmSync")
      }
      Some(Lang::Python) => {
          content.contains("subprocess")
              || content.contains("os.system")
              || content.contains("os.popen")
              || content.contains("eval(")
              || content.contains("exec(")
              || content.contains("__import__")
              || content.contains("pickle")
      }
      Some(Lang::Ruby) => {
          content.contains("eval")
              || content.contains("system")
              || content.contains("exec")
              || content.contains("send(")
              || content.contains("require(")
              || content.contains("open(")
      }
      _ => false,
  };
  ```

  Need to expose `detect_language` from `src/ast/mod.rs` (currently private fn at line 82).

- [ ] **1.2** Make `detect_language` public in `src/ast/mod.rs:82`
  - Change `fn detect_language` to `pub fn detect_language`

- [ ] **1.3** Update evasion test E22 (`hn-python-alias`) — this will now trigger Python AST
  but still miss due to the alias issue. Verify it stays `Expected::Miss`.

- [ ] **1.4** Add a NEW scan test for Python subprocess (direct, no alias) to verify P021 works
  via integration scanner now. Content: `import subprocess\nsubprocess.Popen(cmd, shell=True)`

**Fixes vectors:** Unlocks P020-P033 for all future Python/Ruby scanning (prerequisite for E22, E23, E21)

### Phase 2: Quick Regex/Config Fixes (6 vectors)

- [ ] **2.1** Fix P014 regex — broaden XOR to include addition/subtraction
  - **File:** `src/checks/patterns.rs:129`
  - **Change:** `r"String\.fromCharCode\s*\(.*[\^]"` → `r"String\.fromCharCode\s*\(.*[\^+\-]"`
  - **Update evasion test E20:** `expected: Expected::Miss` → `Expected::Detect`
  - **Update `#[test]` at evasion_tests.rs `evasion_fromcharcode_add`:** Remove or flip assertion

- [ ] **2.2** Add Python pickle deserialization rule (P024)
  - **File:** `src/ast/python.rs` — add new function `find_pickle_deserialize`
  - **Tree-sitter query:**
    ```
    (call
      function: (attribute
        object: (identifier) @obj
        attribute: (identifier) @method)
      (#eq? @obj "pickle")
      (#match? @method "^(loads|load|Unpickler)$"))
    ```
  - Rule ID: `DEPSEC-P024`, Severity: Critical, Confidence: High
  - Add rule info to `src/output.rs` RuleInfo map
  - **Update evasion test E21:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **2.3** Add Ruby `open("|cmd")` pipe execution detection
  - **File:** `src/ast/ruby.rs` — add new function `find_pipe_open` or extend P031
  - **Tree-sitter query:**
    ```
    (call
      method: (identifier) @fn
      arguments: (argument_list
        (string (string_content) @arg))
      (#eq? @fn "open")
      (#match? @arg "^\\|"))
    ```
  - Rule ID: `DEPSEC-P034`, Severity: High, Confidence: High
  - **Update evasion test E23:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **2.4** Large file sampling instead of skipping
  - **File:** `src/checks/patterns.rs:285` (the `if meta.len() > MAX_FILE_SIZE { continue; }`)
  - **Change:** Instead of `continue`, read first 50KB + last 50KB, scan those portions
  - ```rust
    let content = if meta.len() > MAX_FILE_SIZE {
        // Sample first and last 50KB for large files
        let bytes = std::fs::read(path)?;
        let head = &bytes[..50_000.min(bytes.len())];
        let tail_start = bytes.len().saturating_sub(50_000);
        let tail = &bytes[tail_start..];
        let mut sample = head.to_vec();
        if tail_start > 50_000 {
            sample.extend_from_slice(tail);
        }
        String::from_utf8_lossy(&sample).to_string()
    } else {
        std::fs::read_to_string(path)?
    };
    ```
  - **Update evasion test E24:** `expected: Expected::Miss` → `Expected::Detect`
  - **Update `#[test] evasion_large_bundle`:** Flip assertion to expect detection

- [ ] **2.5** Unicode confusable normalization
  - **File:** `Cargo.toml` — add `unicode-normalization = "0.1"`
  - **File:** `src/checks/patterns.rs` — before regex matching, normalize line to NFKD form
  - ```rust
    use unicode_normalization::UnicodeNormalization;
    // In the scan loop, before regex matching:
    let normalized_line = line.nfkd().collect::<String>();
    // Use normalized_line for regex matching
    ```
  - NFKD maps Cyrillic `а` (U+0430) to itself (not Latin `a`), so this alone won't fix E13.
    Need a confusables table mapping known lookalikes to ASCII equivalents.
  - **Alternative (simpler):** Use the `unicode-security` crate's `skeleton()` function which
    maps confusable characters. Or maintain a small lookup table for the ~20 most common
    confusable characters (а→a, е→e, о→o, р→p, с→c, у→y, etc.)
  - **Update evasion test E13:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **2.6** Add `needs_ast` probe for `pickle` in the Python gate (from Phase 1)
  - Already covered in 1.1 above — ensure `content.contains("pickle")` is in the Python branch

### Phase 3: AST Query Extensions (7 vectors)

- [ ] **3.1** E08: Detect `process.mainModule.require()`
  - **File:** `src/ast/javascript.rs` — in `find_dangerous_imports`
  - Add tree-sitter query for chained member expression:
    ```
    (call_expression
      function: (member_expression
        object: (member_expression
          object: (identifier) @proc
          property: (property_identifier) @mm)
        property: (property_identifier) @req)
      arguments: (arguments . (string (string_fragment) @mod))
      (#eq? @proc "process")
      (#eq? @mm "mainModule")
      (#eq? @req "require"))
    ```
  - Treat matched call as equivalent to `require(mod)` — add to `dangerous_aliases`
  - **Update evasion test E08:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.2** E16: Detect `(0, require)(name)` indirect call
  - **File:** `src/ast/javascript.rs` — in `find_dynamic_require`
  - Add tree-sitter query for sequence expression as function:
    ```
    (call_expression
      function: (parenthesized_expression
        (sequence_expression
          (_)
          (identifier) @fn))
      arguments: (arguments . (_) @arg)
      (#eq? @fn "require"))
    ```
  - Treat as dynamic require with same severity as P013
  - **Update evasion test E16:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.3** E17: Detect `new global.Function(code)`
  - **File:** `src/ast/javascript.js` — in `find_dynamic_function`
  - Add second query for member_expression constructor:
    ```
    (new_expression
      constructor: (member_expression
        property: (property_identifier) @prop)
      arguments: (arguments . (_) @arg)
      (#eq? @prop "Function"))
    ```
  - Same severity/confidence as existing P008
  - **Update evasion test E17:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.4** E18: Single-level alias resolution for Function
  - **File:** `src/ast/javascript.rs` — in `find_dynamic_function`
  - Before the constructor query, scan for `const X = Function` assignments:
    ```
    (variable_declarator
      name: (identifier) @alias
      value: (identifier) @val
      (#eq? @val "Function"))
    ```
  - Collect aliases, then also match `new <alias>(...)` in the constructor query
  - **Update evasion test E18:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.5** E15: Fix `import()` detection for string-concatenation args
  - The dynamic import query already exists in `find_dynamic_require` (line 519)
  - **The issue:** `needs_ast` doesn't trigger because the file content is
    `"child_" + "process"` — no literal `child_process` string
  - **Fix:** Add `content.contains("import(")` to the JS `needs_ast` gate (Phase 1.1)
  - **Update evasion test E15:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.6** E14: Detect `Object.defineProperty` with dangerous getter
  - **File:** `src/ast/javascript.rs` — add new function `find_dangerous_property_descriptors`
  - Query for `Object.defineProperty` calls where the descriptor object contains a `get`
    method that references dangerous modules:
    ```
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method)
      (#eq? @obj "Object")
      (#eq? @method "defineProperty"))
    ```
  - Then inspect the descriptor argument's body for dangerous patterns (child_process, etc.)
  - **Update evasion test E14:** `expected: Expected::Miss` → `Expected::Detect`

- [ ] **3.7** E09: Detect `Reflect.apply` with dangerous function arguments
  - **File:** `src/ast/javascript.js` — add new function `find_dangerous_reflect`
  - Query:
    ```
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method)
      (#eq? @obj "Reflect")
      (#match? @method "^(apply|construct)$"))
    ```
  - Inspect first argument for `readFileSync`, `exec`, `spawn` etc.
  - **Update evasion test E09:** `expected: Expected::Miss` → `Expected::Detect`

### Phase 4: Update Hornets Nest Tests

- [ ] **4.1** For each fixed vector, update `expected` in `evasion_tests.rs` from `Miss` to `Detect`
- [ ] **4.2** Add new scan-tier tests for P024 (pickle), P034 (Ruby pipe-open)
- [ ] **4.3** Run full scorecard and verify detection rate ≥ 80%
- [ ] **4.4** Verify no regressions in existing 427 unit tests

## Acceptance Criteria

- [ ] `needs_ast` gate triggers Python AST analysis for `.py` files containing `subprocess`, `eval`, etc.
- [ ] `needs_ast` gate triggers Ruby AST analysis for `.rb` files containing `eval`, `system`, etc.
- [ ] P014 regex catches `fromCharCode` with `+` and `-`, not just `^`
- [ ] New P024 rule detects `pickle.loads()` / `pickle.load()` / `pickle.Unpickler()`
- [ ] New P034 rule detects Ruby `open("|cmd")`
- [ ] Files >500KB are sampled (first+last 50KB) instead of skipped
- [ ] Unicode confusable characters are normalized before pattern matching
- [ ] 7 new AST patterns detect: mainModule.require, (0,require), global.Function,
      Function alias, import(), defineProperty getter, Reflect.apply
- [ ] Hornets Nest scorecard shows ≥80% detection (≥30/37 vectors)
- [ ] All 427 existing unit tests still pass
- [ ] `cargo fmt --check` + `cargo clippy -- -D warnings` clean

## Dependencies & Risks

| Risk | Mitigation |
|---|---|
| Unicode normalization adds dependency | `unicode-normalization` is widely used, small footprint |
| Large file sampling misses middle-of-file payloads | Acceptable — attacker has to guess we sample head+tail |
| Python `needs_ast` probes too broad (e.g., `eval(` matches benign code) | Probes only gate AST analysis, not findings — false AST parse is cheap |
| Tree-sitter query syntax varies by grammar version | Pin tree-sitter-* crate versions in Cargo.toml (already done) |
| Some fixes may cause new findings on real projects | Run against pos, hubstaff-server, hubstaff-cli after sprint |

## References

### Files to Modify

| File | Changes |
|---|---|
| `src/checks/patterns.rs:312-321` | Language-aware `needs_ast` gate |
| `src/checks/patterns.rs:129` | P014 regex broadening |
| `src/checks/patterns.rs:216,285` | Large file sampling |
| `src/ast/mod.rs:82` | Make `detect_language` public |
| `src/ast/javascript.rs` | 7 new/extended AST queries (E08, E09, E14, E15, E16, E17, E18) |
| `src/ast/python.rs` | New P024 pickle rule |
| `src/ast/ruby.rs` | New P034 open-pipe rule |
| `src/output.rs` | RuleInfo entries for P024, P034 |
| `Cargo.toml` | Add `unicode-normalization` |
| `tests/hornets_nest/evasion_tests.rs` | Flip 13 vectors from Miss→Detect |
| `tests/hornets_nest/scan_tests.rs` | Add P024, P034 scan tests |

### Brainstorm & Prior Art

- Brainstorm: `docs/brainstorms/2026-04-02-detection-improvement-roadmap-brainstorm.md`
- Hornets Nest: `docs/brainstorms/2026-04-02-hornets-nest-brainstorm.md`
- Hornets Nest plan: `docs/plans/2026-04-02-feat-hornets-nest-adversarial-test-suite-plan.md`
- tree-sitter-graph: https://github.com/tree-sitter/tree-sitter-graph
- Wobfuscator evasion paper: https://ieeexplore.ieee.org/document/9833626/
