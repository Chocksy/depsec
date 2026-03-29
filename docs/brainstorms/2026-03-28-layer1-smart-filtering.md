# Layer 1: Smart Filtering — Detailed Design

**Date:** 2026-03-28
**Status:** Draft
**Goal:** Reduce false positives by 90%+ and make scan output actionable — no LLM required.

---

## Overview

Layer 1 transforms depsec's pattern detection from naive regex matching to context-aware AST analysis using tree-sitter, combined with UX improvements stolen from the best tools in the space.

**Expected impact on POS project scan:**
- Current: 5,765 pattern findings, 700+ exec() warnings, grade F
- After Layer 1: ~50-100 pattern findings, <10 exec() warnings, all actionable

---

## 1. tree-sitter Integration

### 1.1 Dependencies

```toml
[dependencies]
tree-sitter = "0.26"
tree-sitter-javascript = "0.25"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.25"
tree-sitter-rust = "0.24"
```

**Impact:** +1.5MB binary size, ~7s added build time. Requires C compiler (cc crate).

### 1.2 Architecture

Create a new module `src/ast/` alongside the existing `src/checks/patterns.rs`:

```
src/
├── ast/
│   ├── mod.rs          # AstAnalyzer trait + language dispatch
│   ├── javascript.rs   # JS/TS-specific queries
│   ├── python.rs       # Python-specific queries
│   └── rust_lang.rs    # Rust-specific queries
├── checks/
│   ├── patterns.rs     # Existing regex engine (kept for non-AST rules)
│   └── ...
```

**Key principle:** tree-sitter replaces regex ONLY for rules that need structural understanding. Rules like P003 (IP addresses), P007 (entropy), P010 (IMDS IPs) stay regex-based — they don't need AST context.

### 1.3 Which Rules Get AST Upgrade

| Rule | Current | After Layer 1 | Why |
|------|---------|---------------|-----|
| **P001** eval/exec with variable | Regex: `\b(eval\|exec)\s*\(` | AST: check receiver object + import context | Eliminates regex.exec() false positives |
| **P002** base64→exec chain | Regex | AST: verify actual decode→execute flow | Eliminates .map file false positives |
| **P003** HTTP to raw IP | Regex | Regex (unchanged) | IP detection doesn't need AST |
| **P004** credential file reads | Regex | AST: verify fs.readFile/open call context | Could reduce false positives in comments |
| **P005** binary file reads | Regex | Regex (unchanged) | File extension matching is sufficient |
| **P006** curl/wget in install scripts | Regex | AST: verify actual command execution | Could distinguish command strings from docs |
| **P007** high-entropy strings | Regex | Regex (unchanged) | Shannon entropy is content-based, not structural |
| **P008** new Function() | Regex | AST: check if Function constructor with variable | Similar problem to P001 |
| **P009** Python .pth files | Regex | Regex (unchanged) | .pth files are simple text, AST not needed |
| **P010** IMDS probing | Regex | Regex (unchanged) | IP literal detection is sufficient |
| **P011** env serialization | Regex | AST: verify process.env access pattern | Could reduce false positives |
| **P012** install script hooks | Regex | Regex (unchanged) | package.json is JSON, not code |

**Priority AST upgrades: P001, P002, P008** — these account for ~90% of false positives.

### 1.4 P001 AST Query Design (exec() Problem)

**Two-pass approach (stolen from Semgrep):**

**Pass 1: Identify dangerous imports**
```
// Find: const cp = require('child_process')
// Find: const { exec, spawn } = require('child_process')
// Find: import { exec } from 'child_process'
// Find: const shelljs = require('shelljs')
// Find: const execa = require('execa')
```

tree-sitter query:
```scheme
;; CommonJS require
(variable_declarator
  name: [(identifier) @alias (object_pattern (shorthand_property_identifier_pattern) @destructured)]
  value: (call_expression
    function: (identifier) @_req
    arguments: (arguments (string (string_fragment) @module)))
  (#eq? @_req "require")
  (#match? @module "^(child_process|shelljs|execa)$"))

;; ES import
(import_statement
  source: (string (string_fragment) @module)
  (#match? @module "^(child_process|shelljs|execa)$"))
```

Result: a set of local variable names that are aliases for dangerous modules (e.g., `cp`, `exec`, `spawn`, `shelljs`).

**Pass 2: Flag calls on dangerous aliases**
```scheme
;; Method call: cp.exec(variable), shelljs.exec(cmd)
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  arguments: (arguments . (_) @first_arg)
  (#match? @method "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$")
  ;; @obj must be in the dangerous-alias set (checked programmatically)
)

;; Direct call from destructured import: exec(variable)
(call_expression
  function: (identifier) @func
  arguments: (arguments . (_) @first_arg)
  (#match? @func "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$")
  ;; @func must be in the destructured-import set (checked programmatically)
)
```

**What this catches:**
- `child_process.exec(userInput)` ✓ FLAGGED
- `cp.exec(command)` ✓ FLAGGED (cp is alias for child_process)
- `exec(cmd)` ✓ FLAGGED (exec destructured from child_process)
- `shelljs.exec(command)` ✓ FLAGGED
- `execa(command)` ✓ FLAGGED

**What this skips:**
- `regex.exec("pattern")` ✗ NOT FLAGGED (regex is not a dangerous module)
- `db.exec("SELECT ...")` ✗ NOT FLAGGED (db is not a dangerous module)
- `/pattern/.exec(string)` ✗ NOT FLAGGED (regex literal, not an identifier)
- `child_process.exec("literal string")` ✗ NOT FLAGGED (static argument — see 1.5)

### 1.5 Static Argument Demotion

Stolen from Semgrep's `pattern-not-inside: $CP.$EXEC("...",...)` technique.

If the first argument to a dangerous exec call is a **string literal** (not a variable), downgrade severity from High to Low/Informational:

```javascript
exec("ls -la")           // Low — static command, not injectable
exec(userInput)           // High — variable input, potentially injectable
exec(`ls ${userInput}`)   // Critical — template literal with variable interpolation
```

tree-sitter can distinguish these by checking if the first argument node type is:
- `string` / `string_fragment` → static → Low
- `template_string` with `template_substitution` → interpolated → Critical
- `identifier` → variable → High
- Anything else → High (conservative default)

### 1.6 Python-Specific Queries

Python has the same problem but different patterns:

```python
# Dangerous:
import subprocess
subprocess.call(user_input, shell=True)
os.system(command)
eval(expression)
exec(code_string)

# Benign (false positives today):
re.exec(pattern)       # Not actually valid Python, but similar patterns exist
cursor.execute(query)  # Database execute, not shell execute
```

Two-pass approach:
1. Find `import subprocess`, `import os`, `from subprocess import *`
2. Flag `subprocess.call()`, `subprocess.Popen()`, `os.system()`, `os.popen()` with variable arguments
3. Keep `eval()` and `exec()` as direct flags (these are always builtins in Python, no import needed)
4. Exclude `cursor.execute()`, `conn.execute()` — database calls

### 1.7 File Type Exclusions

**Skip entirely** (these generate massive noise with zero signal):
- `.map` files (source maps — contain stringified source code, not executable)
- `.d.ts` files (TypeScript declarations — type definitions, not runtime code)
- `.d.ts.map` files
- `.min.js` files (already partially excluded for entropy, extend to all P-rules)
- `README.md`, `CHANGELOG.md`, `LICENSE` in dependency dirs
- `__tests__/`, `test/`, `spec/`, `__mocks__/` directories inside deps

Add these to the existing skip list in `patterns.rs` alongside binary extensions.

---

## 2. Persona Model (stolen from zizmor)

### 2.1 Three Personas

```
depsec scan .                    # Default: "regular" persona
depsec scan . --persona auditor  # Show everything, including low-confidence
depsec scan . --persona pedantic # Show medium+ confidence
```

| Persona | Shows | Use Case |
|---------|-------|----------|
| **regular** (default) | High confidence, medium+ severity findings only | Day-to-day scanning, CI/CD |
| **pedantic** | Medium+ confidence findings, code smells | Periodic review, pre-release audit |
| **auditor** | Everything including low confidence and informational | Security audit, compliance review |

### 2.2 Finding Metadata

Each finding gets three dimensions (stolen from Semgrep + zizmor):

```rust
struct Finding {
    rule_id: String,           // e.g., "P001"
    severity: Severity,        // Critical, High, Medium, Low, Informational
    confidence: Confidence,    // High, Medium, Low
    persona: Persona,          // Regular, Pedantic, Auditor
    category: Category,        // Vuln, Audit, Style
    message: String,
    file: PathBuf,
    line: usize,
    package: Option<String>,   // NEW: which package this finding belongs to
    context: Option<String>,   // NEW: surrounding code snippet
}

enum Confidence { High, Medium, Low }
enum Persona { Regular, Pedantic, Auditor }
enum Category { Vuln, Audit, Style }
```

**Rule classification:**

| Rule | Confidence | Persona | Category |
|------|-----------|---------|----------|
| P001 (exec with AST) | High | Regular | Vuln |
| P001 (exec, regex fallback) | Low | Auditor | Audit |
| P002 (base64→exec) | High | Regular | Vuln |
| P003 (raw IP HTTP) | Medium | Pedantic | Audit |
| P004 (credential reads) | High | Regular | Vuln |
| P005 (binary reads) | Medium | Pedantic | Audit |
| P006 (install script curl) | High | Regular | Vuln |
| P007 (high entropy) | Low | Auditor | Audit |
| P008 (new Function) | High | Regular | Vuln |
| P009 (.pth files) | High | Regular | Vuln |
| P010 (IMDS) | High | Regular | Vuln |
| P011 (env serialization) | Medium | Pedantic | Audit |
| P012 (install hooks) | High | Regular | Vuln |

---

## 3. Package-Level Aggregation (stolen from Socket.dev)

### 3.1 Current Output (Per-Line)

```
✗ eval()/exec() with variable input: var e2 = /Windows NT/.exec(i2); (node_modules/.vite/deps/posthog-js.js:212)
✗ eval()/exec() with variable input: var e2 = ei.exec(t2); (node_modules/.vite/deps/posthog-js.js:336)
✗ eval()/exec() with variable input: var o2 = ri.exec(t2); (node_modules/.vite/deps/posthog-js.js:341)
... 26 more lines for posthog-js ...
```

### 3.2 New Output (Package-Level)

```
[Patterns]
  ✗ child_process.exec() with variable input in 2 packages:
    shelljs@0.8.5 — 3 calls (2 with variable args, 1 with static args)
      → npm audit: no known vulnerabilities
      → Review: src/exec.js:45, src/exec.js:78 (variable args)

    execa@5.1.1 — 1 call (variable arg from function parameter)
      → npm audit: no known vulnerabilities
      → Review: lib/command.js:23

  ⚠ High-entropy strings in 3 packages:
    fflate@0.8.2 — 1 string (4.8 bits/char, 276 chars) — likely compression table
    object.assign@4.1.5 — 1 string (4.8 bits/char, 513 chars) — likely polyfill
    +2 more (use --verbose to see all)

  ✓ 47 packages use regex.exec() — all benign (skipped by AST analysis)
  ✓ 12 packages use cursor.execute() — all database calls (skipped)

  +23 hidden findings in auditor persona (use --persona auditor to see all)
```

### 3.3 Implementation

1. **Group findings by package** — extract package name from file path (e.g., `node_modules/posthog-js/...` → `posthog-js`)
2. **Deduplicate** — same rule + same package = one entry with count
3. **Show top N** — display the most severe findings, collapse the rest
4. **Above/below the fold** — show count of hidden findings per persona level
5. **Cross-reference with deps check** — if a package also has known CVEs, note it in the pattern finding

---

## 4. Configuration & Suppression (stolen from Snyk + zizmor)

### 4.1 depsec.toml Additions

```toml
[scan]
persona = "regular"  # default persona

[patterns]
# Disable specific rules
disable = ["P007"]  # entropy detection is too noisy for this project

# Per-package overrides
[patterns.allow]
# Trust these packages for specific rules
"posthog-js" = ["P001", "P003"]  # analytics SDK, legitimate network + exec usage
"vitest" = ["P001"]               # test runner, legitimate eval/exec usage

[patterns.ignore]
# Suppress specific file locations (zizmor-style)
locations = [
    "node_modules/.vite/deps/*",  # Vite prebundled deps (already analyzed upstream)
]
```

### 4.2 Expiring Ignores (stolen from Snyk)

```toml
[[patterns.ignore.entries]]
rule = "P001"
package = "shelljs"
reason = "Accepted risk — used in build scripts only"
expires = "2026-06-28"  # Re-evaluate in 3 months
```

After expiration, the finding resurfaces. Prevents permanent suppression of real issues.

---

## 5. Source Map Handling

**Problem:** `.js.map` files contain `sourcesContent` which is the original source code base64-encoded or stringified. This triggers:
- P001 (exec/eval in stringified code)
- P002 (base64 chains)
- P007 (high entropy — it's literally encoded source)

**Solution:** Skip all `.map` files in pattern scanning. They are metadata, not executable code. Source maps are never executed at runtime — they're only used by dev tools for debugging.

Add `.map` to the existing binary extension skip list in `patterns.rs`.

---

## 6. Vite Pre-bundled Deps Handling

**Problem:** `node_modules/.vite/deps/` contains Vite's pre-bundled dependency cache. These are re-bundled versions of packages that already exist in `node_modules/`. Scanning both means **double-counting every finding**.

**Solution:** Skip `node_modules/.vite/` entirely. The original packages in `node_modules/` are scanned — the Vite cache is redundant.

---

## 7. Implementation Order

1. **File exclusions** (.map, .vite/, .d.ts, test dirs) — immediate noise reduction, ~30 minutes
2. **Package-level aggregation** in output — UX improvement, no detection changes
3. **tree-sitter integration** — add crates, create `src/ast/` module
4. **P001 AST upgrade** — two-pass import-aware exec detection
5. **P002/P008 AST upgrade** — same pattern for base64 chains and new Function()
6. **Persona model** — add `--persona` flag and finding metadata
7. **Configuration** — `depsec.toml` allow/ignore rules
8. **Expiring ignores** — time-based suppression

---

## 8. Success Metrics

Run against the POS project before and after:

| Metric | Before | Target |
|--------|--------|--------|
| Total pattern findings | 5,765 | <200 |
| exec() warnings | 700 | <10 (only real child_process/shell calls) |
| False positive rate (estimated) | ~95% | <10% |
| Scan grade | F (0.6/10) | Realistic grade reflecting actual risk |
| Time to review findings | Hours (impossible) | Minutes (actionable) |
