---
title: "feat: Smart Analysis Engine — AST Filtering, LLM Triage, Deep Audit"
type: feat
date: 2026-03-29
brainstorm: docs/brainstorms/2026-03-28-smart-analysis-brainstorm.md
---

# Smart Analysis Engine

## Overview

Transform depsec's pattern detection from naive regex matching to a three-layer analysis engine: AST-aware filtering (tree-sitter), LLM-powered triage (OpenRouter), and deep package audit for novel vulnerabilities. Each layer builds on the previous and is independently useful.

**Test target:** `~/Development/pos` — a real production POS app (Svelte + Tauri + Rust) that currently scores 0.6/10 with 5,765 pattern findings (700+ false positive exec() warnings).

## Problem Statement

depsec's P001 rule (`\b(eval|exec)\s*\(`) cannot distinguish `regex.exec()` (benign) from `child_process.exec(variable)` (dangerous). This produces ~95% false positives on real projects, making the tool unusable for pattern detection. The scoring system reflects this — healthy apps get grade F.

## Proposed Solution

Three phases, shipped and tested incrementally:

| Phase | What | New Dependencies | LLM Required |
|-------|------|-----------------|--------------|
| 1 | File exclusions + package aggregation + persona model | 0 | No |
| 2 | tree-sitter AST integration for P001/P002/P008 | +6 crates | No |
| 3 | LLM triage (`--triage`) + deep audit (`depsec audit`) | 0 (reuse ureq) | Yes (optional) |

## Technical Approach

### Architecture

```
                    ┌─────────────────────────┐
                    │     depsec scan .        │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │     PatternsCheck::run() │
                    │                         │
                    │  ┌───────────────────┐  │
                    │  │ File Exclusions   │  │  Phase 1
                    │  │ (.map, .vite/, …) │  │
                    │  └───────┬───────────┘  │
                    │          │              │
                    │  ┌───────▼───────────┐  │
                    │  │ Regex Engine      │  │  Existing (kept for P003/P007/P010…)
                    │  │ (line-by-line)    │  │
                    │  └───────┬───────────┘  │
                    │          │              │
                    │  ┌───────▼───────────┐  │
                    │  │ AST Engine        │  │  Phase 2
                    │  │ (tree-sitter)     │  │
                    │  │ P001/P002/P008    │  │
                    │  └───────┬───────────┘  │
                    │          │              │
                    │  ┌───────▼───────────┐  │
                    │  │ Package Aggregator│  │  Phase 1
                    │  │ + Persona Filter  │  │
                    │  └───────────────────┘  │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
              opt   │   --triage              │  Phase 3
                    │   LLM Triage Engine     │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
              new   │   depsec audit <pkg>    │  Phase 3
              cmd   │   Deep Audit Engine     │
                    └─────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Noise Reduction (No New Dependencies)

Pure refactoring of `src/checks/patterns.rs` and `src/output.rs`. Zero new crate dependencies. Immediate noise reduction on POS project.

#### Phase 1.1: File & Directory Exclusions

**Files to modify:** `src/checks/patterns.rs`

Add to the existing skip logic (after `BINARY_EXTENSIONS` check):

```rust
// New exclusions — skip entirely, these generate noise with zero signal
const SKIP_EXTENSIONS: &[&str] = &[
    ".map",         // source maps — stringified source, not executable
    ".d.ts",        // TypeScript declarations — type definitions only
    ".d.ts.map",    // declaration source maps
    ".d.mts",       // module declaration files
    ".d.cts",       // CommonJS declaration files
];

const SKIP_DIRS: &[&str] = &[
    ".vite",        // Vite prebundled cache — duplicates of node_modules packages
    "__tests__",    // test directories inside deps
    "test",         // test directories inside deps
    "tests",        // test directories inside deps
    "spec",         // test directories inside deps
    "__mocks__",    // mock directories inside deps
    "__fixtures__", // test fixtures inside deps
];
```

Also skip: `README.md`, `CHANGELOG.md`, `LICENSE`, `HISTORY.md` files inside dep dirs.

**Acceptance criteria:**
- [ ] `.map` files no longer scanned (kills devalue.js.map false positives)
- [ ] `.vite/` directory no longer scanned (kills ~38 duplicate findings)
- [ ] `.d.ts` files no longer scanned
- [ ] Test/mock directories inside deps no longer scanned
- [ ] Existing P-rules still fire on actual source files

**Test:** Run `depsec scan ~/Development/pos` before and after, compare finding counts.

---

#### Phase 1.2: Finding Metadata Enhancement

**Files to modify:** `src/checks/mod.rs`

Add `confidence` and `package` fields to `Finding`:

```rust
#[derive(Debug, Clone, Serialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,    // NEW
    pub message: String,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub suggestion: Option<String>,
    pub auto_fixable: bool,
    pub package: Option<String>,   // NEW — extracted from file path
}
```

**Package extraction logic** (new helper in `patterns.rs`):
```rust
fn extract_package_name(file_path: &str) -> Option<String> {
    // "node_modules/@scope/pkg/lib/file.js" → "@scope/pkg"
    // "node_modules/lodash/index.js" → "lodash"
    // "vendor/bundle/ruby/3.2.0/gems/rails-7.1/..." → "rails-7.1"
    // ".venv/lib/python3.11/site-packages/requests/..." → "requests"
}
```

**Confidence assignment per rule:**

| Rule | Confidence | Rationale |
|------|-----------|-----------|
| P001 (regex-based, pre-AST) | Low | High FP rate without import context |
| P002 base64→exec | Medium | Chain pattern more specific than bare exec |
| P003 raw IP HTTP | Medium | Could be local dev URLs |
| P004 credential reads | High | Very specific file paths |
| P005 binary reads | Medium | Could be legitimate image processing |
| P006 install script curl | High | Very specific context (install scripts only) |
| P007 entropy | Low | Many legitimate high-entropy strings |
| P008 new Function | Medium | Similar to P001 but less common |
| P009 .pth files | High | Very specific attack vector |
| P010 IMDS | High | Very specific IPs |
| P011 env serialization | Medium | Could be legitimate logging |
| P012 install hooks | High | Very specific context |

**Acceptance criteria:**
- [ ] `Finding` struct has `confidence` and `package` fields
- [ ] All pattern rules assign appropriate confidence
- [ ] Package name extracted from file path for all dep-dir findings
- [ ] JSON output includes new fields
- [ ] SARIF output includes confidence as `level` property

---

#### Phase 1.3: Persona Model

**Files to modify:** `src/config.rs`, `src/main.rs`, `src/checks/patterns.rs`, `src/output.rs`

Add `--persona` CLI flag with three levels:

```rust
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub enum Persona {
    Regular,   // Default: High confidence findings only
    Pedantic,  // Medium+ confidence
    Auditor,   // Everything including Low confidence
}
```

**CLI:**
```
depsec scan . --persona auditor
```

**Config:**
```toml
[scan]
persona = "regular"
```

**Filtering logic** in `PatternsCheck::run()`:
```rust
let min_confidence = match ctx.config.persona {
    Persona::Regular => Confidence::High,
    Persona::Pedantic => Confidence::Medium,
    Persona::Auditor => Confidence::Low,
};
// Only include findings >= min_confidence
```

**Acceptance criteria:**
- [ ] `--persona regular` (default) hides Low/Medium confidence findings
- [ ] `--persona pedantic` shows Medium+ confidence findings
- [ ] `--persona auditor` shows all findings
- [ ] Hidden findings count shown: `+47 hidden (use --persona auditor)`
- [ ] Persona configurable in `depsec.toml`

---

#### Phase 1.4: Package-Level Aggregation

**Files to modify:** `src/output.rs`

Instead of printing 700 individual findings, aggregate by package:

**Current:**
```
✗ eval()/exec() with variable input: var e2 = /pattern/.exec(i2); (node_modules/.vite/deps/posthog-js.js:212)
✗ eval()/exec() with variable input: var e2 = ei.exec(t2); (node_modules/.vite/deps/posthog-js.js:336)
... 27 more ...
```

**After:**
```
[Patterns]
  ✗ posthog-js — 29 exec() findings (confidence: low)
    Top: node_modules/.vite/deps/posthog-js.js:212, :336, :341
    → Likely regex.exec() — use --persona auditor for details

  ✗ shelljs@0.8.5 — 3 exec() findings (confidence: high)
    child_process.exec() with variable args at src/exec.js:45, :78
    → Review or remove this dependency

  +12 packages with low-confidence findings (use --verbose)
```

**Implementation:** After collecting all findings in `PatternsCheck::run()`, group by `finding.package` before returning `CheckResult`. The aggregation happens in output rendering, not in the check itself — `CheckResult` still contains individual findings for JSON/SARIF output.

**Acceptance criteria:**
- [ ] Human output groups findings by package name
- [ ] Package summary shows: package name, finding count, top confidence level
- [ ] `--verbose` expands all findings (un-aggregated, like today)
- [ ] JSON/SARIF output unchanged (still individual findings)
- [ ] Hidden package count shown at bottom

---

#### Phase 1.5: Config Enhancements

**Files to modify:** `src/config.rs`, `src/checks/patterns.rs`

```toml
[patterns]
# Trust specific packages for specific rules
[patterns.allow]
"posthog-js" = ["P001"]     # analytics SDK, legitimate exec usage
"vitest" = ["P001"]          # test runner

# Skip specific directory patterns
[patterns.skip_dirs]
dirs = [".vite"]             # already handled by default, but user can add more
```

**Acceptance criteria:**
- [ ] Per-package rule allowlisting works
- [ ] Custom skip_dirs configurable in depsec.toml
- [ ] Allowed packages show as `✓ posthog-js — 29 findings suppressed (allowed in config)`

---

#### 🧪 Phase 1 Testing Checkpoint

**Run against POS project:**
```bash
# Before (baseline)
depsec scan ~/Development/pos 2>&1 | tail -20

# After Phase 1
cargo run -- scan ~/Development/pos 2>&1 | tail -40
cargo run -- scan ~/Development/pos --persona auditor 2>&1 | tail -40
cargo run -- scan ~/Development/pos --verbose 2>&1 | wc -l
```

**Expected results:**
- Pattern findings drop from 5,765 to <500 in regular persona
- exec() warnings drop from 700 to <50 (mostly Low confidence, hidden by default)
- Grade improves from F to at least D (pattern score no longer zeroed)

**🔍 codex-investigator review:** After Phase 1 implementation, have codex-investigator review all changed files for correctness, edge cases, and consistency with existing patterns.

---

### Phase 2: tree-sitter AST Integration

Add tree-sitter for structural code understanding. This is the phase that truly solves the regex.exec() vs child_process.exec() problem.

#### Phase 2.1: Add tree-sitter Dependencies

**Files to modify:** `Cargo.toml`

```toml
[dependencies]
# ... existing deps ...
tree-sitter = "0.24"
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.23"
tree-sitter-rust = "0.23"
```

**Acceptance criteria:**
- [ ] `cargo build` succeeds with new dependencies
- [ ] `cargo deny check` passes (licenses OK)
- [ ] Binary size increase is ≤2MB
- [ ] Build time increase is ≤10s

---

#### Phase 2.2: AST Module Scaffold

**New files:**

```
src/ast/
├── mod.rs           # Language dispatch, AstAnalyzer trait
├── javascript.rs    # JS/TS queries for dangerous patterns
├── python.rs        # Python queries
└── rust_lang.rs     # Rust queries (for unsafe, Command::new)
```

**`src/ast/mod.rs`:**
```rust
use tree_sitter::{Parser, Language, Query, QueryCursor, Tree};
use std::path::Path;

pub struct AstAnalyzer {
    js_parser: Parser,
    ts_parser: Parser,
    py_parser: Parser,
    rs_parser: Parser,
}

pub struct AstFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub line: usize,
    pub context: String,       // surrounding code snippet
    pub receiver: Option<String>, // what object .exec() was called on
    pub import_source: Option<String>, // where the object was imported from
}

impl AstAnalyzer {
    pub fn new() -> Self { /* initialize parsers with language grammars */ }

    /// Analyze a file, returning any security findings
    pub fn analyze_file(&mut self, path: &Path, content: &str) -> Vec<AstFinding> {
        let lang = detect_language(path);
        match lang {
            Some(Lang::JavaScript | Lang::TypeScript) => self.analyze_js(content),
            Some(Lang::Python) => self.analyze_python(content),
            Some(Lang::Rust) => self.analyze_rust(content),
            None => vec![], // unknown language, skip AST analysis
        }
    }
}
```

**Acceptance criteria:**
- [ ] `AstAnalyzer::new()` initializes all 4 language parsers
- [ ] `detect_language()` maps file extensions to languages
- [ ] Module compiles and is usable from `patterns.rs`

---

#### Phase 2.3: P001 AST Upgrade — exec() Detection

**Files to modify:** `src/ast/javascript.rs`, `src/checks/patterns.rs`

**Two-pass approach for JavaScript/TypeScript:**

**Pass 1 — Import detection query:**
```scheme
;; CommonJS: const cp = require('child_process')
(variable_declarator
  name: (identifier) @alias
  value: (call_expression
    function: (identifier) @_req
    arguments: (arguments (string (string_fragment) @module)))
  (#eq? @_req "require")
  (#match? @module "^(child_process|shelljs|execa)$"))

;; CommonJS destructured: const { exec } = require('child_process')
(variable_declarator
  name: (object_pattern
    (shorthand_property_identifier_pattern) @destructured)
  value: (call_expression
    function: (identifier) @_req
    arguments: (arguments (string (string_fragment) @module)))
  (#eq? @_req "require")
  (#match? @module "^(child_process|shelljs|execa)$"))

;; ES import: import { exec } from 'child_process'
(import_statement
  (import_clause
    (named_imports (import_specifier name: (identifier) @imported)))
  source: (string (string_fragment) @module)
  (#match? @module "^(child_process|shelljs|execa)$"))
```

Result: set of `(alias_name, source_module)` tuples.

**Pass 2 — Dangerous call detection query:**
```scheme
;; Method call: cp.exec(arg), shelljs.exec(arg)
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  arguments: (arguments . (_) @first_arg)
  (#match? @method "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"))

;; Direct call: exec(arg) — only if 'exec' was destructured from dangerous module
(call_expression
  function: (identifier) @func
  arguments: (arguments . (_) @first_arg)
  (#match? @func "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"))
```

**Programmatic filtering (Rust side):**
1. Run Pass 1 to get `dangerous_aliases: HashSet<String>`
2. Run Pass 2, for each match:
   - If `@obj` is in `dangerous_aliases` → **High confidence finding**
   - If `@func` is in `dangerous_aliases` (destructured import) → **High confidence finding**
   - If `@obj` / `@func` NOT in aliases → **Skip** (it's regex.exec() or db.exec())
3. Check `@first_arg` node type:
   - `string` / `string_fragment` → downgrade to **Medium** (static command)
   - `template_string` with substitutions → **Critical** (interpolated command)
   - `identifier` → **High** (variable input)

**Integration with PatternsCheck:**
```rust
// In PatternsCheck::run():
let mut ast = AstAnalyzer::new();

for file in walk_dep_files(ctx.root) {
    let content = read_file(&file)?;

    // AST analysis for rules that benefit from structure
    let ast_findings = ast.analyze_file(&file, &content);

    // Regex analysis for rules that don't need AST (P003, P007, P010, etc.)
    let regex_findings = scan_with_regex(&file, &content, &compiled_patterns);

    // Deduplicate: if AST found something on the same line as regex, prefer AST finding
    // (AST findings have higher confidence and more context)
    findings.extend(merge_findings(ast_findings, regex_findings));
}
```

**Acceptance criteria:**
- [ ] `regex.exec()` calls are NO LONGER flagged (the core fix!)
- [ ] `child_process.exec(variable)` IS flagged as High confidence
- [ ] `child_process.exec("static string")` IS flagged as Medium confidence
- [ ] Destructured imports are resolved: `const { exec } = require('child_process'); exec(cmd)` → flagged
- [ ] Aliased imports are resolved: `const cp = require('child_process'); cp.exec(cmd)` → flagged
- [ ] Non-dangerous `.exec()` calls are skipped: `db.exec()`, `cursor.execute()`, etc.
- [ ] Finding includes `receiver` and `import_source` for better context

---

#### Phase 2.4: P002/P008 AST Upgrades

**P002 (base64→exec chain):** Use AST to verify actual decode-then-execute flow, not just pattern co-occurrence in stringified source maps.

**P008 (new Function()):** Use AST to check if `Function` constructor is called with a variable argument, not just any `Function(` string.

Same two-pass approach as P001 but with different queries.

**Acceptance criteria:**
- [ ] P002 no longer fires on `.map` files (AST doesn't parse source map JSON as code)
- [ ] P008 only fires on `new Function(variable)`, not `Function.prototype` references

---

#### Phase 2.5: Python AST Queries

**Files to modify:** `src/ast/python.rs`

Python dangerous patterns:
```scheme
;; subprocess.call(var, shell=True)
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list
    (identifier) @first_arg)
  (#eq? @obj "subprocess")
  (#match? @method "^(call|run|Popen|check_output|check_call)$"))

;; os.system(var)
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "os")
  (#match? @method "^(system|popen|execvp?)$"))
```

**Acceptance criteria:**
- [ ] Python `subprocess.call()`, `os.system()` with variable args → flagged
- [ ] Python `cursor.execute()` → NOT flagged
- [ ] Python `re.match()`, `re.search()` → NOT flagged
- [ ] `eval()` and `exec()` (Python builtins) → still flagged (these are always dangerous in Python)

---

#### 🧪 Phase 2 Testing Checkpoint

**Run against POS project:**
```bash
# Compare before/after AST integration
cargo run -- scan ~/Development/pos 2>&1 | grep -c "exec()"
# Expected: <10 (down from 700+)

cargo run -- scan ~/Development/pos --persona auditor 2>&1 | grep -c "exec()"
# Expected: still <10 (AST correctly classifies, not just hides)

cargo run -- scan ~/Development/pos --format json 2>&1 | jq '.results[] | select(.category == "Patterns") | .findings | length'
# Expected: dramatic reduction
```

**Expected results:**
- exec() false positives eliminated entirely (not hidden, truly not detected)
- POS project grade improves to C or better
- AST analysis adds <1s to scan time (tree-sitter is fast)

**🔍 codex-investigator review:** Review the entire `src/ast/` module for:
- Correctness of tree-sitter queries (do they match what we think?)
- Edge cases: what about minified code? Webpack bundles? TypeScript enums?
- Memory safety: are we handling large files correctly?
- Performance: any accidental O(n²) in the merge logic?

---

### Phase 3: LLM Triage & Deep Audit

#### Phase 3.1: OpenRouter Client

**New file:** `src/llm.rs`

Minimal HTTP client for OpenRouter's chat completion API. Uses `ureq` (already a dependency — no new crates!).

```rust
pub struct LlmClient {
    api_key: String,
    model: String,
    base_url: String,  // "https://openrouter.ai/api/v1"
}

pub struct ChatMessage {
    pub role: String,    // "system", "user", "assistant"
    pub content: String,
}

pub struct ChatResponse {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
}

pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl LlmClient {
    pub fn from_env() -> Option<Self> { /* reads OPENROUTER_API_KEY */ }
    pub fn from_config(config: &Config) -> Option<Self> { /* reads from depsec.toml */ }

    pub fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse> { /* ureq POST */ }
    pub fn chat_json<T: DeserializeOwned>(&self, messages: &[ChatMessage]) -> Result<T> {
        /* chat + parse JSON from response */
    }

    pub fn estimate_cost(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        /* rough cost estimate based on model pricing */
    }
}
```

**Configuration:**
```toml
[triage]
api_key_env = "OPENROUTER_API_KEY"
model = "anthropic/claude-sonnet-4-6"
max_findings = 50
timeout_seconds = 30
```

**Acceptance criteria:**
- [ ] `LlmClient::from_env()` reads API key from environment
- [ ] `chat()` sends properly formatted OpenRouter request
- [ ] Response parsed correctly (content + usage)
- [ ] Timeout and error handling (no panics on API errors)
- [ ] Missing API key → clear error message with setup instructions

---

#### Phase 3.2: Triage Engine (`--triage` flag)

**Files to modify:** `src/main.rs` (new flag), new `src/triage.rs`

```rust
pub struct TriageResult {
    pub finding: Finding,
    pub classification: Classification,  // TP, FP, NeedsInvestigation
    pub confidence: f64,                 // 0.0 - 1.0
    pub reasoning: String,
    pub recommendation: String,
}

pub enum Classification {
    TruePositive,
    FalsePositive,
    NeedsInvestigation,
}

pub fn triage_findings(
    findings: &[Finding],
    root: &Path,
    client: &LlmClient,
    config: &TriageConfig,
) -> Vec<TriageResult> {
    // 1. Build context per finding (±30 lines + imports)
    // 2. Send to LLM with structured prompt
    // 3. Parse JSON response
    // 4. Filter by confidence threshold (>0.7)
}
```

**CLI:**
```bash
depsec scan . --triage                    # Triage all findings
depsec scan . --triage --triage-dry-run   # Show what would be sent
depsec scan . --triage --triage-budget 1.00  # Max spend
```

**Prompt design:** See `docs/brainstorms/2026-03-28-layer2-llm-triage.md` §4 for full prompt templates.

**Acceptance criteria:**
- [ ] `--triage` sends findings to OpenRouter for analysis
- [ ] Each finding gets TP/FP/NI classification with confidence
- [ ] Results displayed inline with scan output
- [ ] `--triage-dry-run` shows what would be sent without API calls
- [ ] Cost estimation shown before proceeding (interactive) or respected (CI)
- [ ] Findings below 0.7 confidence auto-classified as NeedsInvestigation

---

#### Phase 3.3: Triage Caching

**New file:** `src/triage_cache.rs`

Cache triage results by `(package, version, rule_id, content_hash)`:

```
~/.cache/depsec/triage/
├── shelljs@0.8.5/
│   └── P001-a3f2b1c4.json
```

**Acceptance criteria:**
- [ ] Second scan with `--triage` uses cached results (no API calls)
- [ ] Cache invalidated when package version changes
- [ ] Cache TTL configurable (default 30 days)
- [ ] `depsec cache clear` command to purge

---

#### Phase 3.4: Deep Audit Command

**New files:** `src/audit.rs`, `src/audit/capability.rs`, `src/audit/conversation.rs`

```bash
depsec audit posthog-js                    # Full audit
depsec audit shelljs --focus rce           # Focus on RCE
depsec audit posthog-js --dry-run          # Show what would be analyzed
depsec audit posthog-js --budget 2.00      # Max spend
```

**Four-phase architecture:**

1. **Reconnaissance** — locate package, parse metadata, build file tree, identify entry points
2. **Capability Analysis** — tree-sitter scan for dangerous API usage (reuses Phase 2 AST engine)
3. **LLM Deep Analysis** — iterative call-chain tracing with vulnerability-specific prompts
4. **Self-Verification** — adversarial pass ("argue against this finding")

See `docs/brainstorms/2026-03-28-layer3-deep-audit.md` for full design details.

**Acceptance criteria:**
- [ ] `depsec audit <package>` locates and profiles the package
- [ ] Capability map generated without LLM (tree-sitter only)
- [ ] LLM iterative analysis follows call chains (max 8 rounds)
- [ ] Self-verification pass challenges each finding
- [ ] Output: terminal, JSON, SARIF formats
- [ ] Budget enforcement with per-round cost tracking
- [ ] `--dry-run` shows capability map and what would be sent to LLM

---

#### Phase 3.5: Variant Analysis

When a package has known CVEs (from the deps check), use them as seeds:

```bash
depsec audit tar   # tar has 6 known CVEs — variant analysis runs automatically
```

The LLM receives the CVE description and searches for similar unpatched patterns.

**Acceptance criteria:**
- [ ] Known CVEs automatically trigger variant analysis
- [ ] Variant findings clearly labeled as "variant of CVE-XXXX"
- [ ] Can be disabled with `--no-variant`

---

#### 🧪 Phase 3 Testing Checkpoint

**Run against POS project:**
```bash
# Triage remaining findings
OPENROUTER_API_KEY=sk-or-... cargo run -- scan ~/Development/pos --triage

# Deep audit a specific package
OPENROUTER_API_KEY=sk-or-... cargo run -- audit shelljs
OPENROUTER_API_KEY=sk-or-... cargo run -- audit posthog-js --focus rce

# Audit a package with known CVEs (variant analysis)
OPENROUTER_API_KEY=sk-or-... cargo run -- audit tar
```

**🔍 codex-investigator review:** Review `src/llm.rs`, `src/triage.rs`, `src/audit.rs` for:
- API key handling (not leaked in logs/output)
- Prompt injection risks (dependency code sent to LLM could contain adversarial content)
- Cost calculation accuracy
- Error handling for API failures, timeouts, malformed responses
- Cache invalidation correctness

---

## Alternative Approaches Considered

| Approach | Why Rejected |
|----------|-------------|
| **ast-grep** instead of tree-sitter | +5MB binary (vs +1.5MB), poor Rust docs, no native negative matching |
| **Semgrep rules** | External dependency, requires Semgrep installed, Python runtime |
| **Direct Claude API** | Vendor lock-in; OpenRouter gives flexibility at same quality |
| **reqwest** for HTTP | Would add async runtime (tokio); ureq is already present and sync |
| **Registry source** instead of disk | Requires network, may differ from installed version, more complex |

## Acceptance Criteria

### Functional Requirements

- [ ] `depsec scan .` on POS project produces <100 pattern findings (down from 5,765)
- [ ] Zero false positives from `regex.exec()` pattern
- [ ] `--persona` flag controls finding visibility at 3 levels
- [ ] `--triage` flag sends findings to LLM for classification
- [ ] `depsec audit <package>` performs deep source code analysis
- [ ] All existing functionality preserved (no regressions)

### Non-Functional Requirements

- [ ] Binary size increase ≤2MB
- [ ] Scan time increase ≤2s (tree-sitter parsing is fast)
- [ ] New crate dependencies ≤6
- [ ] `--triage` and `audit` work without API key (graceful degradation)

### Quality Gates

- [ ] `cargo clippy` passes
- [ ] `cargo deny check` passes (licenses)
- [ ] `cargo test` passes
- [ ] codex-investigator review after each phase
- [ ] POS project tested after each phase

## Dependencies & Prerequisites

- tree-sitter crates require a C compiler at build time (`cc` crate, auto-resolved)
- OpenRouter API key required only for Layer 2/3 (optional)
- POS project at `~/Development/pos` available for testing

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| tree-sitter queries miss edge cases | FPs or FNs | Test extensively on POS project + codex review |
| tree-sitter breaks cross-compilation | Can't build for Linux/ARM | Test CI build early in Phase 2 |
| OpenRouter API changes | Triage/audit breaks | Thin client, easy to swap endpoint |
| LLM hallucinates vulnerabilities | False alarms | Self-verification pass + confidence thresholds |
| Large packages overwhelm LLM context | Poor audit quality | Token budget + iterative approach |

## References & Research

### Internal
- Brainstorm overview: `docs/brainstorms/2026-03-28-smart-analysis-brainstorm.md`
- Layer 1 design: `docs/brainstorms/2026-03-28-layer1-smart-filtering.md`
- Layer 2 design: `docs/brainstorms/2026-03-28-layer2-llm-triage.md`
- Layer 3 design: `docs/brainstorms/2026-03-28-layer3-deep-audit.md`
- Current patterns check: `src/checks/patterns.rs`
- Current config: `src/config.rs`

### External
- tree-sitter Rust docs: docs.rs/tree-sitter
- tree-sitter query syntax: tree-sitter.github.io/tree-sitter/using-parsers/queries
- OpenRouter API docs: openrouter.ai/docs
- zizmor persona model: github.com/zizmorcore/zizmor
- Semgrep import-aware rules: github.com/semgrep/semgrep-rules
- VulnHuntr call-chain tracing: github.com/protectai/vulnhuntr
