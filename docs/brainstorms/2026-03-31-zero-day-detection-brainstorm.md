# Brainstorm: Zero-Day Detection — Beyond Regex

**Date:** 2026-03-31
**Status:** Decided
**Trigger:** axios supply chain attack via plain-crypto-js (2026-03-31)

## Problem

The axios@1.14.1 compromise injected `plain-crypto-js@4.2.1` — a textbook supply chain dropper that completely evaded depsec's static analysis. Socket caught it in 6 minutes. We didn't.

### How the Payload Evades depsec

```javascript
// Evasion 1: Custom 2-layer obfuscation (XOR + reversed base64)
_trans_2 = function(x, r) {
    S = Buffer.from(E, "base64").toString("utf8");  // P002 can't see require on diff line
    return _trans_1(S, r);  // charCodeAt XOR — we don't detect this
}

// Evasion 2: Dynamic require with computed args
t = require(_trans_2(stq[2], ord));  // "fs" — not a string literal
W = require(_trans_2(stq[1], ord));  // "os" — P001 AST blind

// Evasion 3: Aliased dangerous function
{ execSync: F }  // F(s) not detectable as execSync

// Evasion 4: Anti-forensic cleanup
// Deletes setup.js, replaces package.json with clean copy
```

### Current Rules vs This Attack

| Rule | Fires? | Why |
|------|--------|-----|
| P001 AST | No | Requires `require("child_process")` with string literal |
| P001 regex | No | Looks for `exec(var)` — malware uses `F(s)` |
| P002 | No | `Buffer.from` and `require` on different lines |
| P007 entropy | Weak | Would fire on `stq` array strings (Low confidence, Medium severity) |
| P012 | No | Only checks root `package.json`, not dep package.json |
| AST gate | No | Gated on `content.contains("child_process")` — literal never appears |
| OSV/MAL | Reactive | Only after Socket/OSV publishes advisory |

**Result: depsec produces 0-1 weak findings on this zero-day.** Socket produces Critical alert in 6 minutes.

## Research Findings

### Socket's Detection Architecture (proprietary, rules NOT public)

Three layers:
1. **Static analysis** — custom engine analyzing code structure, capabilities, obfuscation
2. **AI/ML classification** — models for malware, anomaly, typosquat detection
3. **Metadata/provenance** — maintainer behavior, ownership changes, cross-version drift

80+ alert types across 5 severity levels. Key signals:
- `dynamicRequire` — dynamic require() calls
- `obfuscatedFile` — obfuscation patterns (line length, identifier patterns, constants)
- `installScripts` — postinstall hooks
- `networkAccess` — module-level network calls
- `shellAccess` — system shell invocation
- `envVars` — environment variable access
- Cross-version behavioral comparison

### Datadog GuardDog (BEST open-source alternative — rules are public)

**Repo: https://github.com/DataDog/guarddog**

Uses Semgrep YAML taint rules + YARA patterns. Key rules we can learn from:

| Rule | Technique |
|------|-----------|
| `npm-exec-base64.yml` | Taint: `Buffer.from()`/`atob()` → `eval()`/`new Function()` |
| `npm-obfuscation.yml` | `while(!![])`, `_0x` hex names, JSFuck, Caesar via `fromCharCode` |
| `npm-api-obfuscation.yml` | Bracket notation `module["function"]()`, `Reflect.get()` — 28 patterns |
| `npm-install-script.yml` | postinstall in deps (with allowlist for husky, prisma, etc.) |
| `npm-silent-process-execution.yml` | `child_process` with `{ detached: true, stdio: 'ignore' }` |
| `npm-steganography.yml` | Image → `eval()` / `steggy.reveal` |

### OpenSSF Package Analysis (dynamic + static, open source)

**Repo: https://github.com/ossf/package-analysis**

Static signals in Go:
- `suspicious_identifiers.go` — hex identifiers (`_0x[a-f0-9]{3,}`), single-char vars
- `string_entropy.go` — Shannon entropy with false-positive filtering
- `base64.go` — Base64 detection with quality filters
- Line length distribution analysis

Dynamic: gVisor sandbox execution, syscall + network monitoring (similar to our install-guard).

### Tree-sitter Capabilities (what we can do TODAY)

| Capability | Possible? |
|---|---|
| Detect non-literal require arguments | **Yes** — AST node type check |
| Detect `String.fromCharCode` clustering | **Yes** — count occurrences in scope |
| Track variable from assignment to usage | **Partially** — custom walker, not queries |
| Cross-function dataflow | **No** — requires custom code |
| Cross-file analysis | **No** — one file at a time |

### The Detection Spectrum

```
Regex → AST Patterns → Dataflow/Taint → AI/ML

WE HAVE     WE HAVE        SEMGREP HAS     SOCKET HAS
(P001-P012) (P001, P008)   (open source)   (proprietary)

                  ↑
           WE BUILD HERE (this session)
```

## What We're Building

### Phase 1: AST Behavioral Heuristics (this session)

Five new detection rules using tree-sitter, plus fixes to existing rules:

**P013: Dynamic Require** (Critical, High confidence)
- AST: `require()` where argument is NOT a string literal
- Catches: `require(variable)`, `require(func())`, `require(arr[i])`
- This single rule would have caught the axios attack
- Almost never legitimate in production dependencies

**P014: String Deobfuscation Primitives** (High, Medium confidence)
- `String.fromCharCode()` combined with XOR (`^`) operators
- `charCodeAt` + bitwise operations (the encoding half)
- Dense `fromCharCode` calls (>3 in same function = deobfuscation routine)

**P015: Anti-Forensic File Operations** (Critical, High confidence)
- `unlinkSync`/`rmSync` targeting `__filename`, `setup.js`, `package.json`
- `renameSync` replacing package.json (the cleanup pattern)
- `copyFileSync` to system directories (`PROGRAMDATA`, `/Library/Caches`)

**P016: Dependency Install Scripts** (High, High confidence)
- Scan `node_modules/*/package.json` for postinstall/preinstall hooks
- Allowlist known-safe scripts (husky, node-gyp, prisma, esbuild)
- Not just root package.json — the actual attack vector

**P017: Obfuscation Indicators** (Medium, Medium confidence)
- Bracket notation API access: `module["require"]`, `global["eval"]`
- Hex-prefixed identifiers: `_0x[a-f0-9]{3,}`
- `while(!![])` / `while(!!{})` patterns (common in obfuscated code)
- Multiple `atob`/`Buffer.from("base64")` in same file without obvious purpose

**Existing fixes:**
- **AST gate**: Remove `content.contains("child_process")` requirement for P013
- **P002 enhancement**: Also flag `Buffer.from(x, "base64")` + `require()` in same FILE (not just same line)
- **P012 scope**: Extend to scan dependency `package.json` files, not just root

### Phase 2: Signal Combination Scoring (this session)

Instead of each rule firing independently, combine signals:

```
dynamic_require + entropy + deobfuscation = definitely_malicious (score: Critical)
install_script + network_access + obfuscation = highly_suspicious (score: High)
single_dynamic_require alone = suspicious (score: Medium)
```

A file-level "suspicion score" that escalates when multiple weak signals co-occur.

### Phase 3: Lightweight Taint Tracking (future)

Semgrep-inspired source → sink tracking within a single file:
- Sources: `Buffer.from(x, "base64")`, `atob()`, `String.fromCharCode()` chains
- Sinks: `require()`, `exec()`, `eval()`, `new Function()`
- Track: variable assignment chains within a function

### Phase 4: LLM-Enhanced Analysis (future)

Use existing `llm.rs` infrastructure to:
- Analyze files with multiple weak signals
- Ask "does this code look like malware obfuscation?"
- Provide human-readable explanation of why code is suspicious

## Key Decisions

1. **Tree-sitter first, not Semgrep integration** — we stay pure Rust, no external dependency on Semgrep CLI. GuardDog's rules inform our PATTERNS but we implement in tree-sitter.
2. **P013 (dynamic require) is the single highest-impact rule** — would have caught axios attack cold.
3. **Signal combination is essential** — individual weak signals are noisy, combined signals are definitive.
4. **Scan dep package.json files** — the install script vector is the #1 entry point for malware.
5. **AST gate must be broadened** — can't require literal dangerous module names when the whole point of obfuscation is hiding them.

## Open Questions

- Should P016 (dep install scripts) block by default or just warn?
- How aggressive should obfuscation detection be? (false positives on minified code)
- Should we add GuardDog as an optional backend? (`depsec scan --engine guarddog`)

## Why This Approach

- **Practical** — tree-sitter heuristics ship today, catch 90% of current attack patterns
- **Layered** — each phase adds depth without requiring the previous to change
- **Independent** — no dependency on Socket/Semgrep/GuardDog as runtime requirements
- **Informed** — rules directly derived from real malware analysis (axios, tinycolor, etc.)
