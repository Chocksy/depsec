# Layer 3: Deep Audit — Detailed Design

**Date:** 2026-03-28
**Status:** Draft
**Goal:** Full source code analysis of individual packages for novel vulnerabilities — zero-day hunting territory.
**Prerequisites:** Layer 1 (smart filtering) + Layer 2 (LLM triage)

---

## Overview

Layer 3 adds `depsec audit <package>` — a deep, LLM-powered analysis of a specific dependency's source code. Unlike Layer 2 (which triages existing findings), Layer 3 actively searches for vulnerabilities that no scanner has found before.

This is inspired by:
- **Anthropic's zero-day research** (500+ zero-days with Claude Opus 4.6)
- **VulnHuntr** (call-chain tracing from entry points, found real CVEs)
- **Google Big Sleep** (variant analysis from known patches)
- **Sean Heelan's methodology** (focused context construction, anti-hallucination)

---

## 1. Command Design

```bash
# Audit a specific package
depsec audit posthog-js

# Audit with specific focus areas
depsec audit shelljs --focus rce,injection

# Audit a Rust crate (from Cargo.lock)
depsec audit serde_yaml --ecosystem cargo

# Audit with verbose reasoning output
depsec audit execa --verbose

# Dry run — show what would be analyzed
depsec audit posthog-js --dry-run
```

### Why Per-Package, Not Whole Project?

1. **Token economics** — analyzing a full `node_modules/` would cost hundreds of dollars and take hours
2. **Quality** — focused analysis on one package with full context beats shallow analysis of everything
3. **Actionability** — if you find something in `posthog-js`, you know exactly what to do (report upstream, pin version, find alternative)
4. **The VulnHuntr lesson** — iterative call-chain tracing from entry points is the highest-signal approach. This only works package-by-package.

---

## 2. Architecture

```
depsec audit <package>

┌──────────────────────────────────────────────────────┐
│ Phase 1: Reconnaissance                              │
│                                                      │
│ 1. Locate package in node_modules/vendor/.venv/      │
│ 2. Parse package metadata (package.json, Cargo.toml) │
│ 3. Build file tree of the package                    │
│ 4. Identify entry points (exports, public API)       │
│ 5. Profile capabilities (network? fs? exec? env?)    │
│                                                      │
│ Output: Package profile + entry point list           │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ Phase 2: Capability Analysis (No LLM)                │
│                                                      │
│ 1. tree-sitter scan for dangerous API usage:         │
│    - child_process / subprocess / os.system           │
│    - fetch / http / net / dns                         │
│    - fs / readFile / writeFile / open                 │
│    - eval / exec / Function / vm                      │
│    - process.env / os.environ                         │
│    - crypto / buffer / base64                         │
│ 2. Map each capability to its location in the code    │
│ 3. Determine which entry points lead to each          │
│    capability (forward call graph)                    │
│                                                      │
│ Output: Capability map with call paths               │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ Phase 3: LLM Deep Analysis                           │
│                                                      │
│ For each dangerous capability path:                  │
│ 1. Extract the call chain from entry point to sink   │
│ 2. Send to LLM with vulnerability-specific prompts   │
│ 3. LLM reasons about exploitability:                 │
│    - Can external input reach this sink?             │
│    - Is input validated/sanitized along the path?    │
│    - What's the impact if exploited?                 │
│ 4. LLM generates PoC if it believes vuln is real     │
│                                                      │
│ Output: Vulnerability candidates with PoCs           │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ Phase 4: Self-Verification                           │
│                                                      │
│ 1. Send each candidate back to LLM with directive:   │
│    "Argue AGAINST this being a real vulnerability"    │
│ 2. LLM attempts to debunk its own finding            │
│ 3. If debunking succeeds → discard                   │
│ 4. If debunking fails → high-confidence finding      │
│                                                      │
│ Output: Verified findings with confidence scores     │
└──────────────────────────────────────────────────────┘
```

---

## 3. Phase 1: Reconnaissance (Pure Rust, No LLM)

### 3.1 Package Location

```rust
fn locate_package(name: &str, root: &Path) -> Option<PackageLocation> {
    // npm/yarn/pnpm
    let npm_path = root.join("node_modules").join(name);
    if npm_path.exists() { return Some(PackageLocation::Npm(npm_path)); }

    // Scoped npm packages
    if name.starts_with('@') {
        let parts: Vec<&str> = name.splitn(2, '/').collect();
        let scoped = root.join("node_modules").join(parts[0]).join(parts[1]);
        if scoped.exists() { return Some(PackageLocation::Npm(scoped)); }
    }

    // Cargo (extract from Cargo.lock, find in registry cache)
    // Ruby (vendor/bundle)
    // Python (.venv/lib/pythonX.Y/site-packages)
    // ...
}
```

### 3.2 Package Profile

```rust
struct PackageProfile {
    name: String,
    version: String,
    ecosystem: Ecosystem,       // Npm, Cargo, Gem, PyPI, Go
    path: PathBuf,
    entry_points: Vec<EntryPoint>,
    file_tree: Vec<PathBuf>,    // All source files
    total_lines: usize,
    total_files: usize,
    has_native_code: bool,      // .c, .cc, .cpp, .rs with unsafe
    has_install_scripts: bool,  // postinstall, build.rs, setup.py
    description: Option<String>,
    dependencies: Vec<String>,
    known_cves: Vec<String>,    // From OSV (already have this data)
}
```

### 3.3 Entry Point Detection

**npm packages:**
- `main` field in package.json → primary entry
- `exports` field → all exported paths
- `bin` field → CLI entry points
- Files in root matching `index.{js,ts,mjs}`

**Cargo crates:**
- `src/lib.rs` → library entry
- `src/main.rs` → binary entry
- `pub fn` / `pub struct` declarations → public API surface

**Python packages:**
- `__init__.py` → package entry
- Files listed in `setup.py` / `pyproject.toml`
- `__all__` exports

---

## 4. Phase 2: Capability Analysis (tree-sitter, No LLM)

### 4.1 Capability Detection

Using tree-sitter queries, scan the package for API usage that indicates capabilities:

```rust
enum Capability {
    ShellExecution,      // child_process, subprocess, os.system, Command::new
    NetworkAccess,       // fetch, http, net, reqwest, urllib
    FileSystemAccess,    // fs, readFile, writeFile, open, std::fs
    DynamicExecution,    // eval, exec, Function, vm.runInContext
    EnvironmentAccess,   // process.env, os.environ, std::env
    CryptoOperations,    // crypto, base64, buffer manipulation
    ProcessControl,      // process.exit, os.kill, signal handling
    NativeCode,          // ffi, napi, cffi, ctypes, unsafe blocks
}

struct CapabilityInstance {
    capability: Capability,
    file: PathBuf,
    line: usize,
    code_snippet: String,
    containing_function: Option<String>,
}
```

### 4.2 Capability Expectation Matching (stolen from Socket.dev + GuardDog)

Compare detected capabilities against what the package *should* need:

```rust
struct CapabilityExpectation {
    // Based on package category/description
    expected: HashSet<Capability>,
    // Actually detected
    detected: HashSet<Capability>,
}

// Example:
// Package: "date-fns" (date formatting library)
// Expected: none (pure computation)
// Detected: NetworkAccess at lib/helpers.js:42
// → SUSPICIOUS: why does a date library need network access?
```

**Heuristic rules for expectations:**
- Package description contains "http", "fetch", "api", "client" → expect NetworkAccess
- Package has `postinstall` script → expect ShellExecution (but flag anyway)
- Package is in `devDependencies` → more tolerant (build tools legitimately exec)
- Package has no description → no expectations (flag everything)

### 4.3 Forward Call Graph

Build a lightweight call graph from entry points to capability sinks:

```
entry_point: module.exports.transform()
  → calls: processInput() at lib/process.js:10
    → calls: validateConfig() at lib/config.js:5
      → calls: child_process.exec(cmd) at lib/config.js:12  ← SINK
```

This is the call chain that gets sent to the LLM in Phase 3.

**Implementation:** tree-sitter for function call extraction + simple name-based resolution (not full type inference — that's overkill for security scanning).

---

## 5. Phase 3: LLM Deep Analysis

### 5.1 Analysis Modes

```bash
depsec audit shelljs                     # Default: all CWE categories
depsec audit shelljs --focus rce         # Focus on Remote Code Execution
depsec audit shelljs --focus injection   # Focus on injection vulnerabilities
depsec audit shelljs --focus ssrf        # Focus on Server-Side Request Forgery
```

**CWE categories to check:**

| Category | CWEs | Focus Flag | Relevant Capabilities |
|----------|------|------------|----------------------|
| Remote Code Execution | CWE-78, CWE-94, CWE-95 | `rce` | ShellExecution, DynamicExecution |
| Injection | CWE-89, CWE-79, CWE-77 | `injection` | ShellExecution, DynamicExecution |
| Path Traversal | CWE-22, CWE-23 | `path` | FileSystemAccess |
| SSRF | CWE-918 | `ssrf` | NetworkAccess |
| Information Disclosure | CWE-200, CWE-209 | `infoleak` | EnvironmentAccess, NetworkAccess |
| Deserialization | CWE-502 | `deser` | DynamicExecution |
| Prototype Pollution | CWE-1321 | `prototype` | (JS-specific) |

### 5.2 VulnHuntr-Style Iterative Analysis

**Don't dump the whole package into the LLM.** Instead, use iterative call-chain tracing:

```
Round 1: Send entry point code + capability map
LLM: "I need to see the implementation of processInput() at lib/process.js"

Round 2: Send processInput() implementation
LLM: "I need to see validateConfig() and how cmd is constructed"

Round 3: Send validateConfig() implementation
LLM: "I can now trace the full path. The cmd variable at line 12 includes
      user-supplied input from the config parameter without sanitization.
      This is CWE-78: OS Command Injection."

Round 4: LLM generates PoC
```

**Implementation:**

```rust
struct AuditConversation {
    model: String,
    messages: Vec<Message>,
    max_rounds: usize,       // Default: 5 (prevent infinite loops)
    current_round: usize,
    resolved_files: HashSet<PathBuf>,  // Don't re-send files
}

enum LlmAction {
    RequestFile { path: String, function: Option<String> },
    RequestCallGraph { function: String },
    ReportFinding { finding: AuditFinding },
    NoIssueFound,
}
```

### 5.3 Vulnerability-Specific Prompts

Stolen from VulnHuntr's approach — each CWE category gets a targeted prompt:

**RCE Prompt:**
```
Analyze this call chain for Remote Code Execution (CWE-78, CWE-94, CWE-95).

Focus on:
1. Does external/user input reach a shell execution sink (exec, spawn, system)?
2. Is the input sanitized or escaped before reaching the sink?
3. Can an attacker control the command or its arguments?
4. Are there any bypasses for existing sanitization?

If you find a vulnerability:
- Explain the exact data flow from input to sink
- Provide a concrete proof-of-concept input that would trigger execution
- Rate confidence 0-10 (only report if >= 7)
```

**SSRF Prompt:**
```
Analyze this call chain for Server-Side Request Forgery (CWE-918).

Focus on:
1. Does external input influence a URL or hostname used in HTTP requests?
2. Is there URL validation? Can it be bypassed (DNS rebinding, URL parsing differences)?
3. Can an attacker reach internal services (169.254.169.254, localhost, internal DNS)?
4. Are there any redirect-following behaviors that could be abused?

If you find a vulnerability:
- Explain how an attacker could craft input to reach internal services
- Provide a concrete PoC URL
- Rate confidence 0-10
```

### 5.4 Context Budget

**Problem:** Large packages can't fit in a single context window.
**Solution:** Only send what's relevant — use the call graph to scope context.

| Package Size | Approach |
|-------------|----------|
| < 5k lines | Send full package + iterative questioning |
| 5k - 50k lines | Send entry points + capability map + iterative file requests |
| > 50k lines | Send capability map + only files along dangerous call paths |

**Token budget per audit:** ~100k tokens (input + output across all rounds)
**Estimated cost:** $0.50-$5.00 per package audit (Claude Sonnet)

---

## 6. Phase 4: Self-Verification (stolen from Anthropic)

### 6.1 The Adversarial Pass

For each finding from Phase 3, run a second LLM pass with a different directive:

```
You are a senior security researcher reviewing a junior analyst's finding.
Your job is to find reasons this is NOT a real vulnerability.

The analyst claims:
{finding_description}

Proof-of-concept:
{poc}

Your task:
1. Identify any reasons the PoC would NOT work in practice
2. Check if there are hidden sanitization or validation steps
3. Consider if the "user input" is actually controlled by the application, not the user
4. Look for framework-level protections that would prevent exploitation
5. Consider if the vulnerability requires unrealistic preconditions

If you can debunk the finding, explain why it's a false positive.
If you cannot debunk it, explain why the finding is likely real.

Respond with:
- verdict: "DEBUNKED" or "CONFIRMED"
- reasoning: your analysis
- debunk_evidence: (if debunked) what the analyst missed
- confirmation_evidence: (if confirmed) why the PoC is realistic
```

### 6.2 Confidence Scoring

```
Phase 3 confidence × Phase 4 result = Final confidence

Phase 3: 8/10 + Phase 4: CONFIRMED → Final: HIGH (report)
Phase 3: 7/10 + Phase 4: DEBUNKED → Final: DISCARD
Phase 3: 9/10 + Phase 4: DEBUNKED → Final: MEDIUM (report with caveat)
Phase 3: 6/10 + Phase 4: CONFIRMED → Final: MEDIUM (report with caveat)
```

---

## 7. Variant Analysis (stolen from Google Big Sleep)

### 7.1 When a Package Has Known CVEs

If the package has known CVEs (from Layer 1's OSV check), use them as seeds for variant analysis:

```
Package: tar@6.2.1 has known CVE: GHSA-34x7-hfp2-rc4v (path traversal)

Step 1: Fetch the CVE details (advisory URL from OSV)
Step 2: Send to LLM: "This package had a path traversal vulnerability.
        Are there similar unpatched patterns elsewhere in the codebase?"
Step 3: LLM searches for variant patterns
```

This is the highest-yield technique — known bugs are the best guide to unknown bugs. Google Big Sleep's first real zero-day was found this way (variant of a prior SQLite bug).

### 7.2 Implementation

```rust
async fn variant_analysis(
    package: &PackageProfile,
    known_cves: &[CveInfo],
    client: &OpenRouterClient,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    for cve in known_cves {
        let advisory = fetch_advisory_details(&cve.advisory_url).await;

        let prompt = format!(
            "This package ({} v{}) has a known vulnerability:\n\
             CVE: {}\nType: {}\nDescription: {}\n\n\
             Search the package source code for similar patterns \
             that might be vulnerable to the same class of attack.\n\
             Focus on code that handles the same type of input \
             or uses similar unsafe patterns.",
            package.name, package.version,
            cve.id, cve.cwe_type, advisory.description
        );

        // Run iterative analysis focused on variant patterns
        let variant_findings = iterative_audit(
            package, &prompt, client, AuditFocus::Variant
        ).await;

        findings.extend(variant_findings);
    }

    findings
}
```

---

## 8. Output Format

### 8.1 Terminal Output

```
depsec audit shelljs

Auditing shelljs@0.8.5...

[Reconnaissance]
  Package: shelljs 0.8.5 (npm)
  Files: 23 source files, 4,821 lines
  Entry points: 3 (index.js, shell.js, make.js)
  Known CVEs: 0

[Capabilities Detected]
  ✗ Shell Execution — 12 locations
    exec.js:45, exec.js:78, shell.js:112, ...
  ✗ File System Access — 8 locations
    shell.js:23, cp.js:15, ...
  ⚠ Environment Access — 3 locations
    shell.js:5, config.js:2, ...
  ✓ No network access detected
  ✓ No dynamic code execution (eval/Function)

[Deep Analysis — 4 rounds of LLM analysis]
  Round 1: Analyzing entry points and capability map...
  Round 2: Following exec() call chain in exec.js...
  Round 3: Analyzing input flow from shell.exec() to child_process...
  Round 4: Generating PoC and verifying...

[Findings]
  ⚠ MEDIUM (confidence: 0.73, verified):
    CWE-78: Potential OS Command Injection
    File: src/exec.js:45
    Path: shell.exec(cmd) → exec(cmd) → child_process.exec(cmd)
    Issue: The `cmd` parameter is passed to child_process.exec() without
           shell metacharacter escaping. If cmd contains user input,
           an attacker could inject additional commands via ; or &&.
    PoC: shell.exec("ls; cat /etc/passwd")
    Mitigation: Use child_process.execFile() instead of exec() to avoid
                shell interpretation, or escape shell metacharacters.

  ✓ Verified by adversarial analysis (self-verification passed)

[Summary]
  1 finding (0 critical, 1 medium, 0 low)
  Analysis cost: ~$0.82 (4 rounds, Claude Sonnet)
  Total tokens: ~45k input, ~8k output
```

### 8.2 JSON Output

```bash
depsec audit shelljs --format json
```

```json
{
    "package": "shelljs",
    "version": "0.8.5",
    "ecosystem": "npm",
    "audit_metadata": {
        "model": "anthropic/claude-sonnet-4-6",
        "rounds": 4,
        "total_tokens": 53000,
        "estimated_cost": 0.82,
        "timestamp": "2026-03-28T14:30:00Z"
    },
    "capabilities": {
        "shell_execution": { "count": 12, "locations": ["exec.js:45", "..."] },
        "file_system_access": { "count": 8, "locations": ["shell.js:23", "..."] },
        "environment_access": { "count": 3, "locations": ["shell.js:5", "..."] }
    },
    "findings": [
        {
            "id": "AUDIT-001",
            "cwe": "CWE-78",
            "severity": "MEDIUM",
            "confidence": 0.73,
            "verified": true,
            "file": "src/exec.js",
            "line": 45,
            "title": "Potential OS Command Injection",
            "description": "...",
            "call_chain": ["shell.exec(cmd)", "exec(cmd)", "child_process.exec(cmd)"],
            "poc": "shell.exec(\"ls; cat /etc/passwd\")",
            "mitigation": "Use child_process.execFile() instead of exec()",
            "analysis_reasoning": "..."
        }
    ],
    "variant_analysis": {
        "known_cves_checked": 0,
        "variants_found": 0
    }
}
```

### 8.3 SARIF Output

```bash
depsec audit shelljs --format sarif
```

Extends the existing SARIF output in `src/sarif.rs` with audit-specific fields.

---

## 9. Responsible Disclosure

### 9.1 When a Real Vulnerability Is Found

If the audit finds a high-confidence vulnerability:

```
⚠ HIGH CONFIDENCE FINDING — Potential zero-day vulnerability detected.

Before disclosing publicly:
1. Report to the package maintainer via their security policy
2. Allow 90 days for a fix before public disclosure
3. Do NOT include this finding in public CI/CD output

Generate responsible disclosure report? [y/N]
```

If the user says yes, generate a disclosure template:

```markdown
# Security Vulnerability Report

**Package:** shelljs 0.8.5
**Vulnerability:** OS Command Injection (CWE-78)
**Severity:** Medium
**Found by:** depsec audit (LLM-assisted analysis)
**Date:** 2026-03-28

## Description
[Auto-generated from the finding]

## Proof of Concept
[Auto-generated PoC]

## Suggested Fix
[Auto-generated mitigation]

## Timeline
- 2026-03-28: Vulnerability discovered
- 2026-03-28: Report sent to maintainer
- [90-day deadline]: Public disclosure if no fix
```

---

## 10. Cost Management

### 10.1 Estimated Costs Per Audit

| Package Size | Rounds | Tokens | Cost (Sonnet) | Cost (Opus) |
|-------------|--------|--------|---------------|-------------|
| Small (<1k lines) | 2-3 | ~20k | ~$0.20 | ~$1.00 |
| Medium (1-10k lines) | 3-5 | ~50k | ~$0.50 | ~$2.50 |
| Large (10-50k lines) | 5-8 | ~100k | ~$1.00 | ~$5.00 |
| Very large (>50k lines) | 8-12 | ~200k | ~$2.00 | ~$10.00 |

### 10.2 Budget Controls

```toml
[audit]
max_budget = 5.00           # Stop if cost exceeds $5
max_rounds = 8              # Maximum LLM conversation rounds
model = "anthropic/claude-sonnet-4-6"  # Default model
```

```bash
depsec audit posthog-js --budget 2.00  # Override max budget
depsec audit posthog-js --model anthropic/claude-opus-4-6  # Use Opus for highest quality
```

---

## 11. Implementation Order

1. **Package location + profile** — find packages on disk, parse metadata
2. **Capability detection** — tree-sitter queries for dangerous API usage (reuse Layer 1's AST engine)
3. **Forward call graph** — lightweight name-based call resolution
4. **LLM integration** — reuse Layer 2's OpenRouter client
5. **Iterative analysis loop** — multi-round conversation with file requests
6. **Vulnerability-specific prompts** — per-CWE prompt templates
7. **Self-verification** — adversarial pass
8. **Variant analysis** — CVE-seeded pattern search
9. **Output formats** — terminal, JSON, SARIF
10. **Responsible disclosure** — report generation
11. **Cost tracking** — per-round token counting and budget enforcement

---

## 12. colgrep Integration (Optional Enhancement)

**colgrep** (`colgrep` v1.0.8) is a semantic code search tool that uses ColBERT embeddings to find code by meaning, not just text. It supports 18+ languages and is already installed on the development machine.

### How colgrep Complements tree-sitter

| | tree-sitter | colgrep |
|---|---|---|
| **Question** | "Is this .exec() on child_process?" (structural) | "Find functions that handle user input" (semantic) |
| **Strength** | Precise structural matching | Discovery of relevant code by meaning |
| **Speed** | Instant (compiled) | Fast after indexing |
| **Integration** | Compiled into depsec binary | External runtime tool (not bundled) |

### Use in Layer 3 Audit

During Phase 1 (Reconnaissance), if colgrep is available on the system:

```bash
# Find entry points that handle external input
colgrep "functions that accept user input or HTTP request data" node_modules/shelljs/ --json

# Find error handling patterns
colgrep "error handling and exception catching" node_modules/shelljs/ --json

# Find authentication or authorization logic
colgrep "authentication verification or token validation" node_modules/shelljs/ --json
```

This provides an additional discovery channel beyond tree-sitter's structural queries. It's particularly useful for large packages where you don't know what to look for yet.

### Implementation

```rust
fn try_colgrep_discovery(package_path: &Path, queries: &[&str]) -> Option<Vec<ColGrepResult>> {
    // Check if colgrep is available
    let status = Command::new("colgrep").arg("--version").status().ok()?;
    if !status.success() { return None; }

    let mut results = Vec::new();
    for query in queries {
        let output = Command::new("colgrep")
            .arg(query)
            .arg(package_path)
            .arg("--json")
            .arg("-k").arg("5")  // Top 5 results
            .output()
            .ok()?;

        if let Ok(parsed) = serde_json::from_slice::<Vec<ColGrepResult>>(&output.stdout) {
            results.extend(parsed);
        }
    }
    Some(results)
}
```

**Key principle:** colgrep is a nice-to-have enhancement, never a requirement. Layer 3 works without it — tree-sitter capability analysis + LLM iterative questioning are the core loop.

---

## 13. Future Ideas (Not in Scope Now)

- **Fuzz harness generation** — for Rust crates with `unsafe` blocks, generate cargo-fuzz harnesses (Google's oss-fuzz-gen approach)
- **Multi-package audit** — audit all packages with specific capabilities (e.g., "audit all packages that use child_process")
- **CI integration** — `depsec audit --ci` runs on new dependencies added in a PR
- **Community findings database** — share anonymized audit results to build collective intelligence
- **Sandboxed execution** — actually run PoCs in a container to verify exploitability
