---
title: "feat: Narrative Rule Explanations in Scan Output"
type: feat
date: 2026-03-29
---

# Narrative Rule Explanations in Scan Output

## Overview

Replace the generic "Review or remove this dependency" suggestion with rule-specific narratives that explain **what was found**, **why it matters**, and **what to do about it**. Add a rule glossary at the end of scan output so users understand the DEPSEC codes.

## Problem Statement

Current output:
```
  ✗ detect-libc — 2 findings (DEPSEC-P001, confidence: high)
    Top: node_modules/detect-libc/lib/detect-libc.js:19, :31
    → Review or remove this dependency
```

Problems:
1. "DEPSEC-P001" means nothing to the user — what does it detect?
2. "Review or remove this dependency" is the same for every pattern finding — not actionable
3. No context about whether the finding is expected behavior (build tool) vs suspicious
4. User can't make informed decisions without understanding what the rule checks for

## Proposed Solution

Two changes:

### 1. Rule-Specific Suggestions (inline, per finding)

Replace the generic suggestion with rule-aware text:

```
  ✗ detect-libc — 2 findings (P001: Shell Execution, confidence: high)
    Top: node_modules/detect-libc/lib/detect-libc.js:19, :31
    → Calls child_process.exec() with variable arguments — verify commands are not user-controlled
```

Each rule gets:
- A **human name** shown alongside the code (e.g., "P001: Shell Execution")
- A **specific suggestion** explaining the risk and what to check

### 2. Rule Glossary (at the end of output)

After the scorecard, print a legend of all rules that triggered:

```
[Rule Guide]
  P001  Shell Execution — Package calls child_process.exec/spawn with variable
        arguments. If the command is user-controlled, this enables Remote Code
        Execution. Common in build tools (esbuild, detect-libc) — expected for
        dev dependencies, suspicious for runtime libraries.

  P008  Dynamic Code — Package uses new Function() to construct executable code
        at runtime. This is how template engines (ejs, pug) and code generators
        work. Verify that template inputs are properly escaped.

  P007  Encoded Payload — High-entropy string detected (likely base64 or encoded
        data). Often benign (compression tables, polyfill data), but encoded
        payloads are a common malware obfuscation technique.
```

Only rules that appear in the current scan are listed — not all 12 rules.

## Technical Approach

### Files to Modify

| File | Change |
|------|--------|
| `src/checks/patterns.rs` | Add `name` and `narrative` fields to `PatternRule` |
| `src/ast/javascript.rs` | Add narrative text to AST-generated `AstFinding`s |
| `src/output.rs` | Show rule name inline, render glossary at end |
| `src/checks/mod.rs` | (Optional) Add `rule_name` field to `Finding` |

### Rule Metadata

Extend `PatternRule` with narrative fields:

```rust
struct PatternRule {
    rule_id: &'static str,
    name: &'static str,           // NEW: "Shell Execution"
    description: &'static str,    // Existing: one-line description
    narrative: &'static str,      // NEW: multi-sentence explanation
    suggestion: &'static str,     // NEW: specific action to take
    pattern: &'static str,
    severity: Severity,
    confidence: Confidence,
}
```

### Rule Narratives (All 12 Rules)

```rust
// P001
name: "Shell Execution",
narrative: "Package calls child_process.exec/spawn with variable arguments. \
    If the command string includes user-controlled input, an attacker can \
    inject additional commands (Remote Code Execution). Common in build tools \
    (esbuild, node-gyp, detect-libc) where it's expected behavior.",
suggestion: "Verify commands are static or properly escaped — safe for build tools, \
    suspicious for runtime libraries",

// P002
name: "Encoded Execution",
narrative: "Decodes base64/atob data and passes it to eval, exec, or Function. \
    This is the #1 obfuscation pattern in npm malware — decode payload, execute it. \
    Legitimate uses are rare.",
suggestion: "Investigate immediately — this pattern is highly suspicious",

// P003
name: "Raw IP Network Call",
narrative: "Makes HTTP requests to a hardcoded IP address instead of a domain. \
    Malware uses raw IPs to avoid DNS-based blocking and monitoring. \
    Could also be a local development/testing URL.",
suggestion: "Check if the IP is a known service — raw IPs in production deps are suspicious",

// P004
name: "Credential Harvesting",
narrative: "Reads files from ~/.ssh, ~/.aws, ~/.env, or ~/.gnupg directories. \
    These contain credentials, private keys, and secrets. Legitimate packages \
    never need to read your SSH keys or AWS credentials.",
suggestion: "Remove this dependency immediately — no legitimate package reads your credentials",

// P005
name: "Steganographic Payload",
narrative: "Reads binary files (.wav, .mp3, .png, .jpg, .ico) and extracts bytes. \
    A known malware technique: hide executable payload in image/audio files \
    to evade text-based scanners.",
suggestion: "Investigate the binary file contents — this is a known malware obfuscation technique",

// P006
name: "Install Script Network Call",
narrative: "Postinstall or preinstall script makes network calls (curl, wget, fetch). \
    Install scripts run automatically during npm install with full system access. \
    Malware uses them to download and execute second-stage payloads.",
suggestion: "Review the install script — legitimate uses include downloading prebuilt binaries",

// P007
name: "Encoded Payload",
narrative: "String with high Shannon entropy (>4.5 bits/char) detected. \
    Could be base64-encoded data, encryption keys, or obfuscated code. \
    Also common in legitimate compression tables and polyfill data.",
suggestion: "Check if the string is a known data table or if it decodes to executable code",

// P008
name: "Dynamic Code Construction",
narrative: "Uses new Function() to create executable code from a string at runtime. \
    This is how template engines (ejs, pug, handlebars) compile templates. \
    Dangerous if the string includes user-controlled input (code injection).",
suggestion: "Expected for template engines — verify template inputs are properly escaped",

// P009
name: "Python Startup Injection",
narrative: "A .pth file containing executable code (subprocess, exec, eval, base64). \
    Python .pth files run automatically on every interpreter startup — \
    this is a powerful persistence mechanism for malware.",
suggestion: "Remove immediately — .pth files with executable code are almost always malicious",

// P010
name: "Cloud Credential Probing",
narrative: "Accesses the cloud instance metadata service (169.254.169.254 or 169.254.170.2). \
    IMDS provides IAM credentials, instance identity, and network configuration. \
    If your code runs in AWS/GCP/Azure, this could steal cloud credentials.",
suggestion: "Remove immediately unless this is a cloud SDK — IMDS access from dependencies is a red flag",

// P011
name: "Environment Exfiltration",
narrative: "Serializes process.env or os.environ to JSON. Environment variables often \
    contain API keys, database passwords, and secrets. Serializing them all \
    is a prerequisite for exfiltration.",
suggestion: "Check if the serialized env is sent over the network — legitimate logging should filter secrets",

// P012
name: "Suspicious Install Hook",
narrative: "package.json install script contains suspicious commands (curl, wget, eval, \
    exec, bash -c). Install hooks run with full system access during npm install. \
    Safe scripts (husky, patch-package, node-gyp) are excluded from this check.",
suggestion: "Review the script command — common in native module builds, suspicious otherwise",
```

### Glossary Rendering

In `src/output.rs`, after the ASCII scorecard:

```rust
fn render_rule_glossary(report: &ScanReport, use_color: bool) -> String {
    // Collect unique rule_ids from all findings
    let triggered_rules: HashSet<&str> = report.results.iter()
        .flat_map(|r| &r.findings)
        .map(|f| f.rule_id.as_str())
        .collect();

    if triggered_rules.is_empty() { return String::new(); }

    // Look up narratives for each triggered rule
    // Print formatted glossary
}
```

### Output Changes

**Inline (per package aggregate):**
```
Before: ✗ detect-libc — 2 findings (DEPSEC-P001, confidence: high)
         → Review or remove this dependency

After:  ✗ detect-libc — 2 findings (P001: Shell Execution, confidence: high)
         → Verify commands are static or properly escaped — safe for build tools
```

**End of output (after scorecard):**
```
[Rule Guide]
  P001  Shell Execution
        Calls child_process.exec/spawn with variable arguments. If user-controlled,
        enables Remote Code Execution. Common in build tools where it's expected.

  P008  Dynamic Code Construction
        Uses new Function() to create code from strings. Standard for template
        engines (ejs, pug). Dangerous if input is user-controlled.
```

## Acceptance Criteria

- [ ] Each pattern rule has a human name, narrative, and specific suggestion
- [ ] Rule name shown inline: `P001: Shell Execution` instead of just `DEPSEC-P001`
- [ ] Rule-specific suggestions replace "Review or remove this dependency"
- [ ] Rule glossary printed at end of human output (only triggered rules)
- [ ] Glossary only in human output — JSON/SARIF include raw rule_id
- [ ] AST-generated findings (P001, P008) also get narrative suggestions
- [ ] `--verbose` shows same narratives
- [ ] Existing tests pass + new test for glossary rendering

## Success Metrics

A user running `depsec scan .` for the first time can understand what each finding means and what to do about it without googling "DEPSEC-P001".

## References

- Current rule definitions: `src/checks/patterns.rs:15-80`
- Current output rendering: `src/output.rs:140-210`
- AST findings: `src/ast/javascript.rs`
- Similar approach: Semgrep rules include `message` + `metadata.references` per rule
- zizmor includes rule explanations in `--explain` flag
