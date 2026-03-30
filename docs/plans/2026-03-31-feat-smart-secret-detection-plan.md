---
title: "feat: Smart Secret Detection — Entropy + AST + Pre-Commit Hook"
type: feat
date: 2026-03-31
brainstorm: docs/brainstorms/2026-03-31-smart-secret-detection-brainstorm.md
---

# Smart Secret Detection

## Overview

Add a second detection layer that uses tree-sitter to find string literals assigned to suspicious variable names, applies Shannon entropy analysis, and integrates as a pre-commit hook. Catches secrets that regex patterns miss — like the hubstaff CLIENT_SECRET that triggered a bounty report.

## Problem Statement

Bounty hunter found `CLIENT_SECRET: &str = "1PHTn28JDE1H5_NTwbN7..."` in hubstaff-cli within hours of push. Both depsec and gitleaks missed it. Root cause: regex can only find patterns it knows about. The value had underscores/dashes the character class excluded, and Rust type annotations broke the assignment pattern.

The regex was fixed, but the fundamental problem remains: **what about secrets in variable names we haven't anticipated?**

## Research Findings

| Tool | Technique | Would it catch hubstaff? |
|------|-----------|-------------------------|
| TruffleHog | Keyword pre-filter + entropy + 882 API verifiers | Maybe (generic detector only) |
| detect-secrets (Yelp) | 18-keyword denylist + high entropy (4.5/3.0) + file-type-aware regex | Yes — keyword plugin matches "secret" |
| DeepSecrets (OWASP) | AST token stream + semantic variable name analysis + entropy 4.15 | Yes — flags variable name alone |
| Nosey Parker | Vectorscan + 87 rule files + generic "secret .{0,20} value" | Maybe (narrow character class) |
| GitHub | Regex + GPT-4 for generic passwords | Probably — LLM understands context |
| **depsec (proposed)** | **tree-sitter AST + keyword + tiered entropy + pre-commit** | **Yes — name + entropy** |

**Key insight from DeepSecrets:** Variable name alone is sufficient to flag — entropy is a confidence booster, not a gate. `CLIENT_SECRET = "hello"` should still be flagged (low confidence) because the variable NAME is suspicious.

## Technical Approach

### Phase 1: AST Secret Scanner (`src/secrets_ast.rs`)

Use tree-sitter to find string literal assignments with suspicious variable names.

**Suspicious name patterns** (stolen from detect-secrets + DeepSecrets):
```rust
const SUSPICIOUS_NAMES: &[&str] = &[
    "secret", "password", "passwd", "pwd", "token", "api_key",
    "apikey", "access_key", "auth", "credential", "private_key",
    "client_secret", "client_id", "bearer", "jwt",
];

const NAME_SHOWSTOPPERS: &[&str] = &[
    "public", "path", "mock", "fake", "dummy", "test", "example",
    "sample", "placeholder", "template", "todo", "fixme",
];
```

**tree-sitter queries for each language:**

JS/TS:
```scheme
;; const/let/var NAME = "value"
(variable_declarator
  name: (identifier) @name
  value: [(string (string_fragment) @value) (template_string) @value])
```

Rust:
```scheme
;; const NAME: type = "value"
(const_item
  name: (identifier) @name
  value: (string_literal (string_content) @value))
```

Python:
```scheme
;; NAME = "value"
(assignment
  left: (identifier) @name
  right: (string (string_content) @value))
```

**Detection logic:**
```
for each string assignment (name, value):
  1. name matches SUSPICIOUS_NAMES? → name_signal = true
  2. name matches NAME_SHOWSTOPPERS? → skip
  3. value starts with ${, {, <, % ? → skip (template reference)
  4. value looks like a function call? → skip (indirect reference)
  5. Calculate Shannon entropy of value

  if name_signal AND entropy >= 3.5 AND len >= 16:
    → HIGH confidence secret (like hubstaff case)
  elif name_signal AND len >= 8:
    → MEDIUM confidence (suspicious name, any value)
  elif entropy >= 4.5 AND len >= 30:
    → LOW confidence (high entropy, no name signal)
```

### Phase 2: Integrate with SecretsCheck

In `src/checks/secrets.rs`, after running regex patterns, also run AST analysis:

```rust
// Existing: regex patterns (S001-S020)
let regex_findings = scan_with_regex(...);

// New: AST-based detection
let ast_findings = secrets_ast::scan_for_secrets(root, &files);

// Merge, deduplicate (prefer AST finding if same location)
let all_findings = merge_findings(regex_findings, ast_findings);
```

AST findings get new rule IDs: `DEPSEC-S021` (name + entropy), `DEPSEC-S022` (name only), `DEPSEC-S023` (entropy only).

### Phase 3: Pre-Commit Hook

New command: `depsec hook install`

```bash
$ depsec hook install
Installed pre-commit hook at .git/hooks/pre-commit
Secrets will be checked on every commit.
```

Creates `.git/hooks/pre-commit`:
```bash
#!/bin/sh
# depsec pre-commit hook — blocks commits with secrets
exec depsec secrets-check --staged
```

New command: `depsec secrets-check --staged`

```
1. git diff --cached --name-only → list of staged files
2. For each file: run regex + AST secret detection
3. If secrets found → print report, exit 1 (blocks commit)
4. If clean → exit 0 (commit proceeds)
```

**Output on blocked commit:**
```
depsec: 2 potential secrets detected in staged files

  ✗ src/auth.rs:9 — CLIENT_SECRET (high confidence)
    "1PHTn28JDE1H5_NTwbN7..." (84 chars, 4.8 bits/char entropy)
    → Move to environment variable: std::env::var("CLIENT_SECRET")

  ⚠ src/auth.rs:8 — CLIENT_ID (medium confidence)
    "RSMvSFhq3H1aYUn_MJ-g..." (43 chars, 4.2 bits/char entropy)
    → Move to environment variable or config file

Commit blocked. To proceed anyway: git commit --no-verify
To allowlist: echo "src/auth.rs:9" >> .depsec/secrets.allow
```

### Phase 4: Allowlisting

File: `.depsec/secrets.allow`
```
# Known test fixtures
tests/fixtures/fake_credentials.rs
# Specific lines
src/config.rs:42
# Fingerprint-based (content hash)
sha256:abc123...
```

## Acceptance Criteria

- [ ] AST scanner finds string literals assigned to suspicious variable names
- [ ] Shannon entropy calculated for each candidate
- [ ] Tiered thresholds: name + high entropy = HIGH, name only = MEDIUM, entropy only = LOW
- [ ] Works for JS/TS, Rust, Python (tree-sitter grammars already available)
- [ ] `depsec hook install` creates pre-commit hook
- [ ] `depsec secrets-check --staged` scans only staged files
- [ ] Blocked commit shows clear message with remediation
- [ ] `.depsec/secrets.allow` for false positive management
- [ ] Would have caught the hubstaff CLIENT_SECRET bounty case
- [ ] All existing 148 tests pass + new TDD tests

## Files to Create/Modify

| File | Change |
|------|--------|
| `src/secrets_ast.rs` | **NEW** — AST-based secret detection |
| `src/checks/secrets.rs` | Integrate AST findings with regex findings |
| `src/main.rs` | Add `hook install/uninstall` and `secrets-check` commands |
| `src/config.rs` | Add `[secrets]` config section for thresholds |

## References

- Brainstorm: `docs/brainstorms/2026-03-31-smart-secret-detection-brainstorm.md`
- DeepSecrets (OWASP): semantic variable name analysis — our primary inspiration
- detect-secrets (Yelp): 18-keyword denylist, file-type-aware regex
- TruffleHog: entropy thresholds 3.0-4.25 per detector
- Bounty report: hubstaff-cli CLIENT_SECRET exposed in public repo
