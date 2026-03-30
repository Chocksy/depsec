# Brainstorm: Smart Secret Detection — Beyond Regex

**Date:** 2026-03-31
**Status:** Draft
**Trigger:** Bounty hunter found hardcoded CLIENT_SECRET in hubstaff-cli that both depsec AND gitleaks missed.

---

## The Problem

A bounty hunter's automated tool found `CLIENT_SECRET: &str = "1PHTn28JDE..."` in a public repo within hours of it being pushed. Neither depsec nor gitleaks caught it because:

1. **Regex gap:** S011 pattern expected `CLIENT_SECRET = "value"` but Rust has `CLIENT_SECRET: &str = "value"` (type annotation)
2. **Character class gap:** Pattern only matched `[A-Za-z0-9]` but the secret contained `_` and `-`
3. **Fundamental limitation:** Regex can only find secrets it's been told to look for

The regex bug was fixed (now handles type annotations and extended chars), but the deeper problem remains: **what about secrets that don't match ANY named pattern?**

---

## What We're Building

**Entropy + AST secret detection** — a second layer on top of regex that catches secrets by their statistical properties, not their format.

### How It Works

Use tree-sitter to parse source files and find:
1. **All string literal assignments** — `const X = "value"`, `let x: &str = "value"`, etc.
2. **Check variable name** — does it contain `token`, `key`, `secret`, `password`, `credential`, `auth`, `api`, `jwt`, `bearer`?
3. **Calculate Shannon entropy** of the string value
4. **Apply tiered thresholds:**

| Variable Name Signal | Entropy Threshold | Min Length | Example |
|---------------------|-------------------|-----------|---------|
| Strong (secret, password, key, token) | 3.5 bits/char | 16 chars | `CLIENT_SECRET = "abc123..."` |
| Medium (auth, api, credential) | 4.0 bits/char | 20 chars | `AUTH_CODE = "xyz789..."` |
| None (generic variable) | 4.5 bits/char | 30 chars | `data = "A3kF9x..."` |

**Why this catches the hubstaff case:**
- Variable: `CLIENT_SECRET` → strong name signal (threshold: 3.5)
- Value: 84 chars, ~4.8 bits/char entropy → way above threshold
- Result: **FLAGGED** regardless of regex patterns

### Pre-Commit Hook Integration

```bash
# Install (one-time):
depsec hook install

# Adds to .git/hooks/pre-commit:
#!/bin/sh
depsec secrets-check --staged
```

On every `git commit`:
1. Get staged files (`git diff --cached --name-only`)
2. For each file: parse with tree-sitter, find string literals
3. Check variable names + entropy
4. Also run existing regex patterns
5. If secrets found → block commit with clear message

**Output on blocked commit:**
```
depsec: potential secrets detected in staged files

  src/auth.rs:8 — CLIENT_ID assigned high-entropy string (4.2 bits/char, 43 chars)
    const CLIENT_ID: &str = "RSMv...l6g"
    → Move to environment variable or secrets manager

  src/auth.rs:9 — CLIENT_SECRET assigned high-entropy string (4.8 bits/char, 84 chars)
    const CLIENT_SECRET: &str = "1PHT...omw"
    → Move to environment variable or secrets manager

To proceed anyway: git commit --no-verify
To allowlist: add fingerprint to .depsec/secrets.allow
```

---

## Why This Approach

1. **Catches what regex misses** — the hubstaff case would be caught by entropy alone, regardless of format
2. **No ML dependencies** — pure statistics + AST. Deterministic, fast, auditable
3. **No network calls** — unlike verification-based tools, works offline
4. **Builds on existing infrastructure** — tree-sitter already integrated, entropy calc exists in P007
5. **Pre-commit hook prevents exposure** — catches secrets before they reach GitHub, preventing bounty reports

---

## Key Decisions

1. **Entropy + AST, no ML** — deterministic, no dependencies, builds on tree-sitter
2. **Tiered thresholds by variable name** — lower bar for suspicious names, higher for generic
3. **Pre-commit hook** — catches secrets before `git commit`, not after push
4. **Language-aware parsing** — tree-sitter handles Rust type annotations, TypeScript types, Go var declarations
5. **Allowlisting** — `.depsec/secrets.allow` for known false positives (test fixtures, example values)
6. **Scan staged files only** — fast (milliseconds), not full repo scan

---

## Comparison with Other Tools

| Tool | Regex | Entropy | AST-aware | Verification | Pre-commit |
|------|-------|---------|-----------|--------------|------------|
| gitleaks | Yes | No | No | No | Yes |
| TruffleHog | Yes | Yes | No | Yes (800 APIs) | Yes |
| detect-secrets (Yelp) | Yes | Yes (plugin) | No | No | Yes |
| Nosey Parker | Yes | Limited | No | No | No |
| **depsec (proposed)** | **Yes** | **Yes + tiered** | **Yes (tree-sitter)** | **No** | **Yes** |

**Our unique advantage:** AST-aware entropy. No other tool uses tree-sitter to understand variable names in context. They all regex the raw text, which means they miss type annotations and language-specific syntax.

---

## Open Questions

1. **Should we also scan git history?** TruffleHog and gitleaks can scan all commits. We could add `depsec secrets-scan --history` for full repo audit.
2. **False positive management** — how to make allowlisting easy? `.depsec/secrets.allow` with fingerprints? Or inline `// depsec:allow` comments?
3. **Binary files** — should we check compiled binaries for embedded strings? (The bounty report mentioned "extractable from compiled binary")
4. **CI integration** — should `depsec scan` fail CI if secrets are found, or is that separate from the pre-commit hook?
