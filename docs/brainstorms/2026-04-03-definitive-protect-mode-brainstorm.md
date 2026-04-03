---
date: 2026-04-03
topic: definitive-protect-mode
---

# Sprint 5: Definitive Protect Mode

## What We're Building

Transform both `depsec scan` and `depsec protect` from noisy warning generators
into definitive decision-makers. The primary path uses LLM (via OpenRouter) to
deliver binary verdicts: ✓ clean or ✗ BLOCKED with a specific reason. Static-only
mode (no API key) serves as a fallback using aggressive confidence filtering.

## Why This Approach

**The problem:**
- POS scan: 3,254 findings → nobody reads this
- CEMS scan: 1,355 findings → noise
- A vibe coder running `npm install` needs a seatbelt, not a security audit

**The Socket.dev model:**
Socket.dev sends new/suspicious packages to an LLM and gets definitive verdicts
in <6 minutes. We do the same but as a local tool — the static checks (86.5%
detection rate) are the funnel, the LLM is the judge.

**No package allowlists:**
Any major package can be compromised (event-stream, ua-parser-js, colors.js).
Trust is earned by behavior analysis, not by name/popularity. The existing
CAPABILITY_ALLOWLIST in capabilities.rs should be REMOVED.

## Key Decisions

### 1. LLM is the primary path, not a luxury add-on
- The default experience assumes an OpenRouter API key is configured
- Static-only mode is the fallback for users without an API key
- depsec should prompt users to set up their API key on first run

### 2. Unified philosophy for scan and protect
Both modes follow the same pipeline:
```
Static scan (fast, 100ms)
  → Confidence filter (Critical/High severity + High confidence)
  → LLM triage (send top N suspects with code context)
  → Definitive verdict: clean or blocked
```

- `depsec scan` → shows verdicts as a report (for reviewing a project)
- `depsec protect npm install` → blocks or passes (for installing packages)

### 3. Static-only fallback (no API key)
- Show only Critical/High severity + High confidence findings
- No medium confidence, no Low severity
- Binary: if anything passes this filter → flag it. Otherwise → clean.

### 4. No package-name allowlists
- Remove CAPABILITY_ALLOWLIST from capabilities.rs
- Every package judged on behavior, not identity
- Compromised popular packages must be caught, not silenced

### 5. LLM verdict pipeline
```
Step 1: Static scan produces N findings across all checks
Step 2: Filter to Critical/High severity + High confidence → ~15-20 suspects
Step 3: Group by package → ~5-10 suspect packages
Step 4: For each suspect package, send to LLM:
  - The specific findings (rule IDs, messages, code snippets)
  - The file content around the finding (±20 lines)
  - The package metadata (name, version, description)
  - Question: "Is this malicious or legitimate? Explain in 1 sentence."
Step 5: LLM returns: MALICIOUS | SUSPICIOUS | BENIGN for each package
Step 6: Output:
  - MALICIOUS → ✗ BLOCKED: [package] — [LLM reason]
  - SUSPICIOUS → ⚠ Review: [package] — [LLM reason] (only in scan mode)
  - BENIGN → suppressed (✓ clean)
```

### 6. Cost and speed
- ~5-10 LLM calls per scan (one per suspect package)
- Using fast model (Gemini Flash or Claude Haiku) — ~$0.01 per scan
- Target: <10 seconds for full pipeline (static + LLM)
- The existing `--triage` flag already has the OpenRouter client built

### 7. LLM prompt engineering protection (future)
- The LLM analyzes code, which could contain adversarial prompts
- Defense: structured output (JSON), system prompt hardening, output validation
- Not in scope for this sprint — tracked as future work

## The Output Experience

### `depsec protect npm install express`
```
✓ depsec: install clean (3 packages scanned, 0.8s)
```

### `depsec protect npm install evil-package`
```
✗ depsec: BLOCKED — evil-package@1.0.0
  Credential exfiltration: reads ~/.ssh/id_rsa and sends to 93.184.216.34
  (Run 'depsec scan' for full analysis)
```

### `depsec scan` (default — definitive mode)
```
depsec v0.20.0 — Supply Chain Security Scanner

Scanning pos... 487 packages analyzed in 3.2s

✗ 1 issue found:

  1. native-run@2.0.1 — SUSPICIOUS
     Reads credential files (.ssh, .aws) and makes network requests.
     LLM verdict: "Legitimate — native-run needs SSH keys to deploy
     to iOS/Android devices. Network calls are to Apple/Google APIs."
     → No action needed (build tool behavior)

✓ 486 packages clean

Grade: A (99.8%)
```

### `depsec scan` (no API key — static-only)
```
depsec v0.20.0 — Supply Chain Security Scanner
⚠ No API key configured — using static analysis only (set OPENROUTER_API_KEY for LLM verdicts)

Scanning pos... 487 packages analyzed in 1.1s

2 findings (Critical/High confidence only):

  1. [critical] DEPSEC-P025 — @pglite: WebAssembly binary detected
  2. [high] DEPSEC-CAP:credential-exfiltration — native-run: reads .ssh + network

Run 'depsec setup' to configure LLM for definitive verdicts.
```

## What Needs to Change

### Remove
- CAPABILITY_ALLOWLIST in capabilities.rs (20 hardcoded package names)
- Medium/Low confidence findings from default scan output
- Verbose "X findings" count — replace with "X packages analyzed"

### Add
- Confidence filter applied before any output (not just persona model)
- Package-level grouping in scan output (show packages, not individual findings)
- LLM triage as default (not opt-in `--triage`)
- `depsec setup` wizard that prompts for OpenRouter API key
- Definitive verdict formatting (✓/✗ with one-line reasons)

### Modify
- Executive summary → Definitive summary (packages, not findings)
- Protect output → Single line (clean or blocked)
- Exit codes: 0 = clean, 1 = blocked/issues, 2 = error (unchanged)

## Open Questions

- Should `depsec scan --full` still show all findings for auditors? (Probably yes)
- What's the right N for "top N suspects sent to LLM"? (Probably 10-15 packages max)
- Should the LLM verdict be cached? (Yes — per package@version, invalidate on new scan)
- How to handle LLM API errors gracefully? (Fall back to static-only, warn user)

## Next Steps

→ `/workflows:plan` for implementation details
