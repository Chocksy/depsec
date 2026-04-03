---
title: "feat: Sprint 5 — Definitive Protect Mode"
type: feat
date: 2026-04-03
---

# Sprint 5: Definitive Protect Mode

## Overview

Transform depsec from a noisy warning generator into a definitive decision-maker.
The primary path uses LLM (via OpenRouter) to deliver binary verdicts: clean or blocked.
Static-only mode (no API key) serves as a fallback with aggressive confidence filtering.

**Brainstorm:** `docs/brainstorms/2026-04-03-definitive-protect-mode-brainstorm.md`

## Problem Statement

- POS scan: 3,254 findings → useless
- CEMS scan: 1,355 findings → noise
- A vibe coder running `npm install` needs a seatbelt, not a security audit
- `depsec protect` should say "✓ clean" or "✗ BLOCKED" — nothing in between

## Implementation Phases

### Phase 1: Remove Package-Name Allowlist

Any package can be compromised. Trust is earned by behavior, not identity.

- [ ] **1.1** Remove `CAPABILITY_ALLOWLIST` from `src/checks/capabilities.rs:139-168`
  - Delete the 20 hardcoded package entries (express, axios, esbuild, etc.)
  - Remove `is_combination_allowed()` function (lines 567-576)
  - Update `evaluate_package()` to skip allowlist check
  - Keep the USER allowlist from config (that's the user's explicit choice)
  - Update tests that depend on allowlist behavior

- [ ] **1.2** Run hornets nest + full test suite to verify no regressions

### Phase 2: Make LLM Triage the Default Path

Currently `--triage` is opt-in and post-hoc. Make it the default when an API key exists.

- [ ] **2.1** Restructure `src/commands/scan.rs` scan pipeline:

  ```
  BEFORE: scan → render output → if --triage { triage → append }
  AFTER:  scan → filter → if has_api_key { triage } → render definitive output
  ```

  - Move triage BEFORE rendering, not after
  - The triage results inform the output, not append to it
  - Only render after triage verdicts are known

- [ ] **2.2** Auto-detect API key availability:
  - If `OPENROUTER_API_KEY` env var is set → LLM mode (default)
  - If not set → static-only mode with a one-time hint: "Set OPENROUTER_API_KEY for definitive verdicts"
  - No `--triage` flag needed in LLM mode — it's always on
  - Keep `--no-triage` flag for users who want to skip LLM intentionally
  - Keep `--triage-dry-run` for cost estimation

- [ ] **2.3** Integrate triage verdicts into exit code:
  - After triage, recalculate `has_issues` from TP-only findings
  - `exit 0` if all findings are FP/NI (LLM cleared them)
  - `exit 1` only if LLM confirms True Positives remain
  - Static-only mode: exit code based on High-confidence filter as before

### Phase 3: Definitive Output Format

Replace the verbose executive summary with a package-focused definitive summary.

- [ ] **3.1** New `render_definitive()` function in `src/output.rs`:

  **With LLM verdicts:**
  ```
  depsec v0.20.0 — pos

  487 packages scanned in 3.2s

  ✗ 1 issue:
    native-run@2.0.1 — reads credential files + network requests
    Verdict: Legitimate build tool (SSH for device deployment)

  ✓ 486 packages clean

  Grade: A (99.8%)
  ```

  **Static-only (no API key):**
  ```
  depsec v0.20.0 — pos
  ⚠ Static analysis only (set OPENROUTER_API_KEY for AI verdicts)

  487 packages scanned in 1.1s

  2 findings (high confidence):
    [critical] @pglite — WebAssembly binary detected
    [high] native-run — credential read + network access

  ✓ 485 packages clean

  Run 'depsec setup' for definitive AI-powered verdicts.
  ```

- [ ] **3.2** Group findings by PACKAGE, not by rule:
  - Currently output is: "P001 found in file X, P002 found in file Y..."
  - New output: "Package X has these issues: [P001, P002, CAP:exfil]"
  - One line per suspicious package, not one line per finding
  - Show the LLM verdict (TP/FP/NI + reasoning) inline

- [ ] **3.3** Definitive protect output in `src/install_guard.rs`:

  **Clean install:**
  ```
  ✓ depsec: install clean (3 packages scanned, 0.8s)
  ```

  **Blocked install:**
  ```
  ✗ depsec: BLOCKED — evil-package@1.0.0
    Credential exfiltration: reads ~/.ssh/id_rsa and POSTs to 93.184.216.34
  ```

  - Single line for clean (no change from current)
  - 2-3 lines for block: package name + reason
  - No verbose finding list, no rule IDs in user-facing output

### Phase 4: Confidence Recalibration

Current confidence levels produce too many "High" confidence findings that aren't actually
high confidence. Recalibrate so the filter `Critical/High + High confidence` is meaningful.

- [ ] **4.1** Audit all pattern rules and their confidence assignments:
  - P001 (eval/exec): Currently `Low` for regex, `High` for AST → correct
  - P007 (entropy): Currently `Low` → correct (very noisy)
  - P013 (dynamic require): Currently `Low` for regex, `High` for AST → correct
  - P002 (base64→eval): Currently `Medium` → should this be `High` when both parts are on same line?
  - COMBO rules: Currently `High`/`Medium` → review

- [ ] **4.2** The key filter: what survives `Critical/High severity + High confidence`?
  - AST-confirmed P001 (exec with variable args from dangerous module)
  - AST-confirmed P008 (new Function with variable)
  - AST-confirmed P013 (dynamic require with function call)
  - P004 (credential read) — already `High` confidence
  - P010 (IMDS probe) — already `High` confidence
  - P015 (anti-forensic) — already `High` confidence
  - P018 (node binding) — already `High` confidence
  - P024 (pickle) — already `High` confidence
  - P025 (WASM) — currently `Medium` → consider `High` for unknown packages
  - CAP combinations — currently `Medium` → keep (these go to LLM)
  - Secrets (S-rules) — already separate check, always visible
  - Deps (V-rules) — CVEs with known severity, always visible

- [ ] **4.3** Reduce P002 false positives:
  - `Medium` confidence when base64 and eval are on different lines
  - `High` confidence when chained on same expression (e.g., `eval(atob(x))`)

### Phase 5: Protect Mode LLM Integration

Wire the triage engine into the protect command for the `depsec protect npm install` flow.

- [ ] **5.1** Add LLM verdict to `depsec protect` sandboxed path:
  - After kill chain evaluation, if verdict is `Warn` or `Block`:
    - If API key available: send the canary + network evidence to LLM for confirmation
    - LLM returns: CONFIRMED MALICIOUS | FALSE ALARM | NEEDS REVIEW
    - Only block on CONFIRMED MALICIOUS
  - If no API key: use existing verdict logic (Warn prints warning, Block blocks)

- [ ] **5.2** Add static scan to `depsec protect` for newly installed packages:
  - After `npm install` completes, run a quick scan on the newly installed packages
  - Filter to Critical/High + High confidence
  - If any findings → send to LLM for verdict
  - Block if LLM confirms TP

- [ ] **5.3** Output formatting for protect:
  - Remove all ANSI escape code noise from protect output
  - Single ✓ or ✗ line with clean formatting
  - Show LLM verdict reason when blocking

### Phase 6: Setup Wizard

- [ ] **6.1** Add `depsec setup` command:
  - Prompt for OpenRouter API key
  - Test the key with a small API call
  - Save the env var name to global `~/.config/depsec/config.toml`
  - Print: "✓ AI verdicts enabled. depsec will now provide definitive decisions."

- [ ] **6.2** First-run experience:
  - If no API key and first scan → print: "Tip: Run 'depsec setup' for AI-powered definitive verdicts"
  - Only show once (flag in config)

## Acceptance Criteria

- [ ] CAPABILITY_ALLOWLIST removed — every package judged on behavior
- [ ] `depsec scan` default output shows packages (not individual findings)
- [ ] With API key: LLM verdicts appear inline, exit code reflects TP-only
- [ ] Without API key: only Critical/High + High confidence findings shown
- [ ] `depsec protect` outputs single line: "✓ clean" or "✗ BLOCKED: reason"
- [ ] POS scan goes from 3,254 findings → ~5-10 package-level items → LLM reduces to 0-2
- [ ] CEMS scan goes from 1,355 findings → ~10-15 items → LLM reduces to 0-3
- [ ] `depsec setup` wizard works for API key configuration
- [ ] All existing unit tests + hornets nest tests still pass
- [ ] `cargo fmt --check` + `cargo clippy -- -D warnings` clean

## Dependencies & Risks

| Risk | Mitigation |
|---|---|
| LLM unavailable / rate limited | Graceful fallback to static-only with message |
| Prompt injection via malicious code | System prompt already has anti-injection rules, structured JSON output |
| Removing allowlist creates noise for build tools | LLM handles this — build tools get FP verdict |
| Breaking change for existing users | `--full` flag still shows everything, `--no-triage` skips LLM |

## Important Notes (from user feedback)

### LLM Provider: Groq via OpenRouter
- OpenRouter supports Groq as a backend provider — no new API client needed!
- Change default model from `anthropic/claude-sonnet-4-6` to a Groq-hosted model
  (e.g., `groq/llama-3.3-70b-versatile`) in `TriageConfig`
- Existing `src/llm.rs` OpenRouter client works as-is — just a model name change
- Users can override model in `depsec.toml` `[triage] model = "..."` for any
  OpenRouter-supported provider (Anthropic, Google, Groq, etc.)

### No Artificial Timeouts
- Don't set tight timeouts that make the LLM useless
- Let the LLM take as long as it needs to properly analyze code
- A 30-second analysis that catches a real attack is worth the wait

### LLM Needs Full Package Context
- Current triage sends ±30 lines of context — not enough for definitive verdicts
- The LLM should be able to read ALL files in a suspect package
- Send the full package directory listing + key files (entry point, install scripts, etc.)
- If a package has 10 files totaling 50KB, send all of them
- The LLM needs to understand the full attack chain, not just a code snippet

## References

### Files to Modify

| File | Changes |
|---|---|
| `src/checks/capabilities.rs` | Remove CAPABILITY_ALLOWLIST, update evaluate_package |
| `src/commands/scan.rs` | Restructure: triage before render, auto-detect API key |
| `src/output.rs` | New render_definitive(), package-grouped output |
| `src/install_guard.rs` | LLM verdict in protect, clean output formatting |
| `src/triage.rs` | Adjust for default-on mode, integrate with render |
| `src/config.rs` | Global config for API key, first-run flag |
| `src/commands/misc.rs` | Add `depsec setup` command |
| `src/main.rs` | Register setup command |

### Brainstorm & Prior Art
- Brainstorm: `docs/brainstorms/2026-04-03-definitive-protect-mode-brainstorm.md`
- Detection roadmap: `docs/brainstorms/2026-04-02-detection-improvement-roadmap-brainstorm.md`
- Existing triage: `src/triage.rs` (system prompt, cache, cost estimation)
- Existing LLM client: `src/llm.rs` (OpenRouter integration)
