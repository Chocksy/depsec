---
date: 2026-03-31
topic: executive-summary-default
---

# Executive Summary as Default Output

## What We're Building

Transform the default `depsec` experience from "146 lines of categorized findings" to "5-10 lines of prioritized actions."

## Key Decisions

1. **`depsec` alone runs the scan** — No subcommand needed. `depsec` or `depsec .` or `depsec /path` runs the scan. All other commands remain subcommands (`depsec fix`, `depsec protect`, etc.). Like `cargo clippy` or `zizmor .`.

2. **Executive summary is the default output** — Prioritized actions (red/yellow/green), not category-by-category listing. The detailed category view moves to `--full`. `--verbose` shows everything including build tools.

3. **Simplified flags:**
   - `depsec` — executive summary (NEW default)
   - `depsec --full` — current detailed category-by-category output
   - `depsec --verbose` — everything including build tools, low-confidence
   - `depsec --json` / `--sarif` — machine output (unchanged)
   - `depsec --strict` — auditor-level (replaces `--persona auditor`)
   - `depsec --relaxed` — pedantic-level (replaces `--persona pedantic`)
   - Kill `--persona` flag (confusing name, replaced by `--strict`/`--relaxed`)

4. **Triage suggested inline** — When ambiguous findings exist, suggest `depsec --triage` to let AI classify them. Makes the LLM feature discoverable.

## Executive Summary Format

```
$ depsec

depsec v0.14.0 — pos-app                                    Grade: D (4.0/10)

🔴 2 actions needed:
  1. Pin workflow actions to SHA (1 unpinned) → run: depsec fix
  2. Remove JWT tokens from .cursor/plans/ (2 leaked)
     → .cursor/plans/sup-00d0b27d.plan.md:49

🟡 3 things to review:
  3. 68 dependency advisories across 22 packages → run: npm audit fix
  4. 11 suspicious patterns in 5 runtime packages
  5. Missing SECURITY.md

🟢 What's working:
  ✓ Capabilities: 91% — build tools properly isolated
  ✓ Lockfiles committed and verified
  ✓ No malware detected

5 findings may be false positives → run 'depsec --triage' for AI classification

Run 'depsec --full' for detailed breakdown.
```

## Priority Logic

Actions are prioritized by:
1. **CRITICAL** severity findings → 🔴 (red, action needed)
2. **HIGH** severity OR auto-fixable → 🔴 (red, action needed)
3. **MEDIUM** severity in runtime deps → 🟡 (yellow, review)
4. **LOW** or build-only → collapsed into "what's working" or hidden
5. Auto-fixable items get `→ run: depsec fix` inline

## Grouping Logic

Findings are grouped into "actions" not individual findings:
- 68 CVEs across 22 packages → ONE action: "update deps"
- 3 unpinned workflow actions → ONE action: "pin actions"
- 2 JWT leaks in same dir → ONE action: "remove JWTs"

Each action has:
- What's wrong (1 line)
- What to do (inline command or path)
- Count of individual findings (for context)

## The `scan` Subcommand

`depsec scan` becomes an alias for `depsec` (backwards compatible). Both produce the executive summary. `depsec scan --full` gives detailed view.

## Open Questions

- Should the scorecard (ASCII box) show in executive mode? Or only in `--full`?
- Should the rule glossary (P001, P002 explanations) show in executive mode? Or only in `--full`/`--verbose`?
- Should `depsec` with no path default to `.`? (Yes, like most tools)

## Next Steps

→ `/workflows:plan` then `/workflows:work`
