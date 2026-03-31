# Brainstorm: Wire Up All Broken/Dead Features

**Date:** 2026-03-31
**Decision:** Path B — wire everything up, fix it all

## What We're Building

Connecting all scaffolded-but-dead features into production code paths:

### Critical Wiring (6 items)
1. **`--sandbox` on protect** — stop hardcoding false, pass CLI flag through to ProtectOpts → install_guard
2. **`--learn` / `--strict` on protect** — thread through ProtectOpts → install_guard → monitor::run_monitor()
3. **External rules `apply_rules()`** — call from scanner.rs run_scan() after existing checks, affects all scan paths
4. **`--budget` on audit** — track real USD cost via OpenRouter usage API, enforce cap per audit session
5. **Canary tokens** — plant in sandbox temp home before sandboxed install, fail install if package reads them
6. **Attestation** — auto-generate after protect completes, remove hidden separate commands

### README / Docs (6 items)
7. Add capabilities check docs (8 combo rules, 10pts weight)
8. Document `--staged` flag for pre-commit hook usage
9. Fix sandbox docs to reflect actual behavior (protect-only, requires --sandbox or config)
10. Fix config example (add `capabilities` to enabled list)
11. Fix scoring weights (add capabilities=10, remove phantom network=10)
12. Document external rules system end-to-end

### Additional Code Fixes (11 items)
13. Rule guide output.rs — add P013-P019 narratives
14. Shell hook aliases — update from deprecated `install-guard` to `protect`
15. Remove phantom `network` scoring weight (no check produces network results)
16. Selfcheck trust claims — verify dynamically instead of hardcoded checkmarks
17. Unify hook install commands (legacy uses `secrets-check`, new uses `scan --staged`)
18. Remove unused `tree-sitter-python` dependency (or wire it up for Python AST)
19. Fix audit max_rounds (always capped to 2, misleading)
20. Audit: support non-npm ecosystems (Cargo, pip, gem, Go) in locate_package()
21. LLM module: capture response `id` for OpenRouter generation stats
22. LLM module: replace hardcoded pricing with live `/api/v1/models` fetch
23. PatternRule dead fields — either use name/narrative or remove them

## Why This Approach

User wants truth in advertising — every flag the CLI accepts must do what it says. Dead code that's fully implemented just needs wiring, not rewriting. The hardest new work is budget enforcement (needs OpenRouter API integration) and multi-ecosystem audit support.

## Key Decisions

- **Sandbox CLI flag overrides config** — `--sandbox` means auto-detect backend
- **Canary detection = install failure** — not just a warning
- **Attestation integrated into protect output** — no separate commands
- **External rules affect scoring** — new "external_rules" category
- **Budget = USD cap** — using OpenRouter token usage from responses + hardcoded pricing (with future option for live pricing)
- **Network weight removed** — phantom category, misleading

## Open Questions

- Should we wire tree-sitter-python NOW or remove the dependency? (Scope creep risk)
- Multi-ecosystem audit (Cargo/pip/gem/Go) — full implementation or just Cargo since depsec is Rust?
