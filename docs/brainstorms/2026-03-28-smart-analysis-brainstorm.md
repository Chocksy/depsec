# Brainstorm: Smart Analysis Engine — From Noise Reduction to Zero-Day Hunting

**Date:** 2026-03-28
**Status:** Draft
**Scope:** Three-layer evolution of depsec's pattern detection and analysis capabilities

---

## The Problem

Running `depsec scan .` on a real production app (POS system, Svelte + Tauri + Rust) produces **5,765 pattern findings** — with **700+ exec() warnings** alone. ~95% are false positives: `regex.exec()` being flagged alongside `child_process.exec()`. The scan scores 0.6/10 (grade F) for a perfectly healthy app.

**Root cause:** Line-by-line regex matching (`\b(eval|exec)\s*\(\s*[a-zA-Z_]`) has zero context awareness. It cannot distinguish:
- `re.exec("safe string")` (regex match — benign)
- `child_process.exec(userInput)` (shell execution — dangerous)
- `db.exec("SELECT ...")` (database query — benign)

**Top false positive sources (from POS scan):**

| Package | exec() hits | Actually dangerous? |
|---------|------------|---------------------|
| vitest | 38 | No — test runner, regex `.exec()` |
| .vite/deps (bundled) | 38 | No — Vite prebundled deps |
| posthog-js | 29 | No — analytics, UA regex parsing |
| core-js | 28 | No — polyfills |
| acorn | 20 | No — JS parser |
| js-tokens | 16 | No — tokenizer |

---

## What We're Building

A three-layer evolution of depsec's analysis engine, shipped incrementally:

### Layer 1: Smart Filtering (No LLM Required)
Make the existing scanner context-aware using AST parsing (tree-sitter) and UX improvements. **Goal: reduce false positives by 90%+ and make output actionable.**

### Layer 2: LLM Triage (`--triage` flag)
Optional LLM-powered analysis of remaining findings. SAST-first, LLM-second architecture. **Goal: for each finding, answer "is this actually dangerous in context?"**

### Layer 3: Deep Audit (`--audit <package>`)
Full source code analysis of individual packages for novel vulnerabilities. **Goal: find things no scanner has found before.**

---

## Why This Approach

**Research-backed:** We analyzed Socket.dev, Semgrep, Snyk, zizmor, Sandworm, VulnHuntr, Google Big Sleep, Anthropic's zero-day research, GitHub Security Lab's taskflow agent, CyberArk Vulnhalla, and IRIS (Cornell/UPenn). The consistent finding across all successful tools:

1. **Static analysis first, LLM second** — LLMs reduce false positives rather than generating findings (FP rates drop from 92% to 6.3%)
2. **Context is the #1 lever** — sending dataflow context, not just the flagged line, is what separates useful from useless
3. **AST-level understanding** eliminates entire classes of false positives that regex can never solve
4. **Multi-stage verification** catches hallucinated vulnerabilities before they reach the user

---

## Key Decisions

1. **tree-sitter for AST parsing** — +1.5MB binary size, 7s build time, first-class Rust bindings, built-in query predicates for negative matching. Powers Helix, Zed, Difftastic. Beats ast-grep for our use case (smaller binary, better docs, native negative matching).

2. **Dependency impact is minimal** — depsec currently has 102 unique transitive crates. Adding tree-sitter + 4 language grammars adds only ~6 new crates (102 → 108, +6%). Most tree-sitter deps (`regex`, `aho-corasick`, `memchr`) are already in the tree. Compare: ast-grep would add ~20+ crates and 3x the binary size increase.

3. **Single LLM provider via OpenRouter** — one API endpoint, user provides `OPENROUTER_API_KEY`. No complex multi-provider abstraction. OpenRouter handles model routing (Claude, GPT, Gemini, open-source).

4. **Analyze installed deps on disk** (node_modules, vendor, .venv) — not registry source. Simpler, works offline, catches post-install modifications.

5. **Incremental rollout** — Layer 1 is pure Rust, no API dependency. Layer 2 adds optional LLM. Layer 3 builds on both. Each layer is independently useful.

6. **colgrep as optional complementary tool** — colgrep (semantic code search via ColBERT embeddings) can complement tree-sitter in Layer 3 for discovering relevant code to audit. It's a runtime tool (not bundled), useful for natural-language queries like "find functions that handle user input" before structural analysis. See Layer 3 doc for details.

---

## Dependency Impact Analysis

| | Current | After Layer 1 | After Layer 2 | After Layer 3 |
|---|---|---|---|---|
| Direct deps | 10 | 15 (+5 tree-sitter crates) | 15 (reqwest already present) | 15 |
| Unique transitive deps | 102 | ~108 (+6%) | ~108 (+0%) | ~108 (+0%) |
| Binary size | 2.8MB | ~4.3MB (+1.5MB) | ~4.3MB (+0%) | ~4.3MB (+0%) |
| New runtime deps | 0 | 0 | 0 | colgrep (optional) |

Layer 2 and 3 add zero new Rust crate dependencies — they reuse reqwest (already present) for OpenRouter API calls.

---

## Open Questions

1. **Custom rule syntax**: Should external TOML rules support tree-sitter query patterns, or keep them regex-only with built-in rules using tree-sitter?
2. **Caching**: Should LLM triage results be cached per package@version to avoid re-analyzing on every scan?
3. **Cost management**: How to surface estimated API costs before running `--triage` on a large project?
4. **CI/CD mode**: Should `--triage` work in CI, or is it interactive-only? (API keys in CI, cost per run, timing)

---

## Research Sources

### Tools Analyzed
- **Socket.dev** — Package-level capability model with 102 alert types, above/below-the-fold UI
- **Semgrep** — Import context matching, taint tracking, pattern-not-inside, severity/confidence/likelihood metadata
- **Snyk** — Path-based ignore with expiration, disregardIfFixable, reachability analysis
- **zizmor** — Persona model (Auditor/Pedantic/Regular), Capability classification (Arbitrary/Structured/Fixed)
- **Sandworm** — Runtime interception with per-package permissions
- **VulnHuntr** (2.6k stars) — LLM call-chain tracing from entry points
- **Parsentry** — tree-sitter + parallel AI agents, 10 languages
- **GuardDog** (DataDog, 1k stars) — Semgrep + YARA for malicious package detection
- **CyberArk Vulnhalla** — CodeQL + LLM, 96% FP reduction, numeric status codes
- **IRIS** (Cornell/UPenn) — LLMs generate taint specs for CodeQL (neurosymbolic)
- **GitHub Security Lab Taskflow Agent** — MCP-enabled multi-stage YAML pipelines
- **Anthropic claude-code-security-review** — Three-phase analysis with confidence thresholds

### Key Research
- Anthropic: 500+ zero-days found by Claude Opus 4.6 (red.anthropic.com/2026/zero-days)
- Google Big Sleep: First AI zero-day in SQLite (Project Zero + DeepMind)
- Sean Heelan: o3 found Linux kernel zero-day CVE-2025-37899 with no scaffolding
- Paper: LLM agents reduce SAST FP from 92% to 6.3% (arxiv 2601.22952)
- Paper: LLMxCPG — code slicing reduces analysis scope 67-91% (arxiv 2507.16585)
- Paper: Vul-RAG improves accuracy 16-24% with CVE knowledge retrieval (arxiv 2406.11147)
