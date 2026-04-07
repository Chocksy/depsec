---
date: 2026-04-02
topic: detection-improvement-roadmap
---

# Detection Improvement Roadmap: 45.9% → 97%

## What We're Building

A phased improvement to depsec's static analysis that closes the 20 evasion gaps
identified by the Hornets Nest adversarial test suite, raising detection from 45.9%
to 97% through four sprints of increasing architectural sophistication.

## Current State

The Hornets Nest scorecard shows 17/37 detection (45.9%). The 20 evasion gaps fall
into three categories:

- **Quick fixes** (6 vectors): Regex additions, config changes, bug fix
- **AST extensions** (7 vectors): Broader tree-sitter queries within current architecture
- **Architectural** (7 vectors): Need new analysis capabilities (import graph, variable
  resolution, WASM inspection)

## Why This Approach

### Alternatives Considered

1. **Full Code Property Graph (Joern-style)** — Too heavy. Joern is JVM-based, 100MB+
   runtime. Overkill for package scanning where speed matters.

2. **GNN/ML-based detection** — Research shows 99%+ accuracy (GraphShield, JStrong) but
   requires training data, model management, and explainability is poor. Better as a
   future addition on top of deterministic rules.

3. **Full taint analysis** — Research-grade problem. Symbolic execution (Manticore) is
   too slow for scanning thousands of packages.

### Chosen: Layered Deterministic Analysis

Build incrementally on what we have (tree-sitter + regex + capabilities), adding:
- Intra-file variable resolution (constant propagation)
- Inter-file import graph with capability propagation
- WASM import/export inspection

All deterministic, all explainable, all fast.

## Sprint Plan

### Sprint 1: Quick Wins + AST Extensions (45.9% → 81%)

**Quick fixes (6 vectors):**

| Vector | Fix |
|---|---|
| E22 Python alias | Fix `needs_ast` gate in patterns.rs:312-321 to include Python/Ruby keywords |
| E23 Ruby pipe-open | Add `open("\|cmd")` pattern to Ruby AST rules |
| E21 pickle.loads | Add Python deserialization attack pattern (new rule P024) |
| E20 fromCharCode+add | Broaden P014 regex from `[\^]` to `[\^+\-]` |
| E24 >500KB skip | Sample first+last 50KB of large files instead of skipping entirely |
| E13 Unicode homoglyph | Normalize confusable unicode characters before pattern matching |

**AST extensions (7 vectors):**

| Vector | Fix |
|---|---|
| E08 mainModule.require | Extend P013 AST query to match member_expression chains |
| E16 (0,require)(name) | Detect sequence_expression + call pattern in tree-sitter |
| E17 global.Function | Broaden P008 query: match member_expression not just identifier |
| E18 const Fn = Function | Add single-level alias resolution for known-dangerous identifiers |
| E15 import() expression | Add dynamic import() call expression to P013 |
| E14 defineProperty getter | Detect property descriptors with get function containing dangerous calls |
| E09 Reflect.apply | Detect Reflect.apply/construct with dangerous function arguments |

### Sprint 2: Import Graph + Capability Propagation (81% → 86%)

New module: `src/graph.rs` (~200 lines)

Build an intra-package import graph by parsing require()/import statements across
all files in a package. Propagate capabilities along import edges.

```rust
struct PackageGraph {
    files: HashMap<String, FileCapabilities>,
    imports: HashMap<String, Vec<String>>,  // file → files it imports
}

fn propagate_capabilities(graph: &mut PackageGraph) {
    // Topological sort, propagate capabilities upward
    // If file A imports file B, A inherits B's capabilities
}

fn detect_cross_file_patterns(graph: &PackageGraph) -> Vec<Finding> {
    // If any file transitively has BOTH credential_read AND network → flag
    // Use betweenness centrality to find "bridge" files
}
```

**Catches:** E06 (multi-file scatter), E12 (JSON payload loaded at runtime)

**Key insight from Cerebro paper:** Order matters. Model behavior sequences by
execution phase (install-time → import-time → runtime) + call graph order.

**Visualization bonus:** The import graph can be rendered as mermaid/DOT for a
`depsec graph <package>` command showing internal structure with capability annotations.

### Sprint 3: Intra-File Variable Resolution (86% → 95%)

Extend the tree-sitter AST pass with lightweight constant propagation:

```
const r = require('fs')           → r maps to 'fs'
const method = "read" + "File"    → method maps to "readFile"
const Fn = Function               → Fn maps to Function
const target = homedir() + path   → target flagged as dynamic credential path
```

NOT full dataflow — just const assignment tracking. Walk VariableDeclarator nodes,
resolve RHS to string literal or known-dangerous identifier, use resolved values
in subsequent pattern queries.

**Catches:** E01 (string concat), E03 (alias chains), E10 (globalThis concat),
E17/E18 (Function alias)

**Reference tool:** tree-sitter-graph (Rust crate) provides a DSL for constructing
graphs from tree-sitter parse trees. Could use this or build custom.

### Sprint 4: WASM Inspection (95% → 97%)

**Market gap:** No npm security scanner inspects WASM binary contents. depsec would
be the first.

**Research findings:**
- CrowdStrike: 75% of WASM samples in the wild are malicious
- Wobfuscator (IEEE S&P 2022): WASM evasion reduces detector recall to 0.00
- WASM distributed in npm as: .wasm files (48%), base64 strings (39%), array exprs (13%)
- 66% of packages with WASM dependencies never update them

**Implementation (3 phases):**

Phase A — Detect WASM presence:
- Scan for .wasm files (currently skipped as binary)
- Detect base64-encoded WASM (magic bytes \0asm = AGFzbQ==)
- Detect array-encoded WASM ([0x00, 0x61, 0x73, 0x6d])
- Flag unexpected WASM in non-WASM packages

Phase B — Import/export capability analysis:
- Use `wasm-tools` Rust crate to parse WASM binary
- Extract import section: what host capabilities does the module request?
- Risk model: fd_write + sock_open + environ_get = HIGH risk
- Cross-reference with JS glue code imports

Phase C — Behavioral heuristics:
- CryptoNight mining signatures in exports (_cryptonight_hash)
- Entropy analysis on WASM data sections
- Size anomalies (utility package shipping 5MB WASM)

**Catches:** E04 (WASM payload)

## Remaining Gaps After All Sprints

| Vector | Why it persists |
|---|---|
| E02 Proxy wrapping | Needs runtime analysis — Proxy creates an identity alias invisible to static analysis |

One gap remaining = **97% detection rate**.

## Key Decisions

- **Deterministic over ML**: All improvements are rule-based and explainable.
  ML-based detection (GNN) is a future addition, not a replacement.
- **tree-sitter is sufficient**: No need for Joern/CodeQL. tree-sitter + custom
  graph construction gives us what we need at the right performance level.
- **WASM Phase A is differentiation**: Being first to detect WASM presence in npm
  packages is a marketing advantage, not just a security one.
- **Import graph enables visualization**: The graph is both a detection tool and
  a user-facing feature (`depsec graph <pkg>`).

## Research References

### Graph-Based Analysis
- [Joern](https://github.com/joernio/joern) — Code Property Graphs (open standard)
- [tree-sitter-graph](https://github.com/tree-sitter/tree-sitter-graph) — Rust DSL for graphs from tree-sitter
- [Cerebro](https://arxiv.org/abs/2309.02637) — Behavior sequence model for malicious package detection
- [SpiderScan](https://dl.acm.org/doi/10.1145/3691620.3695492) — Graph-based behavior modeling (ASE 2024)
- [HERCULE](https://rshariffdeen.com/paper/ICSE25-SEIP.pdf) — Inter-package static analysis (ICSE-SEIP 2025)

### WASM Analysis
- [wasm-tools](https://github.com/bytecodealliance/wasm-tools) — Rust crate for WASM manipulation
- [WABT](https://github.com/WebAssembly/wabt) — WebAssembly Binary Toolkit
- [Wobfuscator](https://ieeexplore.ieee.org/document/9833626/) — WASM evasion (IEEE S&P 2022)
- [CrowdStrike WASM Research](https://www.crowdstrike.com/en-us/blog/ecriminals-increasingly-use-webassembly-to-hide-malware/)

### Social Network Analysis on Code
- Betweenness centrality for exfiltration bridge detection
- Louvain community detection for scatter attack visibility
- [ScienceDirect: SNA metrics on call graphs](https://www.sciencedirect.com/science/article/abs/pii/S0164121215001259)

## Execution Status (as of 2026-04-03)

### Sprint 1: COMPLETE (45.9% → 78.4%)
All 13 vectors closed across 4 commits:
- [x] needs_ast gate bug fix (Python/Ruby AST was dead code)
- [x] P024 pickle, P034 Ruby pipe-open, P025 WASM detection
- [x] P014 regex broadened, large file sampling, unicode normalization
- [x] 7 JS AST extensions (mainModule.require, (0,require), global.Function, etc.)
- [x] Reflect.apply detection

### Sprint 2: COMPLETE (78.4% → 83.8%)
- [x] credential_read cross-file bug fix (two-pass scan_package)
- [x] Package-level signal combination (COMBO-001/002/003)
- [x] E14 chained require().exec()
- [x] E22 Python alias resolution
- [x] E12 JSON payload detection (AST eval() with dynamic args)
- [ ] Import graph module (deferred — Layer 1 capability aggregation sufficient)

### Sprint 3: COMPLETE (83.8% → 97.3%)
- [x] global.require alias chain tracking
- [x] Line-level string concat resolution
- [x] Cross-line const propagation (E01, E10) — AST symbol table + bracket access resolution
- [x] E14 getter body — chained require().exec() detection

### Sprint 4: COMPLETE
- [x] WASM presence detection (P025) — first-in-market
- [x] Import/export capability analysis — raw WASM binary parsing (no external crate)
- [ ] Behavioral heuristics (CryptoNight signatures, entropy) — deferred

### Sprint 5: COMPLETE (Definitive Protect Mode)
- [x] Removed CAPABILITY_ALLOWLIST — every package judged on behavior
- [x] LLM triage default when API key exists (auto-detect, --no-triage to skip)
- [x] Definitive output format (render_definitive — package-focused with LLM verdicts)
- [x] Exit code uses TP-only verdicts (FP/NI from LLM → clean exit)
- [x] Phase 4: Confidence recalibration (P002 same-line → High)
- [x] Phase 5: Protect mode post-install scan (delta packages, high-confidence only)
- [x] Phase 6: `depsec setup` wizard (AI verdicts option + API key guidance)

### Sprint 6: Performance — Lockfile-Driven Scanner (NEW — 2026-04-03)
- [x] Pre-filter files by extension in WalkDir (CEMS 299M: timeout → 14.7s)
- [x] Skip noise directories (.cache, @types, __pycache__, .min.js, etc.)
- [x] Lock file cache infrastructure (scan_cache.rs — npm/Cargo/Gemfile parsers)
- [x] Directory-level pruning for cached packages
- [x] **CRITICAL: Lockfile-driven scanner** (Phase 1+2 complete)

### Sprint 7: Multi-Language Parity (NEW — 2026-04-06)
- [x] Fix Rust AST gate (`needs_ast` returned false for .rs — P040-P043 were dead code)
- [x] Add Ruby `require(` to needs_ast gate (P033 was unreachable)
- [x] Multi-language capability model (Python: 10 network + exec + fs + env modules)
- [x] Ruby capability detection (net/http, httparty, faraday, system, ENV, File.read/write)
- [x] Rust capability detection (reqwest, hyper, Command::new, std::env, std::fs, libloading)
- [x] Generalize capability scanner — scans .venv/, vendor/bundle/, not just node_modules
- [x] Python/Ruby/Rust install hook detection (setup.py cmdclass, gemspec extensions, build.rs)
- [x] 12 new hornets nest scan tests (4 Python AST, 4 Ruby AST, 4 Rust AST)
- [x] 30+ new capability unit tests (Python, Ruby, Rust detection + integration)
- [x] AST suggestion text for all P020-P043 rules

### Detection: 36/37 (97.3%)
1 remaining gap: E02 (Proxy wrapping — requires runtime analysis, intentionally unsolvable statically)

### Multi-language parity:
- JS/TS: 9 AST rules + 14 regex rules + 9 capabilities + 8 COMBO rules
- Python: 5 AST rules (P020-P024) + capability detection (network, exec, fs, env, dynamic, install hooks)
- Ruby: 5 AST rules (P030-P034) + capability detection (network, exec, fs, env, install hooks)
- Rust: 4 AST rules (P040-P043) + capability detection (network, exec, fs, env, dynamic, build.rs)
- Hornets nest: 34 tests total (16 JS scan + 6 JS evasion + 4 Python + 4 Ruby + 4 Rust)
- 497 tests total, 0 warnings, 0 clippy issues

### Real-world validation:
- Planted malicious Python package in CEMS → all 3 techniques detected (P021+P024+P003)
- Planted malicious JS packages in POS → all techniques detected (P001+P002+P016+CAP:exfil)
- LLM definitive mode working on pxls (Groq via OpenRouter)

---

## NEXT SESSION: Sprint 6 — Lockfile-Driven Scanner

**This is the #1 priority.** Large JS projects (POS 412M, depsec.dev 138M) still timeout.

### The Problem
WalkDir traverses ALL files in node_modules (50K+ files for POS). Even with filtering,
enumerating 50K entries takes >60s. The cache only helps on REPEAT scans — first scan
still times out.

### The Solution: Don't Walk, Iterate
Instead of `WalkDir::new("node_modules")`, use the lockfile as the package index:

```rust
// CURRENT (slow): walk entire dep tree
for file in WalkDir::new("node_modules").max_depth(7) { scan(file); }

// NEW (fast): iterate packages from lockfile, walk each one shallowly
let packages = parse_lockfile("package-lock.json"); // 639 entries, 500ms
for pkg in packages {
    let pkg_dir = format!("node_modules/{}", pkg.name);
    for file in WalkDir::new(pkg_dir).max_depth(3) { scan(file); }
}
```

### Why This Works
- Lockfile parse: 500ms (639 packages from POS)
- Per-package walk (max_depth 3): ~5-10 files each, ~50ms
- Total: 639 × 50ms = ~32s (parallelizable to ~8s with rayon)
- With cache: only scan new/changed packages → <1s for repeat scans

### Implementation Plan

**Phase 1: Lockfile-driven package enumeration**
- [x] New function `collect_files_from_lockfile()` + `collect_files_walkdir()` in `src/checks/patterns.rs`
- [x] Reads lockfile → gets list of (name, version, dir_path) entries via `LockPackage.dir_path`
- [x] For each package: shallow WalkDir (max_depth 3) + existing scan logic
- [x] Falls back to full WalkDir if no lockfile exists
- [x] Support: package-lock.json (npm), yarn.lock, Cargo.lock, Gemfile.lock

**Phase 2: Cache integration**
- [x] On first scan: build cache from lockfile integrity hashes
- [x] On repeat scan: skip packages where integrity matches cache
- [x] On `npm install new-pkg`: only scan the delta (new/changed packages)
- [x] Cache stored in `.depsec/scan-cache.json`

**Phase 3: Parallel package scanning**
- [x] Add `rayon` to Cargo.toml for data parallelism
- [x] `files_to_scan.par_iter().fold()` with per-thread AstAnalyzer
- [x] POS: 9m19s → 3m06s (3x), ai-standups: 2m03s → 49s (2.5x), CEMS: 13.3s → 10.6s

**Phase 4: Python/Ruby/pnpm/yarn equivalents**
- [x] pip: parse requirements.txt with PEP 503 normalization + venv Python version detection
- [x] pnpm: parse pnpm-lock.yaml v9 (line-based, no YAML crate)
- [x] yarn: parse yarn.lock v1 (header+version+integrity)
- [x] Bundler: parse Gemfile.lock GEM specs (done in Sprint 6 infrastructure)
- [x] Cargo: parse Cargo.lock (done in Sprint 6 infrastructure)
- [x] Multi-ecosystem: parse_lockfile() combines ALL lockfiles (npm+pnpm+yarn+pip+gem+cargo)
- [x] Validated on 25 real projects — zero crashes, all lockfile types working

### Target Performance

| Scenario | Current | Target | Actual |
|----------|---------|--------|--------|
| POS first scan (412M) | >120s timeout | <15s | 160s (patterns: fast, secrets: bottleneck) |
| POS repeat scan (no changes) | >120s timeout | <1s | 18s (patterns: 0s cached, other checks: 18s) |
| POS after `npm install new-pkg` | >120s timeout | <2s | ~18s (delta scan) |
| CEMS first scan (299M) | 14.7s | <10s |
| CEMS repeat scan | 14.7s | <1s |

### Files to modify
- `src/checks/patterns.rs` — add lockfile-driven scan path alongside WalkDir
- `src/scan_cache.rs` — already built, wire into the new scan path
- `Cargo.toml` — add `rayon` for parallel scanning (Phase 3)

### Reference plans
- Sprint 5 plan: `docs/plans/2026-04-03-feat-sprint5-definitive-protect-mode-plan.md`
- Sprint 2 plan: `docs/plans/2026-04-03-feat-sprint2-package-capability-aggregation-plan.md`
- Sprint 1 plan: `docs/plans/2026-04-02-feat-sprint1-detection-quick-wins-ast-extensions-plan.md`
- Hornets nest plan: `docs/plans/2026-04-02-feat-hornets-nest-adversarial-test-suite-plan.md`

### Key context files
- `src/scan_cache.rs` — lockfile parsers + cache already built
- `src/checks/patterns.rs` — current WalkDir-based scanner (the code to replace)
- `src/checks/capabilities.rs` — also needs lockfile-driven approach for its scan_package()
- `tests/hornets_nest/` — adversarial test suite (22 tests, 86.5% detection)
