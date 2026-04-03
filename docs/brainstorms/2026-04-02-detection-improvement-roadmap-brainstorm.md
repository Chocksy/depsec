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

### Sprint 1: COMPLETE (13/13 vectors closed — 45.9% → 78.4%)
All quick fixes and AST extensions shipped across 4 commits.

### Sprint 2: MOSTLY COMPLETE (78.4% → 81.1%)
- [x] credential_read cross-file bug fix
- [x] Package-level signal combination (COMBO-001/002/003)
- [x] E14 chained require().exec()
- [x] E22 Python alias resolution
- [ ] Import graph module (deferred — Layer 1 capability aggregation was sufficient)

### Sprint 3: PARTIALLY COMPLETE (83.8% → 86.5%)
- [x] global.require alias chain tracking
- [x] Line-level string concat resolution
- [ ] Cross-line const propagation (E01, E10) — needs AST symbol table

### Sprint 4: PHASE A COMPLETE (86.5%)
- [x] WASM presence detection (P025)
- [ ] Import/export capability analysis
- [ ] Behavioral heuristics

### Current: 32/37 (86.5%) — 5 remaining gaps
- E01, E10: cross-line const propagation
- E02: Proxy wrap (runtime only)
- E12: JSON payload cross-file data flow
- E14: defineProperty getter body

## Sprint 5: Definitive Protect Mode (NEW — 2026-04-03)

**The critical insight**: Detection without precision is noise. 3,254 findings on POS
is useless. `depsec protect` must be BINARY: ✓ clean or ✗ BLOCKED.

### The Problem
- POS scan: 3,254 findings → nobody reads this
- CEMS scan: 1,355 findings → noise
- `depsec protect npm install` should show 0-2 actionable alerts, not thousands

### The Pipeline
```
Static scan → 3,000 raw signals
  → Confidence filter (Critical/High + High confidence only) → 15-20
  → Package verdict (known-good allowlist, build tool recognition) → 0-3
  → (Future) LLM triage → 0-1 definitive blocks
  → OUTPUT: ✓ clean OR ✗ BLOCKED: reason
```

### Key Design Principles
1. **`scan` mode = audit** (all findings, for security teams)
2. **`protect` mode = seatbelt** (binary verdict only, for developers)
3. **Known-good packages are silenced** (esbuild, playwright, typescript do build-tool things)
4. **Only definitively suspicious patterns block** (credential exfil + network, not just eval())
5. **LLM is the last resort** (sends top 2-3 suspects for final verdict)

### What Needs to Change
- Protect mode applies aggressive confidence + severity filter
- Built-in allowlist for well-known build tools (esbuild, webpack, vite, etc.)
- Package popularity/download count as a trust signal
- `depsec protect` output: single line ✓/✗, not a report

## Next Steps

→ `/workflows:plan` for Sprint 5: Definitive Protect Mode
→ Then: Sprint 3 remainder (const propagation), Sprint 4 remainder (WASM deep analysis)
