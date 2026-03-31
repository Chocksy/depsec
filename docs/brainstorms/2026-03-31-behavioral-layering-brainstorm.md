# Brainstorm: Behavioral Layering — From Noise to Signal

**Date:** 2026-03-31
**Status:** Decided
**Trigger:** Real-world testing of depsec against POS app (Svelte+Tauri+Rust monorepo) revealed 6,731 lines of output, 212 false positives from one regex rule, and F grade for a perfectly legitimate app.

---

## The Problem (Validated by Real-World Testing)

Running `depsec scan ~/Development/pos --verbose` produces:

| Metric | Value | Acceptable? |
|--------|-------|-------------|
| Total output lines | 6,731 | No — unusable |
| Patterns section alone | 6,300 lines (93% of output) | No |
| P001 regex.exec() false positives | 212 | No — one rule, one bug |
| Same CVE listed per package | 5-6 times (tar, devalue, svelte) | No — no dedup |
| Capabilities findings | 59 total, only 11 from app imports | Good split exists but verbose dumps all |
| Score | F (0.6/10) | No — demoralizing for legit app |
| Badge output | Empty | Broken |
| Triage dry-run tokens | "~0 tokens" | Wrong estimate |
| Typosquat: h2, slab, socket2 flagged | 10 false positives | Levenshtein too naive |
| Secrets in .cursor/plans/ | JWT flagged | Should respect gitignore-like paths |
| High-entropy on .tsbuildinfo | 46,060-char match | Always false positive |

### Root Cause Analysis

1. **P001 AST gating bug** — The two-pass AST engine works correctly but only activates for files containing `child_process`/`shelljs`/`execa`. Files with `regex.exec()` (like @sveltejs/kit) never trigger AST, so the dumb regex fallback fires on every `.exec()` call.

2. **No output aggregation** — Every individual advisory, pattern match, and capability finding gets its own line. `tar@6.2.1` appears 6 times for 6 different advisories.

3. **Flat severity model** — All capability findings shown at same alarm level. "vitest writes files AND executes commands" gets the same red X as actual malware indicators.

4. **Missing file exclusions** — `.tsbuildinfo` not in skip list. `.cursor/` not in secrets exclusion.

---

## What We Learned from Research

### Competitive Landscape (Socket.dev, Capslock, Sandworm, LavaMoat, Phylum, OpenSSF)

**Socket.dev** — 50 alert types, but their default policy **IGNORES** networkAccess, shellAccess, eval, envVars, filesystemAccess, dynamicRequire. Only knownMalware blocks. Their answer to false positives is "turn them off." They have ZERO explicit kill-chain combination rules — capabilities fire independently.

**Google Capslock** — The killer insight: **<2% of package version updates introduce a new capability**. Capability version diffing is the most powerful zero-day signal. The boltdb-go attack would've been caught instantly because the fork suddenly gained CAPABILITY_EXEC + CAPABILITY_NETWORK.

**Sandworm** — Runtime interception with TOFU (Trust On First Use). Run your test suite → capture capability baseline → enforce on future runs. Elegant but requires runtime instrumentation.

**Cerebro (academic)** — Behavior SEQUENCES matter, not just sets. `read_credentials → encode → network_request` is an exfiltration CHAIN. Install-time code is 3-5x more suspicious than runtime code.

**LavaMoat (MetaMask)** — Per-package SES Compartments with policy.json. The most complete enforcement model but requires deep Node.js integration.

**OpenSSF Scorecard** — Package health scoring (maintenance, reviews, branch protection). Orthogonal to capabilities but composable as risk multiplier.

### Our Differentiators (confirmed by research)

1. **Kill-chain combination rules** — Nobody else has explicit `C6+C1 = exfiltration` logic. Socket fires capabilities independently.
2. **Local-only analysis** — Socket uploads manifests to their API. We run 100% on-disk.
3. **Install-guard runtime monitoring** — Our protect command provides runtime verification that static analysis misses.
4. **Layered defense** — Patterns → Capabilities → LLM Triage → Runtime. Most tools do one layer.

---

## What We're Building: Behavioral Layering

### Core Principle

**The compound risk of capabilities determines severity, not individual capabilities.**

```
Individual capability alone     → Informational (log, don't alarm)
Expected combination for type   → Low (build tool: exec+fs is normal)
Unexpected dangerous combo      → High (library: exec+network = dropper)
Combo + install hook           → Critical (postinstall + exec + network)
Combo + obfuscation            → Critical (hidden capabilities)
```

### The Three Layers

```
┌─────────────────────────────────────────────┐
│  Layer 3: Version Intelligence              │
│  "Did this package GAIN new capabilities?"  │
│  Signal: capability diff across versions    │
│  (Future — requires version history cache)  │
├─────────────────────────────────────────────┤
│  Layer 2: Compound Risk Scoring             │
│  "Is this combination actually dangerous?"  │
│  Signal: kill-chain rules + reachability    │
│  (This sprint — fixes the output problem)   │
├─────────────────────────────────────────────┤
│  Layer 1: Bug Fixes + Noise Reduction       │
│  "Stop showing things that aren't real"     │
│  Signal: AST gating, file exclusions, dedup │
│  (Quick wins — immediate impact)            │
└─────────────────────────────────────────────┘
```

---

## Layer 1: Bug Fixes & Noise Reduction (Quick Wins)

### 1.1 Fix P001 AST Gating

**Bug:** `needs_ast` only triggers for files containing dangerous module names. Files with regex.exec() never get AST analysis.

**Fix:** Two options:
- **(A) Gate P001 regex on module presence** — Before running P001 regex, check if the file contains any dangerous module string. If not, skip P001 entirely (eval() still fires via separate check).
- **(B) Expand needs_ast trigger** — Also trigger AST for files containing `exec(` when they DON'T contain dangerous modules, just to suppress P001. Expensive for many files.

**Decision: Option A.** Simple, fast, and correct. `regex.exec()` can never be dangerous because regex is not a shell module. Only fire P001 regex on files that mention dangerous modules or as AST fallback.

**Impact:** Kills 212 false positives immediately.

### 1.2 Add Missing File Exclusions

| Exclusion | Why |
|-----------|-----|
| `.tsbuildinfo` | Build cache, not executable. 46K-char entropy match. |
| `.cursor/` | IDE config directory, not project code |
| `.svelte-kit/` | Generated build output, duplicates of source |
| `*.prod.js` minified entropy | Already skip .min.js entropy, extend to .prod.js |

### 1.3 Fix Broken Features

| Feature | Issue | Fix |
|---------|-------|-----|
| Badge command | Empty output | Debug render path |
| Triage dry-run tokens | Shows "~0 tokens" | Fix estimation formula |
| Typosquat h2/slab/socket2 | Levenshtein too naive | Add minimum package name length (>=4) or require distance ≤1 for short names |

### 1.4 Secrets Path Exclusions

Skip secrets scanning in:
- `.cursor/` (IDE plans)
- `.vscode/` (IDE config)
- `*.plan.md` (AI-generated plan files often contain example tokens)

Also: for `DEVICE_CREDENTIAL_KEY_PREFIX = "pos....ret."` and `ACCESS_TOKEN_KEY = "pos....oken"` — these are localStorage key NAMES, not secrets. The detection rule needs to distinguish between "variable holds a key name" vs "variable holds a secret value." Minimum entropy threshold for AST-detected assignments should filter these out.

---

## Layer 2: Compound Risk Scoring (The Main Event)

### 2.1 Finding Tiers

Replace flat severity with compound risk tiers:

```
CRITICAL — Active threat pattern
  Kill-chain combination + install hook
  Kill-chain combination + obfuscation
  Any capability + known malware advisory

HIGH — Dangerous combination
  credential_read + network (exfiltration)
  exec + network (dropper)
  env_access + network (secret leak)
  obfuscation + dynamic_loading

MEDIUM — Suspicious but contextual
  exec + fs_write (payload staging) — common in build tools
  dynamic_loading alone
  install_hook + exec (without network)

LOW — Expected for package category
  Build tools: exec, fs_write, network (expected)
  Test runners: exec, fs_read (expected)
  Web frameworks: network (expected)

INFO — Recorded but not displayed by default
  Single capability alone
  Pattern match in non-imported package
  Low-confidence regex match
```

### 2.2 Package Category Detection

Instead of allowlists for specific packages (axios can be compromised!), detect the CATEGORY:

```
BUILD_TOOL — if package is in devDependencies AND (
  has bin field OR
  name matches /webpack|vite|esbuild|rollup|parcel|turbo|tsup|swc/ OR
  depends on known build infra
)

TEST_RUNNER — if package is in devDependencies AND (
  name matches /jest|vitest|mocha|ava|tap|playwright|cypress/ OR
  has test-related bin commands
)

CLI_TOOL — if package has bin field AND is in devDependencies

RUNTIME_DEP — if package is in dependencies (not devDependencies)

TRANSITIVE — if package is not in any *Dependencies field
```

**Key insight from Socket:** They use download counts and popularity. We can use a SIMPLER signal: **is this package in devDependencies or dependencies?** Build tools in devDeps with exec+fs+network = normal. The SAME capabilities in a runtime dep = investigate.

**No allowlist.** If axios (a runtime dep) suddenly gains `exec` capability, it gets flagged as HIGH regardless of how popular it is. Category detection is structural, not name-based.

### 2.3 Reachability-Enhanced Pattern Findings

Currently reachability only affects capabilities output. Extend to ALL findings:

```
[Patterns]
  ACTION REQUIRED — 3 findings in packages your app imports:
    lodash@4.17.21 — process.binding() access (P017)
    → Your app imports lodash in 12 files

  BUILD TOOLS — 47 findings in devDependencies (not in production):
    esbuild, vite, rollup, etc.
    → These run during build only (use --verbose for details)

  DEEP DEPS — 12 findings in transitive dependencies:
    → Not directly imported; reachable only through dependency chain
```

### 2.4 Output Aggregation

**Deps: Group by package, not by advisory**

Before:
```
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-34x7-hfp2-rc4v
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-83g3-92jg-28cx
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-8qq5-rm4j-mr97
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-9ppj-qmqm-q256
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-qffp-2rhf-9h96
⚠ MEDIUM: tar 6.2.1 — No summary available → GHSA-r6q2-hw4h-h46w
```

After:
```
⚠ tar@6.2.1 — 6 medium advisories (GHSA-34x7, GHSA-83g3, +4 more)
  → Run npm audit fix or update tar
```

**Patterns: Group by rule + package**

Before: 212 lines of `eval()/exec() with decoded or variable input`

After:
```
✓ 47 packages use regex.exec() — benign (AST verified)
✗ child_process.exec() with variable input — 2 packages:
    shelljs@0.8.5 — 3 calls [HIGH: build tool, expected]
    suspicious-pkg@1.0.0 — 1 call [CRITICAL: runtime dep + network]
```

**Capabilities: Already good, just apply tiers**

The capabilities check already separates app-imported vs build-tool findings. Apply compound risk tiers to the app-imported section.

### 2.5 Scoring Recalibration

Current: Every finding counts equally. 68 medium CVEs = almost 0% on deps score.

New: Weight by compound risk tier:

```
Score = base_score * product(penalty_per_finding)

Where penalty =
  CRITICAL finding: 0.5  (halves score)
  HIGH finding:     0.85 (15% reduction)
  MEDIUM finding:   0.97 (3% reduction)
  LOW finding:      0.99 (1% reduction)
  INFO finding:     1.0  (no impact)
```

Example for POS app:
- Workflows: 1 unpinned action (MEDIUM) + 2 missing permissions (LOW) → ~90% → B+
- Deps: 68 medium advisories → 0.97^68 ≈ 0.13 → still low, but medium advisories shouldn't tank score this hard. Cap: minimum 30% if all findings are MEDIUM-or-below.
- Patterns: After AST fix, ~50 findings, mostly LOW/INFO → 85%+ → A/B range
- Secrets: 4 real findings (JWTs) → MEDIUM → ~90% → B+
- Hygiene: 2 findings (SECURITY.md, gitignore) → LOW → 95%+ → A
- Capabilities: 11 app-import findings, mostly MEDIUM (build-tool-like caps) → ~75% → B

**Estimated new grade: C+ to B-** — realistic for a project with real CVEs and some JWTs, but not demoralizing F.

---

## Layer 3: Version Intelligence (Future)

### 3.1 Capability Version Diffing

**The Capslock insight:** <2% of package updates introduce new capabilities. A new capability = strong anomaly signal.

**Design:**
```bash
depsec scan . --diff  # Compare current capabilities against last scan
```

Stores capability profiles in `.depsec/capabilities.json`:
```json
{
  "lodash@4.17.21": ["fs_read"],
  "axios@1.7.2": ["network"],
  "express@4.19.2": ["network", "fs_read"]
}
```

On next scan, if `axios@1.7.3` now has `["network", "exec", "env_access"]`:
```
CRITICAL — axios@1.7.3 gained 2 new capabilities since last scan:
  + exec (never present in any prior scanned version)
  + env_access (never present in any prior scanned version)
  Previously: [network] only
  → This is how the axios compromise manifested. Investigate immediately.
```

### 3.2 Provenance as Risk Multiplier

Check npm provenance attestation:
```
No provenance + dangerous capabilities → severity +1 level
Valid provenance + dangerous capabilities → no change
No provenance + no dangerous capabilities → info note only
```

Single npm registry call per package. Free signal.

### 3.3 Install-time Stratification (from Cerebro)

Capabilities in postinstall scripts are 3-5x more suspicious:
```
postinstall exec → CRITICAL (even without network)
regular code exec → MEDIUM (needs combination for escalation)
test code exec → INFO
```

---

## What We're NOT Building (YAGNI)

- **No package popularity/download count lookups** — requires npm API calls, stale quickly, and popular packages get compromised too (axios)
- **No AI/ML classifiers** — Socket has 3 AI models but they still turn off capability alerts by default. Our combination rules are explicit and auditable.
- **No runtime instrumentation** — Sandworm/LavaMoat approach. Our install-guard provides runtime monitoring where needed.
- **No public capability database** — Nice vision but needs community. Start with local capability profiles.
- **No SES compartments** — LavaMoat's enforcement model. Out of scope — we detect, we don't enforce.

---

## Key Decisions

1. **Behavioral layering as the architecture** — compound risk tiers, not flat severity
2. **Package CATEGORY detection, not package NAME allowlists** — devDependencies + bin field + name patterns determine expected capabilities. Axios in dependencies with exec = flagged regardless of popularity.
3. **Reachability applied to ALL findings** — not just capabilities. Every finding answers "does your app actually use this package?"
4. **Output aggregation by package** — deps grouped by package not advisory, patterns grouped by rule+package, capabilities already good
5. **Scoring recalibration** — compound risk tiers weight differently, MEDIUM-only findings can't tank to F
6. **No allowlists** — the axios lesson. Category detection is structural; individual package exceptions are a trap.
7. **Version diffing as future differentiator** — capability delta is the strongest zero-day signal, per Capslock research

## Open Questions

- Should we fetch npm provenance in Layer 2 or defer to Layer 3? (It's one HTTP call per package but adds latency)
- Should the `--verbose` flag show ALL findings (current behavior) or should there be a `--raw` flag for truly everything?
- For scoring: should devDependency findings count at all? Build tools with dangerous caps are "expected noise" — maybe they shouldn't affect the score.

---

## Implementation Priority

### Sprint 1: Layer 1 Quick Wins
- [ ] Fix P001 AST gating (gate regex on module presence)
- [ ] Add .tsbuildinfo, .cursor/, .svelte-kit/ to skip lists
- [ ] Fix badge empty output
- [ ] Fix triage dry-run token estimation
- [ ] Fix typosquat minimum name length
- [ ] Fix secrets path exclusions (.cursor/, key name vs key value)

### Sprint 2: Layer 2 Output Overhaul
- [ ] Package-level aggregation for deps (dedup advisories)
- [ ] Package-level aggregation for patterns (group by rule+package)
- [ ] Reachability-enhanced pattern output (app imports vs build tools vs transitive)
- [ ] Package category detection (devDeps, bin field, name patterns)
- [ ] Compound risk tiers for capabilities
- [ ] Scoring recalibration with tier-weighted penalties
- [ ] "Above the fold / below the fold" output format

### Sprint 3: Layer 3 Version Intelligence (Future)
- [ ] Capability profile storage (.depsec/capabilities.json)
- [ ] Capability version diffing (--diff flag)
- [ ] Provenance check as risk multiplier
- [ ] Install-time stratification

## Research Sources

- Socket.dev: 50 alert types, default policy ignores most capabilities, no compound rules
- Google Capslock: <2% of updates introduce new capabilities, boltdb-go detection
- Sandworm: TOFU capability baseline from test runs
- LavaMoat: Per-package SES compartments with policy.json
- Cerebro (ACM TOSEM 2025): Behavior sequences, install-time stratification, 16-feature taxonomy
- OpenSSF Scorecard: Package health scoring, BigQuery dataset
- OpenSSF Package Analysis: gVisor sandbox detonation, strace capture
- Phylum/Veracode: ML behavioral analysis, registry firewall
- DataDog GuardDog: Semgrep + YARA rules, open-source
- SLSA/npm Provenance: Sigstore attestations, build reproducibility

## Next Steps

→ `/workflows:plan` for Sprint 1 + Sprint 2 implementation details
→ Re-run POS scan after Sprint 1 to validate noise reduction
→ Re-run POS scan after Sprint 2 to validate output quality
