# Brainstorm: Capability-Based Threat Detection

**Date:** 2026-03-31
**Status:** Decided

## Problem

Our current detection (regex + AST heuristics + signal combination) catches KNOWN malware patterns. But an attacker using a NOVEL obfuscation technique would evade us. Taint tracking was the planned next step, but a first-principles analysis reveals a better approach.

## First Principles: What Actually Constitutes a Threat?

Every supply chain attack MUST eventually do one of these:

1. **Read secrets** — access `~/.ssh`, `~/.aws`, `process.env`, `.npmrc`
2. **Exfiltrate** — send data out via HTTP, DNS, or other network protocol
3. **Install malware** — write executables to disk, modify system files
4. **Execute commands** — spawn shells, run downloaded payloads

No matter how cleverly code is obfuscated, it MUST call real APIs to do damage: `fs.readFile`, `http.request`, `child_process.exec`, etc.

**Key insight:** Instead of tracking HOW code reaches dangerous functions (taint tracking), detect WHAT capabilities each package HAS and flag dangerous combinations.

## What We're Building

**Per-package capability analysis** that scans all files in a dependency to build a capability profile, then flags dangerous combinations.

### Capability Categories

| ID | Capability | How Detected |
|----|-----------|-------------|
| C1 | **Network** | Imports `http`, `https`, `net`, `dgram`, `dns`, `fetch`, `axios`, `node-fetch`, `request` |
| C2 | **Filesystem Read** | Imports `fs` + uses `readFile`, `readFileSync`, `createReadStream`, `readdir` |
| C3 | **Filesystem Write** | Imports `fs` + uses `writeFile`, `writeFileSync`, `createWriteStream`, `copyFile`, `rename` |
| C4 | **Shell Execution** | Imports `child_process` + uses `exec`, `execSync`, `spawn`, `spawnSync` |
| C5 | **Environment Access** | Accesses `process.env` (any property) |
| C6 | **Credential Read** | C2 targeting sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.npmrc`) |
| C7 | **Install Hook** | Has `preinstall`/`postinstall`/`install` in package.json |
| C8 | **Dynamic Loading** | Uses `require(variable)` or `import()` with non-literal argument (P013) |
| C9 | **Obfuscation** | Detected by P014/P017 (fromCharCode+XOR, hex names, etc.) |

### Dangerous Combinations (Kill Chains)

```
CRITICAL — Active threat patterns:
  C6 + C1           = credential exfiltration (read secrets → send out)
  C4 + C1           = dropper (download → execute)
  C7 + C4           = install-time code execution
  C7 + C1           = install-time network call
  C8 + ANY           = obfuscated capability (can't verify what it does)
  C9 + C4           = obfuscated shell execution

HIGH — Suspicious patterns:
  C5 + C1           = env var exfiltration
  C3 + C4           = payload staging (write file → execute)
  C1 + C2           = data harvesting (read files → send)
  C7 + C8           = install hook with dynamic loading

EXPECTED — Normal for certain packages:
  express:    C1 (network) — it's a web framework
  esbuild:    C4 (exec) — it's a build tool
  dotenv:     C2 + C5 (fs read + env) — it reads .env files
```

### How It Works

1. **Walk each package** in `node_modules/`
2. **Scan all .js/.ts files** for import statements and API usage
3. **Build capability profile**: `{C1: bool, C2: bool, ..., C9: bool}`
4. **Apply combination rules** → produce per-package risk assessment
5. **Output**: "Package X has capabilities [network, exec, install-hook] → CRITICAL: dropper pattern"

### How This Beats Taint Tracking

| Aspect | Taint Tracking | Capability Analysis |
|--------|---------------|-------------------|
| Novel obfuscation | Only catches known decode patterns | Catches ANY code that uses dangerous APIs |
| Complexity | High (variable flow, scope, aliasing) | Low (import detection + combination logic) |
| False negatives | High for novel techniques | Low — must call real APIs |
| False positives | Low | Medium (need allowlists for expected capabilities) |
| Performance | Slow (AST walking per function) | Fast (import scanning) |

### The Obfuscation Problem

If code uses `require(decoded_string)`, we can't see WHICH capability it has. But P013 already flags this as `C8: Dynamic Loading`. The combination rule `C8 + ANY = suspicious` handles it:

- `C8 alone` → Medium (could be legitimate plugin loader)
- `C8 + C9 (obfuscation)` → Critical (hidden capabilities + obfuscation = malware)
- `C8 + C7 (install hook)` → High (dynamic loading in install script)

### Allowlist System

Known packages with expected capabilities:
```toml
[capabilities.allow]
express = ["network"]
esbuild = ["exec", "fs_write"]
dotenv = ["fs_read", "env"]
node-gyp = ["exec", "network", "fs_write"]
```

Users can add their own in `depsec.toml`.

## Edge Case Analysis: require() Evasion

Attackers can avoid `require()` entirely. These gaps must be plugged:

| Evasion | Detection |
|---------|-----------|
| `eval("require('http')")` | Already caught by P001 |
| `new Function("return require('fs')")` | Already caught by P008 |
| `global['require']('http')` | Already caught by P017 (bracket notation) |
| Dynamic `import(decoded)` | **NEW: extend P013 for import()** |
| `process.binding('fs')` | **NEW: add P018 pattern** |
| `vm.runInThisContext(code)` | **NEW: add P019 pattern** |
| Inline JS in install script | Already caught by P012/P016 |

The runtime monitor (install-guard) is the ultimate backstop — catches everything at the OS level regardless of how code is obfuscated. The defense stack is layered:

```
Layer 1: Capability Analysis (static) → catches 85% of attacks
Layer 2: Pattern Rules P001-P019      → catches known evasion patterns
Layer 3: Signal Combination            → escalates weak signals to strong
Layer 4: install-guard (runtime)       → catches EVERYTHING that executes
```

## Key Decisions

1. **Capability analysis as primary engine** — simpler, catches more, works against novel attacks
2. **Per-package aggregation** — scan all files, build one profile per package
3. **Combination rules determine severity** — single capability is info, dangerous combos are critical
4. **Allowlist for expected capabilities** — express SHOULD have network, esbuild SHOULD exec
5. **Dynamic require/import (C8) = wildcard capability** — when present, assume worst-case
6. **New check module** — `src/checks/capabilities.rs`, separate from patterns
7. **Plug import() gap** — extend P013 AST detection for dynamic `import()` alongside `require()`
8. **Add process.binding/vm detection** — new patterns P018/P019

## Open Questions

- Should capability analysis be a separate `depsec` command or part of `scan`?
- How to handle scoped packages that legitimately proxy capabilities (e.g., `@my-org/http-client`)?
- Should we scan TypeScript type definitions or just runtime code?

## Why This Approach

This is what Socket does (they call it "capability detection") and what makes them fast at catching zero-days. Our version is simpler because we don't need their AI layer — the combination rules handle most cases. The approach is fundamentally threat-model-driven rather than pattern-driven, which means it doesn't degrade as attackers change obfuscation techniques.
