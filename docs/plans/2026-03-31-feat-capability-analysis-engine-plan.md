---
title: "feat: Per-Package Capability Analysis Engine"
type: feat
date: 2026-03-31
brainstorm: docs/brainstorms/2026-03-31-capability-analysis-brainstorm.md
---

# feat: Per-Package Capability Analysis Engine

## Overview

Add a new `capabilities` check module that scans each dependency package to build a capability profile (network, filesystem, exec, env, etc.) and flags dangerous capability combinations that indicate supply chain threats. Also extend P013 for dynamic `import()` and add P018/P019 for `process.binding`/`vm` evasion patterns.

## Problem Statement

v0.9.0 catches known malware patterns but is still pattern-dependent. A capability-based approach asks "what can this package DO?" instead of "what does this code look like?" — catching threats regardless of obfuscation technique.

## Implementation Plan

### Phase 1: New Check Module — `src/checks/capabilities.rs`

Create `CapabilitiesCheck` implementing the `Check` trait.

#### 1a. Capability Detection

For each package in `node_modules/`, scan all `.js`/`.mjs`/`.cjs` files and detect:

```rust
struct PackageCapabilities {
    name: String,
    network: bool,      // C1: imports http/https/net/dgram/dns/fetch/axios/node-fetch/request
    fs_read: bool,      // C2: imports fs + readFile/readFileSync/createReadStream
    fs_write: bool,     // C3: imports fs + writeFile/writeFileSync/copyFile/rename
    shell_exec: bool,   // C4: imports child_process + exec/spawn methods
    env_access: bool,   // C5: process.env access
    credential_read: bool, // C6: fs read targeting ~/.ssh, ~/.aws, etc.
    install_hook: bool, // C7: postinstall/preinstall in package.json
    dynamic_load: bool, // C8: require(variable) or import(variable) — from P013
    obfuscated: bool,   // C9: detected by P014/P017
}
```

**Import detection approach** — scan each file for:
```rust
const NETWORK_MODULES: &[&str] = &[
    "http", "https", "net", "dgram", "dns", "http2",
    "node:http", "node:https", "node:net", "node:dgram", "node:dns",
    "axios", "node-fetch", "request", "got", "superagent", "undici",
];

const EXEC_MODULES: &[&str] = &[
    "child_process", "node:child_process",
];

const FS_MODULES: &[&str] = &[
    "fs", "fs/promises", "node:fs", "node:fs/promises",
];
```

Use `content.contains()` for fast pre-filtering, then regex or AST for confirmation.

For C5 (env access): `content.contains("process.env")`
For C6 (credential read): reuse P004's sensitive path patterns
For C7 (install hook): reuse P016's package.json scan
For C8 (dynamic load): check if P013 fired for this package
For C9 (obfuscation): check if P014/P017 fired for this package

#### 1b. Combination Rules

```rust
struct CombinationRule {
    name: &'static str,
    required: &'static [Capability],   // ALL must be present
    severity: Severity,
    message: &'static str,
}

const COMBINATION_RULES: &[CombinationRule] = &[
    // CRITICAL — Active threat patterns
    CombinationRule {
        name: "credential-exfiltration",
        required: &[Capability::CredentialRead, Capability::Network],
        severity: Severity::Critical,
        message: "reads credential files AND makes network requests — potential exfiltration",
    },
    CombinationRule {
        name: "dropper",
        required: &[Capability::ShellExec, Capability::Network],
        severity: Severity::Critical,
        message: "executes shell commands AND makes network requests — potential dropper",
    },
    CombinationRule {
        name: "install-exec",
        required: &[Capability::InstallHook, Capability::ShellExec],
        severity: Severity::Critical,
        message: "install script with shell execution — common malware entry vector",
    },
    CombinationRule {
        name: "install-network",
        required: &[Capability::InstallHook, Capability::Network],
        severity: Severity::High,
        message: "install script with network access — review for second-stage downloads",
    },
    CombinationRule {
        name: "obfuscated-dynamic",
        required: &[Capability::DynamicLoad, Capability::Obfuscated],
        severity: Severity::Critical,
        message: "dynamic loading with obfuscation — capabilities hidden, likely malicious",
    },
    CombinationRule {
        name: "env-exfiltration",
        required: &[Capability::EnvAccess, Capability::Network],
        severity: Severity::High,
        message: "accesses environment variables AND makes network requests — potential secret exfiltration",
    },
    CombinationRule {
        name: "payload-staging",
        required: &[Capability::FsWrite, Capability::ShellExec],
        severity: Severity::High,
        message: "writes files AND executes commands — potential payload staging",
    },
    // Dynamic load + ANY other capability
    CombinationRule {
        name: "dynamic-with-capability",
        required: &[Capability::DynamicLoad, Capability::InstallHook],
        severity: Severity::High,
        message: "dynamic loading in package with install hook — hidden capabilities",
    },
];
```

#### 1c. Allowlist

Built-in allowlist for known packages with expected capabilities:

```rust
const CAPABILITY_ALLOWLIST: &[(&str, &[Capability])] = &[
    ("express", &[Capability::Network]),
    ("koa", &[Capability::Network]),
    ("fastify", &[Capability::Network]),
    ("axios", &[Capability::Network]),  // the legit version
    ("node-fetch", &[Capability::Network]),
    ("got", &[Capability::Network]),
    ("esbuild", &[Capability::ShellExec, Capability::FsWrite]),
    ("node-gyp", &[Capability::ShellExec, Capability::Network, Capability::FsWrite]),
    ("prisma", &[Capability::Network, Capability::FsWrite, Capability::ShellExec]),
    ("dotenv", &[Capability::FsRead, Capability::EnvAccess]),
    ("husky", &[Capability::ShellExec, Capability::FsWrite]),
];
```

Also support user-defined allowlist in `depsec.toml`:
```toml
[capabilities.allow]
"@my-org/http-client" = ["network"]
"my-build-tool" = ["exec", "fs_write"]
```

#### 1d. Finding Output

Per-package findings with rule ID `DEPSEC-CAP:combination-name`:

```
DEPSEC-CAP:credential-exfiltration  CRITICAL  Package 'evil-pkg' reads credential files AND makes network requests
  Capabilities: [network, fs_read, credential_read, install_hook]
  Suggestion: Remove this package immediately — credential exfiltration pattern detected
```

### Phase 2: Gap Fixes — P013 import() + P018/P019

#### 2a. Extend P013 for Dynamic `import()`

In `src/ast/javascript.rs`, add to `find_dynamic_require()`:

```scheme
;; Also match import() with non-literal argument
(call_expression
  function: (import) @fn
  arguments: (arguments . (_) @arg))
```

Note: In tree-sitter, dynamic `import()` is a `call_expression` with `function: (import)`. Same logic as require — flag if argument is not a string literal.

**Tests:**
- `test_dynamic_import_variable` — `import(x)` → P013
- `test_static_import_not_flagged` — `import('fs')` → no finding

#### 2b. P018: Node.js Internal Binding Access

```rust
PatternRule {
    rule_id: "DEPSEC-P018",
    name: "Node Internal Binding",
    description: "Direct access to Node.js internal bindings — bypasses require() completely",
    suggestion: "process.binding() is almost never used in userland — investigate immediately",
    pattern: r"process\.(binding|_linkedBinding)\s*\(",
    severity: Severity::Critical,
    confidence: Confidence::High,
}
```

#### 2c. P019: VM Module Code Execution

```rust
PatternRule {
    rule_id: "DEPSEC-P019",
    name: "VM Code Execution",
    description: "vm module used to execute arbitrary code strings",
    suggestion: "vm.runInThisContext/compileFunction can execute obfuscated payloads — review the code being executed",
    pattern: r"vm\.(runInThisContext|runInNewContext|compileFunction|createScript)\s*\(",
    severity: Severity::High,
    confidence: Confidence::Medium,
}
```

### Phase 3: Config Integration

Add to `src/config.rs`:

```rust
#[derive(Debug, Default, Deserialize)]
pub struct CapabilitiesConfig {
    #[serde(default)]
    pub allow: HashMap<String, Vec<String>>,  // package → allowed capabilities
}
```

Add `capabilities: CapabilitiesConfig` to the main `Config` struct.

### Phase 4: Wire Into Scanner

In `src/scanner.rs` or wherever checks are registered, add `CapabilitiesCheck` to the check list. It runs as part of the standard `depsec scan` command.

The capabilities check should run AFTER the patterns check, because it can leverage P013/P014/P017 findings for C8/C9 detection.

## Acceptance Criteria

### Functional

- [ ] Capability profiles built for each package in node_modules
- [ ] 8 combination rules detect dangerous capability patterns
- [ ] Built-in allowlist for 10+ common packages
- [ ] User allowlist from `depsec.toml` respected
- [ ] P013 catches dynamic `import()` alongside `require()`
- [ ] P018 catches `process.binding()` and `process._linkedBinding()`
- [ ] P019 catches `vm.runInThisContext()` and related

### Quality

- [ ] All existing 317 tests still pass
- [ ] 10+ new tests for capability detection
- [ ] Tests for each combination rule
- [ ] Tests for allowlist (both built-in and user-defined)
- [ ] `cargo fmt` + `cargo clippy` clean

### Validation

- [ ] Run against a project with express (should show network capability, no alert)
- [ ] Run against test payload mimicking axios attack (should show Critical combo)
- [ ] Run against clean lodash (should show no capabilities)

## File Changes

| File | Changes |
|------|---------|
| `src/checks/capabilities.rs` | **NEW** — CapabilitiesCheck, capability detection, combination rules, allowlist |
| `src/checks/mod.rs` | Register CapabilitiesCheck |
| `src/checks/patterns.rs` | Add P018, P019 to PATTERN_RULES |
| `src/ast/javascript.rs` | Extend P013 for dynamic import() |
| `src/config.rs` | Add CapabilitiesConfig |
| `src/scanner.rs` | Wire CapabilitiesCheck into scan pipeline |
| `src/rules.rs` | Update rule count |

## References

- [Brainstorm](../brainstorms/2026-03-31-capability-analysis-brainstorm.md)
- [Zero-day detection plan](2026-03-31-feat-zero-day-detection-engine-plan.md)
- [Socket capability detection](https://docs.socket.dev/docs/package-issues)
- Existing patterns: `src/checks/patterns.rs`, `src/ast/javascript.rs`
