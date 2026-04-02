---
date: 2026-04-02
topic: hornets-nest-adversarial-testing
---

# Hornets Nest: Adversarial Testing Suite for depsec

## What We're Building

A comprehensive adversarial test suite ("Hornets Nest") that stress-tests every layer of depsec — both static analysis (`depsec scan`) and runtime protection (`depsec protect`) — using locally-crafted malicious packages that simulate real-world attack techniques and evasion strategies.

The suite produces a **detection matrix scorecard** showing exactly what depsec catches and what it misses, organized by attack layer.

## Why This Approach

- The current benchmark (`scripts/benchmark.sh`) only tests `depsec scan` against the Datadog dataset — 100% detection is suspicious because depsec's patterns were tuned to those samples
- The `depsec protect` pipeline (sandbox + canary + network monitor + kill chain) has **zero automated adversarial testing**
- Real attackers actively evade detection tools (see: [GuardDog evasion writeup](https://medium.com/@heyyoad/how-we-evaded-datadogs-malicious-package-detection-lessons-for-better-security-e8c9b185f97e))
- No existing tool tests both static scan AND runtime sandbox/canary protection together

## Prior Art

| Project | Useful for |
|---|---|
| [NPM-Threat-Emulation](https://github.com/MHaggis/NPM-Threat-Emulation) | Closest to our concept — 9 safe attack scenarios with fake creds + mock server |
| [OSCAR](https://github.com/security-pride/OSCAR) | Dynamic analysis benchmark (500 malicious + 1500 benign per ecosystem) |
| [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | Reference architecture for sandboxed package execution |
| [GuardDog](https://github.com/DataDog/guarddog) | Competitor with known evasion gaps |
| [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) | 174 deeply documented attack trees |
| [MalwareBench](https://github.com/MalwareBench) | Largest labeled benchmark (20,792 packages) |
| [OSC&R](https://pbom.dev/) | MITRE ATT&CK for supply chains — TTPs framework |
| [SAP Risk Explorer](https://github.com/SAP/risk-explorer-for-software-supply-chains) | 100+ attack vectors linked to real incidents |
| [Ladisa Taxonomy](https://arxiv.org/abs/2204.04008) | 107 unique vectors, 94 real incidents — academic gold standard |

## Architecture

```
tests/hornets-nest/
  README.md                        # Suite overview + how to run
  harness.rs                       # Cargo integration test orchestrator
  mock-server/                     # Tiny TCP/HTTP listener for exfil tests
  scorecard.rs                     # Detection matrix scorer + reporter
  packages/
    scan/                          # Packages testing depsec scan (static)
      hn-base64-eval/              # P002: atob → eval chain
      hn-char-code-xor/            # P014: fromCharCode + XOR
      hn-credential-read/          # P004: readFileSync ~/.ssh/id_rsa
      hn-dynamic-require/          # P013: require(variable)
      hn-env-stringify/            # P011: JSON.stringify(process.env)
      hn-imds-probe/               # P010: fetch 169.254.169.254
      hn-install-script-curl/      # P006: curl in postinstall.sh
      hn-new-function/             # P008: new Function(variable)
      hn-obfuscated-hex/           # P017: _0x identifiers + while(!![])
      hn-pth-persist/              # P009: .pth file with exec(base64...)
      hn-raw-ip-fetch/             # P003: HTTP call to raw IP
      hn-self-destruct/            # P015: unlinkSync(__filename)
      hn-stego-payload/            # P005: readFileSync on .png
      hn-vm-exec/                  # P019: vm.runInNewContext
      hn-python-subprocess/        # P021: subprocess.Popen(shell=True)
      hn-ruby-system/              # P031: system("cmd")
    protect/                       # Packages testing depsec protect (runtime)
      hn-canary-tamper/            # Reads + modifies ~/.ssh/id_rsa
      hn-canary-read-restore/      # Reads + restores (hash-match evasion)
      hn-exfiltrator/              # Reads creds + HTTP POST to mock server
      hn-imds-runtime/             # curls 169.254.169.254 in postinstall
      hn-env-exfil/                # process.env → HTTP POST
      hn-delayed-exec/             # setTimeout 5s then exfiltrate
      hn-clean-exfil/              # No static signals, just reads + POSTs
    evasion/                       # Packages designed to BYPASS detection
      # --- Static scan evasion ---
      hn-dynamic-property/         # E01: fs["read"+"File"+"Sync"]
      hn-proxy-wrap/               # E02: new Proxy(require('fs'), {})
      hn-import-alias/             # E03: const r = global.require
      hn-wasm-payload/             # E04: malicious WebAssembly
      hn-native-addon/             # E05: node-gyp C++ credential reader
      hn-multi-file-scatter/       # E06: logic split across 3+ files
      hn-large-bundle/             # E24: malicious code in >500KB file
      hn-mainmodule-require/       # E08: process.mainModule.require()
      hn-reflect-apply/            # E09: Reflect.apply(fs.readFileSync,...)
      hn-globalthis-eval/          # E10: globalThis["ev"+"al"](code)
      hn-dynamic-import/           # E15: import("child_"+"process")
      hn-indirect-require/         # E16: (0, require)(name)
      hn-global-function/          # E17: new global.Function(code)
      hn-alias-function/           # E18: const Fn = Function; new Fn()
      hn-create-require/           # E19: createRequire()(pkg)
      hn-fromcharcode-add/         # E20: fromCharCode + addition (not XOR)
      hn-pickle-deser/             # E21: pickle.loads(untrusted) Python
      hn-python-alias/             # E22: import subprocess as sp
      hn-ruby-pipe-open/           # E23: open("|cmd") Ruby
      hn-unicode-homoglyph/        # E13: evаl (Cyrillic а)
      hn-json-payload/             # E12: payload in .json loaded at runtime
      hn-getter-exec/              # E14: Object.defineProperty getter
      hn-prototype-pollution/      # E11: Object.prototype manipulation
      # --- Sandbox evasion ---
      hn-detect-home-mismatch/     # S01: $HOME vs /etc/passwd
      hn-detect-bwrap/             # S02: /proc/1/cmdline check
      hn-detect-dockerenv/         # S04: /.dockerenv check
      hn-detect-canary-path/       # S05: $HOME contains "depsec-canary"
      hn-detect-missing-dirs/      # S06: no .local, no browser dirs
      hn-env-steal/                # S11: process.env.GITHUB_TOKEN (no file)
      hn-staged-trojan/            # S10: clean install, malicious require()
      hn-path-injection/           # S09: project dir with special chars
      # --- Network evasion ---
      hn-dns-exfil/                # N01: data encoded in DNS queries
      hn-doh-exfil/                # N02: DNS-over-HTTPS
      hn-registry-piggyback/       # N03: POST to registry.npmjs.org
      hn-fast-exfil/               # N04: open+send+close < 100ms
      hn-unix-socket/              # N05: exfil via Unix domain socket
      hn-ipv6-exfil/               # N08: IPv6 connection
      hn-udp-exfil/                # N13: UDP datagram exfil
      hn-ptr-spoof/                # N12: PTR record → allowlist bypass
      hn-icmp-tunnel/              # N07: data in ICMP packets
      hn-file-stage/               # N09: write to node_modules/.cache
      # --- Canary evasion ---
      hn-read-no-modify/           # C11: read canary, don't change it
      hn-non-canary-docker/        # C04: read .docker/config.json
      hn-non-canary-kube/          # C04: read .kube/config
      hn-non-canary-gcloud/        # C04: read .config/gcloud/
      hn-env-var-creds/            # C07: process.env.AWS_ACCESS_KEY_ID
      hn-git-credential/           # C08: git credential fill
      hn-stat-mtime/               # C02: stat canary files, detect fresh
      hn-copy-then-read/           # C10: cp canary to /tmp, read from there
      # --- Kill chain evasion ---
      hn-perfect-evasion/          # K05: read+restore canary + expected host
      hn-dns-plus-read/            # K01: canary tamper + DNS (no TCP)
      hn-info-verdict/             # K06: unexpected conn + no canary = "clean"
  expected/
    scan.json                      # Expected findings per scan package
    protect.json                   # Expected verdicts per protect package
    evasion.json                   # Expected: these SHOULD be caught (initially many will be missed)
```

## Key Decisions

- **Local packages only**: No real registry interaction. Packages are tarballs or directory installs.
- **Mock exfil server**: A tiny TCP listener on localhost receives exfiltration attempts. Validates data was actually sent.
- **Three tiers**: `scan/` tests known-good detection, `protect/` tests runtime pipeline, `evasion/` finds blind spots.
- **Expected outcomes are versioned**: As we fix blind spots, we update `evasion.json` from "miss" to "detect".
- **CI-friendly**: Runs as `cargo test --test hornets_nest` with bwrap available on Linux CI.

## Scoring Model

```
Detection Matrix:
  Static Scan:      X/25 vectors  (pattern matching quality)
  Sandbox:          X/12 vectors  (isolation effectiveness)
  Network Monitor:  X/14 vectors  (exfiltration detection)
  Canary/Honeypot:  X/12 vectors  (credential access detection)
  Kill Chain:       X/6  vectors  (verdict accuracy)
  Supply Chain:     X/11 vectors  (meta-attack resistance)
  ─────────────────────────────────
  Overall:          X/80 vectors  (weighted by real-world prevalence)

Per-vector output:
  [DETECT]  hn-base64-eval        P002 Critical  (expected: detect, actual: detect)
  [MISS]    hn-dynamic-property   E01  High       (expected: detect, actual: miss)
  [EVADE]   hn-dns-exfil          N01  Critical   (expected: miss — known gap)
```

## Highest-Priority Vectors (Build First)

These represent the most realistic and dangerous attack combinations:

1. **K05: Perfect evasion** — read + restore canary + exfil on expected host → `Pass`
2. **S11 + N01: Env var theft + DNS exfil** — no file read, no TCP → `Pass`
3. **S10: Staged trojan** — clean install, malicious at `require()` time → never monitored
4. **N08: IPv6 exfil** — regex is IPv4-only → invisible connection
5. **E04: WASM payload** — zero static analysis → invisible malicious logic
6. **N14 + Docker: Any exfil inside Docker** — all monitoring disabled
7. **C01: Read + restore canary** — hash matches → zero tamper signal
8. **E22: Python alias evasion** — `import subprocess as sp` → P021 bypassed
9. **E24: Large bundle** — >500KB → skipped entirely
10. **K06: Info verdict = clean** — unexpected TCP + no canary → reported clean

## Open Questions

- Should we test against Python/pip packages too, or focus on npm first?
- Do we want the mock exfil server to be Rust (in the test harness) or a simple netcat/socat?
- Should evasion test failures block CI, or just report the scorecard?
- How do we handle the Docker sandbox tests in CI without Docker-in-Docker?

## Next Steps

→ `/workflows:plan` for implementation details — package structure, test harness, CI integration
