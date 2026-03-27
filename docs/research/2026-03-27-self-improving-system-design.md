# Self-Improving System Design

How depsec can adapt to new attacks without manual code changes.

## The Honest Assessment

| Layer | Current State | Self-Improving? |
|-------|--------------|-----------------|
| CVE detection (OSV) | Queries live API | **YES** — new CVEs appear automatically |
| Malicious package detection | Not implemented | **COULD BE** — OSV has 223K+ MAL- entries |
| Code patterns (P001-P008) | Hardcoded regex | **NO** — requires code change + recompile |
| Workflow rules (W001-W005) | Hardcoded checks | **NO** — same |
| Secret patterns (S001-S020) | Hardcoded regex | **NO** — same |
| Network baseline | User-defined hosts | **PARTIALLY** — learns per project over time |

**Bottom line: 1 out of 6 detection layers is currently adaptive.**

---

## Three Levels of Self-Improvement

### Level 1: Live Feeds (achievable now)

#### 1a. Malicious Package Blocklist

The OpenSSF database has **223,794** known malicious packages with `MAL-*` IDs in OSV format. We ALREADY query OSV for CVEs. With a small change, we also check if any installed package is KNOWN MALWARE.

```
Current:  "Is lodash@4.17.21 vulnerable?" → OSV returns CVEs
Upgrade:  "Is evm-oracle@1.0.0 malicious?" → OSV returns MAL-2024-8901
```

This is essentially FREE — we already have the OSV integration. We just need to also report `MAL-*` advisories alongside `GHSA-*` / `RUSTSEC-*` ones.

**Self-improving?** YES. Every time Socket/Snyk/OpenSSF discovers a new malicious package, it gets added to OSV. Our next scan picks it up automatically.

#### 1b. Known-Malicious Host Blocklist

Maintain a list of known C2 domains and IPs that we check network baselines against:
```json
{
  "known_malicious_hosts": [
    "83.142.209.203",
    "models.litellm.cloud",
    "checkmarx.zone",
    "103.106.67.63"
  ],
  "known_malicious_patterns": [
    "169.254.169.254",
    "169.254.170.2"
  ]
}
```

This could be a simple JSON file hosted on our GitHub repo that `depsec` fetches periodically. Like antivirus signature updates, but for network indicators.

**Self-improving?** YES, with a community contribution model. When a new attack is discovered, anyone can PR a new IP/domain to the blocklist.

### Level 2: Dynamic Rules (medium effort)

#### 2a. External Rule Files

Instead of hardcoding patterns in Rust, load them from a `.depsec/rules/` directory:

```toml
# .depsec/rules/pth-persistence.toml
[rule]
id = "DEPSEC-P009"
name = ".pth file with executable code"
severity = "critical"
description = "Python .pth startup hooks can execute code on every interpreter launch"

[rule.match]
file_pattern = "*.pth"
content_patterns = ["subprocess", "exec(", "eval(", "base64", "import os"]
```

Users can add their own rules. The community shares rules. We ship a default ruleset that gets updated from GitHub.

```bash
depsec rules update  # Pull latest rules from github.com/chocksy/depsec-rules
depsec rules list    # Show all active rules
depsec rules add ./my-custom-rule.toml
```

**Self-improving?** YES — rules evolve independently of the binary. New attack discovered → new rule file → `depsec rules update` → detected.

#### 2b. Behavioral Baselining (depsec monitor)

Every time `depsec monitor npm install` runs, it records what happened:
```json
{
  "project": "my-app",
  "timestamp": "2026-03-27T18:00:00Z",
  "command": "npm install",
  "connections": [
    {"host": "registry.npmjs.org", "port": 443, "process": "npm"},
    {"host": "github.com", "port": 443, "process": "npm"}
  ]
}
```

Over multiple runs, this builds a behavioral profile. The system learns what's "normal" for THIS project. When something new appears, it alerts — not because a regex matched, but because the BEHAVIOR changed.

**Self-improving?** YES — learns from every run. Gets smarter about YOUR specific project over time.

### Level 3: Community Intelligence (ambitious, high impact)

#### 3a. Anonymous Telemetry (opt-in)

If users opt in, `depsec` sends anonymized scan summaries:
```json
{
  "ecosystem": "npm",
  "package_count": 142,
  "findings_by_rule": {"W001": 3, "S001": 0, ...},
  "network_hosts_seen": ["registry.npmjs.org", "github.com"]
}
```

When enough users report data, we can detect anomalies:
- "99% of projects using `lodash` never see network calls to raw IPs during install. Your project does."
- "Package `xyz` was flagged by 47 users in the last hour."

**Self-improving?** YES — gets smarter as more people use it. Network effect.

#### 3b. Crowd-Sourced Baselines

Instead of every user building their own baseline, share community baselines:
```bash
depsec baseline pull npm  # Get community-verified baseline for npm ecosystem
```

"For a standard Node.js project, these are the only hosts your npm install should contact."

---

## The "Zero Dependencies" Challenge

You said the "own your security" story needs near-zero deps to be credible. Current state:

| Dep | Why We Need It | Transitive Count | Can We Remove? |
|-----|---------------|-------------------|----------------|
| clap | CLI parsing | ~7 | MAYBE — use manual arg parsing |
| ureq | HTTP client (OSV, GitHub API) | ~15 | NO — need HTTP/TLS |
| regex | Pattern matching | ~3 | NO — core functionality |
| serde + serde_json | JSON parsing | ~4 | NO — OSV API is JSON |
| toml | Config parsing | ~5 | MAYBE — manual TOML parsing |
| sha2 | Hash verification | ~5 | MAYBE — use ring (already pulled by ureq) |
| walkdir | Directory traversal | ~2 | MAYBE — use std::fs directly |
| anyhow + thiserror | Error handling | ~2 | MAYBE — use std::io::Error |

**Realistic minimum: ~50 crates** (ureq+regex+serde is the floor — HTTP+TLS+JSON+regex are non-negotiable).

**Alternative credibility approach:** Instead of minimizing deps, PROVE they're clean:
```bash
depsec self-check

# DepSec Self-Integrity Report
# Binary: depsec v0.1.0 (sha256: abc123...)
# Build: reproducible (SLSA L3)
# Dependencies: 98 crates, 0 advisories, 0 malicious (checked via OSV)
# Licenses: all permissive (MIT, Apache-2.0, ISC, BSD-3, Unicode-3.0, CDLA-2.0)
# Sources: all from crates.io (verified via deny.toml)
# Last audit: 2026-03-27
```

The message isn't "we have zero deps" — it's "we audit our own deps with the same tool we ask you to use, and HERE'S THE PROOF."

---

## The Adaptive Architecture

Here's how all the pieces fit together:

```
┌─────────────────────────────────────────────┐
│                  depsec CLI                   │
│                                               │
│  ┌─────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ Static  │  │ Dynamic  │  │  Runtime     │ │
│  │ Rules   │  │ Feeds    │  │  Monitor     │ │
│  │ (built  │  │ (fetched │  │  (observes   │ │
│  │  in)    │  │  live)   │  │   behavior)  │ │
│  └────┬────┘  └────┬─────┘  └──────┬──────┘ │
│       │            │               │         │
│  P001-P008    ┌────┴─────┐   ┌─────┴──────┐ │
│  W001-W005    │ OSV API  │   │ ss -tnp    │ │
│  S001-S020    │ (CVEs +  │   │ /proc/net  │ │
│  H001-H004    │  MAL-*)  │   │ process    │ │
│               │          │   │ attribution│ │
│               │ Rules    │   │            │ │
│               │ repo     │   │ Behavioral │ │
│               │ (GitHub) │   │ baseline   │ │
│               │          │   │ (learns)   │ │
│               │ C2 host  │   │            │ │
│               │ blocklist│   └────────────┘ │
│               └──────────┘                   │
│                                               │
│  Self-check: depsec audits its own deps      │
│  Reproducible build: same source = same binary│
│  All deps from crates.io, all licenses clean  │
└─────────────────────────────────────────────┘

Three layers of improvement:
1. Static rules: updated by us (code releases)
2. Dynamic feeds: updated by community (OSV + rules repo + blocklist)
3. Behavioral learning: updated by YOUR usage (baselines that get smarter)
```

---

## What Makes This "GOD Mode"

Traditional scanner: "Here are today's findings based on patterns we coded last month."

Adaptive depsec:
- **Yesterday's attacks:** OSV feed catches them (223K+ known malicious packages)
- **Today's attacks:** Network monitor catches anomalous behavior in real-time
- **Tomorrow's attacks:** Behavioral baselines alert when ANYTHING changes, even attacks we've never seen

The behavioral layer is the key. You don't need to know WHAT the attack looks like. You just need to know that your `npm install` suddenly connects to an IP it never connected to before. That's the signal. The attack is novel? Doesn't matter. The BEHAVIOR is anomalous.

**That's the self-improving system: not smarter rules, but smarter baselines.**

---

## Proving We're Pristine (Trust Chain for depsec itself)

For the "own your security" story to work, we need to demonstrate:

1. **98 transitive deps, 0 advisories, 0 malicious** — we scan ourselves every CI run (already doing this)
2. **All deps from crates.io** — enforced by deny.toml (already doing this)
3. **All licenses clean** — enforced by deny.toml (already doing this)
4. **Network connections audited** — our CI monitors what our build does (already doing this)
5. **Reproducible builds** — same source always produces same binary (not yet)
6. **SLSA attestation** — cryptographic proof the binary came from this source (not yet)
7. **Minimal deps with explanation** — document WHY each dep exists and what it brings

The README should have a "Why should you trust depsec?" section that shows all of this. Transparency IS the product.
