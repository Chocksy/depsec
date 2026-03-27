# Competitive Landscape & Network Differentiation Strategy

## The Landscape — Who Does What

### Static Analysis (code scanning)

| Tool | Language | Ecosystem Coverage | # Rules | Our Overlap |
|------|----------|-------------------|---------|-------------|
| **zizmor** | Rust | GitHub Actions ONLY | 34 | HIGH — 5 of our W rules overlap with their 34 |
| **GuardDog** | Python | PyPI, npm, Go, Ruby, GH Actions, VSCode | 40+ | MEDIUM — we share eval/base64/exfil patterns, miss typosquatting/metadata |
| **pip-audit** | Python | PyPI only | N/A (uses OSV) | HIGH — same approach as our deps.rs |
| **cargo-deny** | Rust | Rust only | N/A (advisories+licenses) | HIGH — we use it in our own CI |
| **depsec** | Rust | All 5 ecosystems + GH Actions | 33 rules | — |

**Verdict:** For static analysis, zizmor CRUSHES us on GitHub Actions (34 rules vs our 5). GuardDog has heuristics we lack (typosquatting, metadata). But nobody does ALL ecosystems in one binary like us.

### Network Monitoring (runtime)

| Tool | Approach | Where It Runs | Open Source? |
|------|----------|---------------|-------------|
| **StepSecurity harden-runner** | eBPF/agent on GH Actions runner | CI only | Freemium (cloud dashboard) |
| **Socket Firewall (sfw)** | HTTP proxy wrapping package managers | Developer machine + CI | Yes (CLI), No (API) |
| **Garnet/Jibril** | eBPF kernel sensors, sandbox detonation | Lab/cloud | No (commercial) |
| **Tracee** | eBPF runtime security | Kubernetes/containers | Yes (Aqua) |
| **OpenSnitch** | eBPF application firewall | Linux desktop/server | Yes |
| **depsec** | tcpdump + baseline diffing | CI | Yes |

**Verdict:** Our tcpdump approach is the SIMPLEST. Everyone else requires eBPF, agents, or cloud APIs. But simple = limited. We capture IPs but can't attribute them to specific processes or steps.

---

## Where Each Tool Wins (and Where We Can Win)

### zizmor wins on: GitHub Actions depth
They have 34 rules covering cache poisoning, impostor commits, ref confusion, GITHUB_ENV writes, container credentials, Dependabot config, obfuscated uses paths. We have 5 rules.

**But:** They ONLY do GitHub Actions. No deps, no secrets, no patterns, no network. One file type.

### GuardDog wins on: Package-level heuristics
Typosquatting detection, metadata analysis (empty description, version 0.0.0, unclaimed email domains, repository integrity mismatch, bundled binaries). These are package-LEVEL signals, not code patterns.

**But:** Requires Python + Semgrep installed. Not a single binary. No GitHub Actions analysis. No network monitoring.

### Harden-Runner wins on: CI network monitoring
Per-step network attribution, auto-generated baselines, egress blocking in real-time. They correlate connections to specific workflow steps.

**But:** GitHub Actions only. Requires their cloud dashboard for full features. Not self-contained — needs an account.

### Socket Firewall wins on: Pre-install interception
Blocks malicious packages BEFORE they're installed. Network proxy approach = no code touches your machine.

**But:** Requires their API (freemium). Cached packages bypass it. No static analysis of what's already installed.

---

## Our Unique Position

Nobody else does ALL of these in one tool:
1. Multi-ecosystem dependency scanning (5 parsers)
2. GitHub Actions hardening
3. Secret detection
4. Malicious code pattern scanning
5. Network baseline monitoring
6. Auto-fix capabilities
7. Single static binary, zero runtime dependencies

**The gap we should own: network monitoring that's SELF-CONTAINED.**

Harden-runner needs a cloud account. Socket needs their API. Garnet is commercial. OpenSnitch needs eBPF/root.

What if we could do process-attributed network monitoring using only what's available on a standard CI runner?

---

## Network Monitoring: Where We Can Go

### Level 1 (Current): tcpdump + baseline
**What we do:** Capture all IPs during build, diff against allowed hosts.
**Weakness:** No per-process attribution. Can't tell if npm or cargo made the connection.

### Level 2 (Achievable): Process-aware capture
**Approach:** Instead of raw tcpdump, use `/proc/net/tcp` + `/proc/*/fd` correlation on Linux. Or `ss -tnp` which shows PID per connection.
**What this gives us:** "Process `npm install` connected to 83.142.209.203" — not just "something connected to 83.142.209.203."
**Effort:** Replace tcpdump with a small monitoring loop that polls `ss -tnp` every 100ms.

### Level 3 (Advanced): Sandboxed install monitoring
**Approach:** Run `npm install` / `pip install` inside a network-monitored sandbox. Record every outbound connection. Compare against expected registry hosts.
**What this gives us:** "During `npm install`, package `sketchy-pkg` connected to raw IP 83.142.209.203 on port 8080."
**Effort:** Significant. Need process isolation (namespaces or containers).

### Level 4 (Ambitious): eBPF-based monitoring
**Approach:** Ship a small eBPF program that attaches to kernel network hooks. Perfect per-process attribution.
**What this gives us:** Garnet/Harden-runner level visibility without their cloud dependency.
**Effort:** Very high. eBPF requires kernel headers and compilation.

### Recommendation: Level 2 is the sweet spot
`ss -tnp` is available on every Linux CI runner. No root needed for audit mode. We can correlate PIDs with process names. This alone would be a significant upgrade from raw tcpdump — and nobody else offers this in a self-contained binary.

---

## Attack Vectors Only Network Monitoring Can Catch

These attacks are INVISIBLE to static analysis but VISIBLE on the network:

| Attack | Network Signal | Static Analysis Catches? |
|--------|---------------|-------------------------|
| IMDS credential theft | Connection to 169.254.169.254 | Only if code has literal URL |
| C2 check-in | Periodic connections to unknown domains | No |
| DNS exfiltration | Unusual DNS queries | No |
| Encrypted data exfiltration | Large upload to new domain | No |
| Reverse shell | Outbound TCP to unusual port | No |
| Package install-time phone-home | Connection during `npm install` | No |
| Steganographic C2 resolution | HTTPS to Pastebin/Vercel | No (looks like legitimate traffic) |

**This is why network monitoring is our differentiator — it catches an entire CLASS of attacks that no amount of regex scanning will ever find.**

---

## Brainstorm: Novel Network Features

### 1. "Install Monitor" mode
```bash
depsec monitor npm install
```
Wraps any command, captures all network connections made during execution, reports unexpected ones. Like Socket Firewall but without requiring their API — we use our own baseline.

### 2. Process-attributed baseline
```json
{
  "version": 2,
  "allowed": {
    "npm": ["registry.npmjs.org"],
    "cargo": ["crates.io", "static.crates.io"],
    "python": ["pypi.org", "files.pythonhosted.org"],
    "*": ["github.com", "api.github.com"]
  }
}
```
Not just "allowed hosts" but "allowed hosts PER PROCESS."

### 3. IMDS canary
In CI, proactively block or alert on connections to cloud metadata endpoints:
- `169.254.169.254` (AWS/GCP IMDS)
- `169.254.170.2` (ECS)
- `metadata.google.internal`
These should NEVER be contacted during a build.

### 4. DNS monitoring
Instead of just IP capture, also monitor DNS queries. This catches:
- C2 domain resolution (even if connection is blocked)
- DNS exfiltration (data encoded in query names)
- Lookalike domain resolution (`models.litellm.cloud` vs `litellm.ai`)

### 5. Diff between runs
Store network fingerprint per CI run. Alert when a new run connects to hosts that previous runs never contacted. This is what Harden-Runner does — but we could do it locally with a JSON file.
