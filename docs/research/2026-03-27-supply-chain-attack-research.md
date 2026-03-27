# Supply Chain Attack Research — Gap Analysis for DepSec

**Date:** 2026-03-27
**Sources:** 9 articles covering recent supply chain attacks and defenses

## Sources Analyzed

1. [Securing Python Supply Chain](https://bernat.tech/posts/securing-python-supply-chain/) — 9-layer defense model
2. [Socket Firewall](https://socket.dev/blog/introducing-socket-firewall) — Pre-install package interception
3. [Garnet + LightLLM](https://www.garnet.ai/resources/garnet-saw-lightllm) — eBPF runtime detection of LiteLLM compromise
4. [TeamPCP Campaign](https://socket.dev/blog/teampcp-targeting-security-tools-across-oss-ecosystem) — Threat group targeting security tools
5. [Canary Honeypot](https://github.com/dweinstein/canary) — Filesystem tripwire for credential theft
6. [No Prompt Injection Required](https://futuresearch.ai/blog/no-prompt-injection-required/) — MCP/AI tool supply chain attack
7. [Poisoned Security Scanner](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) — How Trivy was compromised to backdoor LiteLLM

---

## Attack Vectors Catalog

### A. Package Registry Attacks

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Typosquatting** | Packages with similar names to popular ones | Multiple PyPI/npm incidents |
| **Account takeover** | Expired domain re-registration → email → registry account | ctx/PHPass (May 2022) |
| **Credential theft** | Steal PyPI/npm publish tokens from CI | TeamPCP → Trivy → LiteLLM |
| **Dependency confusion** | Internal package name published to public registry | pip `--extra-index-url` vulnerability |
| **Tag rewriting** | Overwrite GitHub Action tags to point to malicious commits | Trivy Action v0.69.4 |

### B. CI/CD Pipeline Attacks

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **`pull_request_target` + checkout** | Code injection into privileged workflow | GhostAction (570+ repos) |
| **Unpinned CI tools** | Pulling latest version of scanner = pulling compromised version | LiteLLM pulling Trivy via apt |
| **GitHub Actions expression injection** | `${{ github.event.issue.body }}` in run blocks | Multiple repos |
| **OIDC workflow modification** | Attacker modifies workflow to trigger legitimate OIDC exchange | Theoretical but documented |
| **Disclosure suppression** | Bot floods to close vulnerability reports | TeamPCP (88 comments, 102 seconds) |

### C. Code-Level Attacks

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **`.pth` file injection** | Python path hooks execute on every interpreter startup | LiteLLM 1.82.8 |
| **postinstall scripts** | Run arbitrary code during `npm install` | Countless npm incidents |
| **Base64 → exec chains** | Obfuscated payload execution | LiteLLM, event-stream |
| **eval() with dynamic input** | Dynamic code execution from decoded payloads | Classic obfuscation pattern |
| **ZIP parser confusion** | Different installers extract different content from same wheel | Documented by researcher |

### D. Credential Theft Patterns

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Cloud IMDS probing** | `curl 169.254.169.254` for AWS/GCP credentials | LiteLLM payload |
| **ECS credential endpoint** | `curl 169.254.170.2/.../credentials` | LiteLLM payload |
| **Filesystem sweep** | Read `~/.ssh`, `~/.aws`, `~/.env`, `~/.gnupg` | LiteLLM + many others |
| **K8s secret exfiltration** | `kubectl get secrets --all-namespaces` | LiteLLM payload |
| **Shell history mining** | Grep shell history for API keys/tokens | LiteLLM payload |
| **Git credential theft** | Read `.git-credentials`, `.gitconfig` | Common pattern |

### E. Persistence Mechanisms

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Systemd user service** | Disguised as "System Telemetry Service" | LiteLLM `sysmon.service` |
| **`.pth` files** | Python startup hooks survive across sessions | LiteLLM 1.82.8 |
| **Cron jobs** | Scheduled execution of backdoor | Common pattern |
| **K8s privileged pods** | Deploy backdoor pods to every node | LiteLLM K8s lateral movement |

### F. Exfiltration Patterns

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Encrypted exfil** | AES-256-CBC + RSA-4096 to C2 domain | LiteLLM `tpcp.tar.gz` |
| **DNS exfiltration** | Encode data in DNS queries | Common APT technique |
| **Lookalike domains** | `models.litellm.cloud` vs `litellm.ai` | TeamPCP |
| **Polling C2** | Backdoor checks URL every 5 minutes for new payloads | LiteLLM `checkmarx.zone` |

---

## DepSec Gap Analysis

### What We Currently Detect

| Attack Vector | DepSec Module | Status |
|---------------|---------------|--------|
| Unpinned GitHub Actions | workflows.rs (W001) | ✅ Detected |
| `pull_request_target` + checkout | workflows.rs (W003) | ✅ Detected |
| Expression injection in `run:` blocks | workflows.rs (W004) | ✅ Detected |
| Write-all permissions | workflows.rs (W002) | ✅ Detected |
| `--no-verify`/`--force` git flags | workflows.rs (W005) | ✅ Detected |
| Known CVEs in dependencies | deps.rs (OSV) | ✅ Detected |
| `eval()`/`exec()` with variable input | patterns.rs (P001) | ✅ Detected |
| Base64 decode → execute | patterns.rs (P002) | ✅ Detected |
| HTTP to raw IP | patterns.rs (P003) | ✅ Detected |
| Sensitive file reads (`~/.ssh`, etc.) | patterns.rs (P004) | ✅ Detected |
| Binary file → execute | patterns.rs (P005) | ✅ Detected |
| postinstall network calls | patterns.rs (P006) | ✅ Detected |
| High-entropy strings | patterns.rs (P007) | ✅ Detected |
| `new Function()` dynamic | patterns.rs (P008) | ✅ Detected |
| Hardcoded secrets (20 patterns) | secrets.rs (S001-S020) | ✅ Detected |
| Missing SECURITY.md | hygiene.rs (H001) | ✅ Detected |
| .gitignore gaps | hygiene.rs (H002) | ✅ Detected |
| Lockfile not committed | hygiene.rs (H003) | ✅ Detected |
| No branch protection | hygiene.rs (H004) | ✅ Detected |
| Unexpected network connections in CI | baseline.rs | ✅ Detected |

### What We DO NOT Detect (Gaps)

#### CRITICAL GAPS (attacks happening NOW in the wild)

| Gap | Attack It Misses | Priority |
|-----|-----------------|----------|
| **`.pth` file detection** | LiteLLM-style persistence via Python startup hooks | P0 |
| **Typosquatting detection** | Packages with names similar to popular ones | P0 |
| **Dependency confusion** | Internal names published to public registries | P1 |
| **Cloud IMDS probing** | `curl 169.254.169.254` for cloud credential theft | P1 |
| **Hash verification** | We check for vulns but not integrity (are you getting what you expect?) | P1 |
| **Unpinned deps in lockfiles** | `requirements.txt` with `>=` instead of `==` (we warn but don't score) | P2 |
| **SBOM generation** | No `--format cyclonedx` or `--format spdx` output | P2 |

#### IMPORTANT GAPS (emerging attack patterns)

| Gap | Attack It Misses | Priority |
|-----|-----------------|----------|
| **Systemd/cron persistence** | Backdoor installs masquerading as legitimate services | P1 |
| **Git tag mutability** | Tags pointed to different commits (Trivy attack vector) | P1 |
| **Disclosure suppression** | Bot floods on vulnerability reports | N/A (not detectable by us) |
| **Cross-ecosystem worms** | npm compromise → PyPI token theft | P2 |
| **K8s secret scanning** | Kubeconfig/service account tokens in repo | P2 |
| **Encrypted exfiltration** | AES+RSA data bundles sent to C2 | P2 (network monitor) |
| **Process ancestry anomalies** | Python spawning Python spawning shell | N/A (runtime, not static) |
| **ZIP parser confusion** | Different content extracted by different installers | P3 |

#### DETECTION APPROACH GAPS

| Gap | What's Missing | How Others Solve It |
|-----|---------------|-------------------|
| **Runtime analysis** | We only do static analysis; no execution sandbox | Garnet uses eBPF; Socket Firewall intercepts at network level |
| **Package reputation** | We check CVEs but not package age, download spikes, maintainer history | Socket API provides reputation scores |
| **Behavioral baselines** | Our network baseline is host-based; no process-level behavioral profiling | Garnet records 65+ behavioral events per package |
| **Pre-install interception** | We scan after install; Socket blocks before download | Socket Firewall acts as HTTP proxy |
| **Canary/honeypot** | No filesystem tripwire for credential theft detection | dweinstein/canary plants fake secrets |
| **SARIF output** | Can't integrate with GitHub Security tab | Standard format for code scanning tools |

---

## Recommended Improvements (Prioritized)

### P0 — Add Now (real attacks using these TODAY)

1. **`.pth` file scanner** — Scan `site-packages/` for `.pth` files containing `exec`, `subprocess`, `base64`, `eval`. This is the #1 emerging attack vector. New rule: `DEPSEC-P009`.

2. **Typosquatting detector** — Compare dependency names against a list of popular packages, flag close Levenshtein-distance matches. E.g., `requets` vs `requests`, `colorsama` vs `colorama`.

3. **IMDS/cloud credential probing** — Add pattern for `169.254.169.254` and `169.254.170.2` in source code AND in network baseline. New rules: `DEPSEC-P009`, `DEPSEC-P010`.

### P1 — Add Soon (active threat landscape)

4. **Dependency confusion check** — If project uses a private registry, warn about packages that also exist on public PyPI/npm. Check `--extra-index-url` usage.

5. **Hash verification audit** — Check if lockfiles include integrity hashes. `Cargo.lock` has `checksum` fields; `package-lock.json` has `integrity`; `yarn.lock` has `resolved` + hash.

6. **Git tag immutability check** — For pinned GitHub Actions, verify the SHA hasn't changed since it was pinned (compare against GitHub API).

7. **K8s/Docker secret patterns** — Add secret patterns for `kubeconfig`, `docker config.json`, service account tokens.

### P2 — Add Later (defense in depth)

8. **SBOM generation** — `depsec sbom .` outputting CycloneDX or SPDX format.

9. **Package age/download anomaly** — Flag newly published packages or packages with sudden download spikes.

10. **SARIF output** — `depsec scan . --format sarif` for GitHub Security tab integration.

11. **Canary mode** — `depsec canary init` to plant fake credential files, `depsec canary watch` to monitor access.

---

## Key Lessons from Research

1. **Static analysis is necessary but insufficient** — LiteLLM's `.pth` attack bypasses all static scanners. Runtime/behavioral detection is the next frontier.

2. **Security tools are HIGH-VALUE TARGETS** — TeamPCP deliberately targets scanners because they have elevated access. DepSec must protect itself as a primary concern.

3. **Hash verification ≠ content safety** — Hash-pinned installs verify integrity, not intent. A compromised maintainer publishes legitimate-looking hashes.

4. **The kill chain is: CI/CD → credentials → registry → payload** — Most sophisticated attacks start by compromising CI infrastructure, not the package directly.

5. **Network monitoring catches what static analysis misses** — The LiteLLM payload's IMDS probes, C2 communication, and encrypted exfiltration are all network-visible. Our baseline approach is on the right track but needs IP-level (not just hostname) awareness.

6. **Defense must be layered** — No single tool catches everything. The Python article's 9-layer model is the right philosophy.

7. **AI toolchains are the new frontier** — SANDWORM_MODE injects rogue MCP servers into Claude, Cursor, VS Code, and Windsurf configs. AI assistants with tool access are now credential-harvesting vectors.

8. **Steganography hides C2 infrastructure** — StegaBin uses zero-width Unicode in Pastebin essays to hide C2 domain lists. Static regex patterns can't catch this; behavioral analysis (outbound connections during install) is required.

9. **Worms are bidirectional** — npm install → GitHub workflow injection → CI harvests secrets → more repos infected → repeat. The attack surface isn't linear, it's a graph.

10. **VSCode/IDE persistence is real** — `tasks.json` with `runOn: folderOpen` and 186-space padding to push malicious commands off-screen. IDE config files are now attack surfaces.

---

## Additional Attack Vectors from StegaBin + SANDWORM Research

### G. AI Toolchain Attacks

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **MCP server injection** | Plant rogue MCP server in AI assistant configs | SANDWORM `McpInject` module |
| **Prompt injection in tool descriptions** | MCP tool descriptions instruct AI to read secrets | SANDWORM rogue server |
| **LLM API key harvesting** | Steal OpenAI/Anthropic/Google keys from env vars | SANDWORM 9-provider sweep |
| **Polymorphic engine** | Use local Ollama to rewrite worm code | SANDWORM (dormant but present) |

### H. Steganography & Obfuscation

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Unicode steganography** | Zero-width chars hide C2 URLs in benign text | StegaBin Pastebin pastes |
| **RC4 + array rotation** | Multi-layer obfuscation in vendored files | StegaBin `version.js` |
| **Dead-drop resolver** | C2 addresses fetched from Pastebin, not hardcoded | StegaBin 3-paste chain |
| **186-space whitespace trick** | Push malicious `tasks.json` off-screen in IDE | StegaBin VSCode persistence |

### I. Worm Propagation

| Vector | Description | Real Example |
|--------|-------------|-------------|
| **Token-based package hijacking** | Steal npm tokens → republish victim's packages with malware | SANDWORM Vector 1 |
| **Automated PR injection** | Create PRs adding malicious dependency with innocent commit messages | SANDWORM Vector 2 |
| **SSH-based git push** | Use victim's SSH agent to push to repos | SANDWORM Vector 3 |
| **Bidirectional CI loop** | npm → workflow → Action → secrets → more repos | SANDWORM GitHub Action loop |

---

## Updated DepSec Gaps (from StegaBin + SANDWORM)

### NEW P0 GAPS

| Gap | Attack It Misses | Source |
|-----|-----------------|--------|
| **MCP config tampering** | Rogue MCP servers in `~/.claude/`, `~/.cursor/`, etc. | SANDWORM |
| **IDE config integrity** | Malicious `tasks.json`, `.vscode/` modifications | StegaBin |
| **Git hook tampering** | Global `init.templateDir` pointing to attacker-controlled hooks | SANDWORM |
| **npm publish token scope** | Tokens with overly broad publish permissions | SANDWORM token hijacking |

### NEW P1 GAPS

| Gap | Attack It Misses | Source |
|-----|-----------------|--------|
| **Unicode obfuscation** | Zero-width characters hiding data in source files | StegaBin |
| **Install script analysis** | `package.json` scripts executing vendored JS with remote fetch | StegaBin |
| **Pastebin/paste site C2** | C2 infrastructure hidden in paste services | StegaBin dead-drop |
| **LLM API key exposure** | OpenAI/Anthropic keys in env vars or `.env` files | SANDWORM |
| **DGA domain detection** | Algorithmically generated C2 domains | SANDWORM DGA |
