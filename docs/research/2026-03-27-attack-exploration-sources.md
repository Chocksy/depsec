# Supply Chain Attack Exploration Sources

Where to discover, study, and track supply chain attacks. Organized by type.

## Live Databases (machine-queryable)

### 1. OpenSSF Malicious Packages Database
**URL:** https://github.com/ossf/malicious-packages
**What:** 10,000+ malicious packages in OSV JSON format. Community-maintained. Ingested by osv.dev.
**Ecosystems:** npm, PyPI, and growing
**Use for depsec:** We already query OSV — these malicious package reports are IN the OSV data we query. But we could also use the raw data to build typosquatting detection lists.
**Stats:** https://ossf.github.io/malicious-packages/stats/total.json

### 2. OSV.dev
**URL:** https://osv.dev
**What:** Google's aggregated vulnerability database. Pulls from GitHub Advisories, PyPA, RustSec, Go Vuln DB, and the OpenSSF malicious packages DB above.
**Use for depsec:** We already use this! Our deps.rs queries the batch API.

### 3. GitHub Advisory Database
**URL:** https://github.com/advisories
**API:** `gh api /advisories`
**What:** CVEs and GHSAs across all ecosystems. Machine-queryable.

### 4. deps.dev (Open Source Insights)
**URL:** https://deps.dev
**API:** https://api.deps.dev
**What:** Google's dependency graph explorer. Shows: dependency trees, known vulnerabilities, OpenSSF Scorecard scores, license info, and version history for any package.
**Use for depsec:** Could query this API for package reputation signals (scorecard score, dependency count, etc.)

## Attack Report Feeds (human-readable, high signal)

### 5. Socket.dev Blog
**URL:** https://socket.dev/blog
**What:** Real-time reporting on malicious packages. They catch 100+ per week across npm/PyPI. Best source for NEW attack techniques.
**Key series:** Each blog post is a detailed technical teardown of a specific campaign.
**Recent hits:** StegaBin, SANDWORM_MODE, TeamPCP, CanisterWorm

### 6. Garnet.ai Resources
**URL:** https://www.garnet.ai/resources
**What:** Runtime/eBPF analysis of supply chain attacks. "What Garnet Saw" series shows kernel-level behavioral fingerprints.
**Key insight:** They DETONATE packages in a sandbox and record syscalls. Shows what static analysis misses.

### 7. Snyk Vulnerability DB + Articles
**URL:** https://security.snyk.io + https://snyk.io/articles/
**What:** Vulnerability database + in-depth attack analyses. The LiteLLM backdoor article is their best work.

### 8. Checkmarx Supply Chain Security Blog
**URL:** https://checkmarx.com/blog/category/supply-chain-security/
**What:** Research team that publishes detailed attack analyses. They discovered many PyPI/npm campaigns.

### 9. Sonatype Blog
**URL:** https://blog.sonatype.com
**What:** Publishes annual "State of the Software Supply Chain" report. Good for macro trends.
**Key report:** They detected and blocked LiteLLM within seconds of publication.

## Frameworks & Taxonomies

### 10. MITRE ATT&CK — Supply Chain Compromise
**URL:** https://attack.mitre.org/techniques/T1195/
**What:** Formal taxonomy of supply chain attack techniques:
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1195.002** — Compromise Software Supply Chain
- **T1195.003** — Compromise Hardware Supply Chain
**Use for depsec:** Map our detection rules to ATT&CK technique IDs in output.

### 11. OpenSSF Scorecard
**URL:** https://securityscorecards.dev
**What:** Automated security health grading for open source projects. Checks: branch protection, CI tests, dependency updates, SAST, signed releases, pinned deps, etc.
**Use for depsec:** Similar philosophy to us. Study their checks for ideas we're missing.
**API:** Can query scorecard for any GitHub repo.

### 12. S2C2F — Secure Supply Chain Consumption Framework
**URL:** https://github.com/ossf/s2c2f
**What:** OpenSSF maturity model for consuming open source software. 4 levels from basic to advanced.

### 13. SLSA (Supply-chain Levels for Software Artifacts)
**URL:** https://slsa.dev
**What:** Framework for software supply chain integrity. Levels 1-4 covering source, build, and provenance.

## Tools to Study & Learn From

### 14. DataDog GuardDog
**URL:** https://github.com/DataDog/guarddog
**What:** CLI tool that scans packages using Semgrep/Yara rules. 6 ecosystems: PyPI, npm, Go, RubyGems, GitHub Actions, VSCode Extensions.
**Why study it:** Has 40+ detection heuristics we could learn from:
- `typosquatting` — Levenshtein distance against top packages
- `exfiltrate-sensitive-data` — Reads ~/.ssh, ~/.aws, etc.
- `exec-base64` — Base64 decoded execution
- `steganography` — Hidden data in images
- `npm-serialize-environment` — `process.env` exfiltration
- `repository_integrity_mismatch` — Extra files vs GitHub repo
- `unclaimed_maintainer_email_domain` — Expired/claimable domains
- `bundled_binary` — Binary files in source packages
- `deceptive_author` — Disposable email addresses
**Use for depsec:** Their Semgrep rules are MIT-licensed. We could study their pattern definitions and translate to our regex engine.

### 15. Socket CLI (sfw)
**URL:** https://github.com/nickvdyck/supply-chain-attacks (catalog, may be stale)
**What:** Pre-install HTTP proxy that queries Socket API for package reputation.
**Why study it:** Intercept-before-install model is fundamentally different from our scan-after-install approach.

### 16. Canary (dweinstein/canary)
**URL:** https://github.com/dweinstein/canary
**What:** Plants fake credential files as tripwires. Zero deps, 1400 LOC Go.
**Why study it:** Complementary approach — detect credential theft behavior, not just code patterns.

### 17. zizmor
**URL:** https://github.com/woodruffw/zizmor
**What:** GitHub Actions security scanner (Rust). Detects template injection, unpinned actions, overly broad permissions, impostor commits.
**Why study it:** Direct competitor for our workflows.rs module. Study their rules for gaps in ours.

### 18. pip-audit
**URL:** https://github.com/pypa/pip-audit
**What:** Python dependency vulnerability scanner using OSV. Official PyPA project.
**Why study it:** Reference implementation for Python ecosystem scanning.

## Newsletters & Feeds

### 19. Socket Weekly Threat Report
Socket publishes weekly summaries of detected malicious packages across ecosystems.

### 20. OpenSSF Newsletter
**URL:** https://openssf.org/newsletter/
Monthly digest of supply chain security developments.

### 21. This Week in Rust — Security Section
Rust-specific security advisories and RustSec updates.

## Academic Research

### 22. "Backstabber's Knife Collection"
**Paper:** Analysis of supply chain attacks on package managers (PyPI focus)
**What:** Systematic taxonomy of attack vectors: typosquatting, dependency confusion, account takeover, malicious updates

### 23. "An Empirical Study of Malicious Packages in npm"
**What:** Large-scale analysis of npm malware characteristics and detection evasion techniques

---

## How to Use These for DepSec Development

### Discovery workflow:
1. **Weekly:** Check Socket.dev blog and OpenSSF malicious-packages stats for new attack patterns
2. **Per attack:** Read the technical teardown → identify which of our modules would/wouldn't catch it → file a gap
3. **Per gap:** Study how GuardDog/zizmor/Socket detect it → adapt the pattern for our regex engine
4. **Quarterly:** Review MITRE ATT&CK updates for new supply chain technique IDs

### Building a test corpus:
1. Pull malicious package reports from ossf/malicious-packages
2. Extract the attack patterns (what files, what code, what behavior)
3. Create sanitized test fixtures that trigger our detection rules
4. Build a "catch rate" metric: what % of known attacks would depsec detect?

### The meta-insight:
**Socket** makes money by having the best detection — they catch packages within minutes of publication. Their moat is the real-time API + AI scanning.

**Our moat is different** — we're the single-binary, zero-config, self-contained scanner. We don't need real-time. We need to catch patterns that are ALREADY KNOWN but that nobody bothers to check for in a unified way.

The play: systematically study every GuardDog heuristic and every Socket blog post, and make sure depsec covers the pattern. We'll never beat real-time API-based detection, but we CAN be the best static scanner you install once and run everywhere.
