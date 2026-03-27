# GOD MODE Brainstorm — Making depsec invisible and always-on

## The Core Insight

Every security tool today requires the developer to REMEMBER to use it. You have to:
- Add `depsec scan .` to your CI
- Run `socket firewall npm install` instead of `npm install`
- Configure harden-runner in every workflow

**GOD MODE = depsec protects you without you thinking about it.**

---

## How to Hook Into Everything (seamless integration)

### Approach 1: Shell Aliases (simplest, works today)

```bash
# User adds to ~/.zshrc or ~/.bashrc
eval "$(depsec shell-hook)"
```

This outputs aliases that wrap common commands:
```bash
alias npm="depsec monitor npm"
alias pip="depsec monitor pip"
alias cargo="depsec monitor cargo"
alias yarn="depsec monitor yarn"
alias pnpm="depsec monitor pnpm"
alias bundle="depsec monitor bundle"
alias go="depsec monitor go"
```

Now every `npm install` automatically runs through depsec's network monitor. User doesn't change their workflow at all.

**Pros:** Dead simple. Works everywhere. Reversible.
**Cons:** User has to opt in via shell config. Easy to bypass with `\npm install`.

### Approach 2: Git Hooks (automatic per-project)

```bash
depsec init  # Sets up git hooks for this project
```

Creates `.git/hooks/post-checkout` and `.git/hooks/post-merge` that run `depsec scan .` after every git pull/checkout/merge. Also creates a `pre-push` hook that blocks pushing if critical findings exist.

**Pros:** Automatic for the project. Other team members get it too (with `core.hooksPath`).
**Cons:** Hooks are local, not enforced remotely. People can `--no-verify`.

### Approach 3: npm/pip lifecycle hooks (deepest integration)

**npm:** Create a `.npmrc` with:
```ini
ignore-scripts=true
```
Then `depsec` runs a pre-approved subset of install scripts after scanning them. This is what Socket Firewall does conceptually — intercept before execution.

**pip:** Use `pip install --no-deps --require-hashes` by default, with depsec managing the hash verification.

**Pros:** Actually prevents malicious code execution.
**Cons:** Complex. Breaking change for user's workflow.

### Approach 4: GitHub App (cloud, but powerful)

A GitHub App that automatically:
- Adds `depsec scan` to every PR as a check
- Comments on PRs with findings
- Blocks merge on critical issues
- No CI config needed — just install the app

**Pros:** Zero config for the user. Works on every repo they own.
**Cons:** Requires a cloud backend. Not pure CLI anymore.

### Approach 5: OS-level process monitor (most GOD mode)

A background daemon that watches ALL process network activity:
```bash
depsec daemon start   # Runs in background
depsec daemon status  # Shows what it's protecting
depsec daemon stop    # Turns off
```

Uses `ss -tnp` polling (Linux) or `lsof -i` (macOS) to monitor every process. When it detects `npm`, `pip`, `cargo`, `go`, or `bundle` making unexpected network calls, it alerts.

**Pros:** True always-on protection. Catches EVERYTHING.
**Cons:** Resource usage. False positives. macOS permissions issues.

---

## The `depsec monitor` Design

This is the most achievable GOD MODE feature:

```bash
# Wrap any command
depsec monitor npm install

# What happens:
# 1. Starts monitoring network connections (ss -tnp polling)
# 2. Runs `npm install` as child process
# 3. Records every outbound connection + the process that made it
# 4. After command finishes, diffs against baseline
# 5. Reports unexpected connections with process attribution
```

### Output:
```
depsec monitor — npm install completed in 12.3s

[Network Activity]
  npm (pid 1234):
    ✓ registry.npmjs.org:443 — expected (npm registry)
    ✓ github.com:443 — expected (git dependencies)

  node (pid 5678, parent: npm):
    ✓ registry.npmjs.org:443 — expected
    ✗ 83.142.209.203:8080 — UNEXPECTED!
      → Process: node ./node_modules/sketchy-pkg/scripts/postinstall.js
      → First seen: never (new connection)

  node (pid 9012, parent: node):
    ✗ pastebin.com:443 — SUSPICIOUS
      → Process: node ./node_modules/sketchy-pkg/vendor/version.js
      → Pattern match: C2 dead-drop resolver

3 connections monitored, 2 unexpected.
Run 'depsec monitor --block' to prevent unexpected connections.
```

### The key innovation: PROCESS ATTRIBUTION

tcpdump gives you IPs. `ss -tnp` gives you IPs + PIDs. We map PIDs to process command lines via `/proc/<pid>/cmdline`. This tells us not just WHAT connected, but WHO (which package's script) made the connection.

### Technical approach on Linux:
```
1. Start polling loop: `ss -tnp` every 100ms
2. For each new connection: read /proc/<pid>/cmdline
3. Map PID → process tree → identify which npm package initiated it
4. After command exits: diff connections against baseline
5. Report with full attribution
```

### On macOS:
```
1. Use `lsof -i -n -P` instead of `ss -tnp`
2. Same PID → process mapping via `ps -p <pid> -o comm=`
3. Less granular but still useful
```

---

## The `depsec preflight` Design

Scan BEFORE installing. Prevent the attack, don't just detect it.

```bash
depsec preflight .

# Analyzes:
# - package.json scripts (preinstall, postinstall, etc.)
# - Lockfile integrity (are hashes present?)
# - Package metadata (age, downloads, maintainer health)
# - Typosquatting (name similarity to popular packages)
# - New dependencies since last install (what changed?)

# Output:
# [Preflight Check] package.json
#   ⚠ postinstall script in "sketchy-pkg": node ./scripts/setup.js
#     → This package runs code during install
#   ✓ No preinstall scripts
#
# [Dependency Changes] (vs lockfile)
#   NEW: sketchy-pkg@1.0.0
#     → Published 2 hours ago
#     → 12 total downloads
#     → No GitHub repository linked
#     → Maintainer email: temp@mailinator.com
#     → ⚠ HIGH RISK: new package, low downloads, disposable email
#
# [Lockfile Integrity]
#   ✓ All 142 packages have integrity hashes
#   ✓ No hash mismatches detected
```

### Where preflight data comes from:

| Check | Data Source |
|-------|------------|
| Install scripts | Parse `package.json` locally |
| Package metadata | deps.dev API (free, no key needed) |
| Scorecard scores | deps.dev API |
| Typosquatting | Local Levenshtein against top-1000 packages |
| Download count | deps.dev API or registry API |
| Publish date | deps.dev API (publishedAt field) |
| Maintainer info | Registry API (npm, PyPI, etc.) |
| Lockfile hashes | Parse lockfile locally |

---

## deps.dev API — What We Can Get For Free

Tested and confirmed working. No API key needed.

### Package info:
```
GET /v3alpha/systems/{ecosystem}/packages/{name}
→ All versions, publish dates, deprecation status
```

### Version details:
```
GET /v3alpha/systems/{ecosystem}/packages/{name}/versions/{version}
→ License, advisories, SLSA provenance, attestations, registry, links
```

### Project scorecard:
```
GET /v3alpha/projects/{github.com%2Fowner%2Frepo}
→ OpenSSF Scorecard with per-check scores:
  - Maintained (last 90 days activity)
  - Code-Review (% of PRs reviewed)
  - Dangerous-Workflow (pull_request_target etc.)
  - Branch-Protection
  - Token-Permissions
  - Signed-Releases
  - Pinned-Dependencies
  - SAST
  - Vulnerabilities
  - License
```

### Dependencies:
```
GET /v3alpha/systems/{ecosystem}/packages/{name}/versions/{version}:dependencies
→ Full dependency tree with resolution
```

### What this enables for depsec:
- **Package age**: Is this package published in the last 24 hours? (suspicious)
- **Download trends**: Did downloads spike from 0 to 100K overnight? (typosquat riding a trend)
- **Maintainer health**: Is the GitHub repo maintained? Code reviewed? Has branch protection?
- **SLSA provenance**: Does the package have cryptographic build attestation?
- **Scorecard grade**: Quick trust signal — is this a well-maintained project?

---

## The Economics of Attacks (Why People Do This)

### Motivation Spectrum

| Attacker Type | Motivation | Typical Target | Scale |
|---------------|-----------|----------------|-------|
| **Nation-state (Lazarus/DPRK)** | Cryptocurrency theft | Crypto devs, DeFi projects | $100M+ stolen (2024) |
| **Criminal gangs (TeamPCP)** | Credential harvesting → resale/extortion | Enterprise CI/CD | ~500K credentials per campaign |
| **Script kiddies** | Crypto mining | Any popular package | Small $ per machine, big volume |
| **Disgruntled maintainers** | Protest/revenge | Their own packages | Chaos, not money |
| **Security researchers** | Bug bounties / fame | Any vulnerable tool | $0-50K per disclosure |

### The Money Trail

**North Korea (Lazarus Group):**
- Stole $1.7B in cryptocurrency in 2024 alone
- StegaBin campaign targeted crypto wallet extensions in browsers
- Fund nuclear weapons program
- Supply chain is their PRIMARY attack vector

**TeamPCP:**
- Claimed "terabytes of trade secrets"
- ~500K credentials from LiteLLM alone
- Sell access to ransomware groups (partnered with Vect)
- Target security tools specifically because they have broad access

**CanisterWorm:**
- Used ICP (Internet Computer) blockchain for C2 — making takedown nearly impossible
- 29+ packages, 135 malicious releases
- Persistence via systemd — survives container restarts
- Self-propagating: steals npm tokens → republishes victim's other packages → grows exponentially

### Why Security Tools Are THE #1 Target

Think about it: what has the most access in any organization?

| Tool | What It Can Access |
|------|-------------------|
| Trivy (vulnerability scanner) | All source code, all containers, CI secrets |
| LiteLLM (AI gateway) | API keys for OpenAI, Anthropic, Google, Azure |
| Dependabot/Renovate | Write access to every repo it manages |
| VS Code extensions | Full filesystem access, terminal access |
| GitHub Actions | All repository secrets, GITHUB_TOKEN |

When you compromise a security scanner, you don't get one machine — you get EVERY machine that runs that scanner. That's why TeamPCP targets them specifically.

**This is why depsec scanning ITSELF is not optional — it's existential.**

---

## Novel Ideas That Nobody Has Yet

### 1. "Canary Dependencies"
Plant fake internal package names in your `package.json` / `requirements.txt`. If anyone downloads them from a public registry, you know there's a dependency confusion attack targeting you.

```bash
depsec canary init  # Generates fake package names based on your org
depsec canary check # Queries public registries for your canary names
```

### 2. "Time Travel" scanning
Don't just scan current dependencies. Scan what WOULD happen if you updated:

```bash
depsec scan . --simulate-update
# "If you update lodash from 4.17.20 to 4.17.21:
#   - 0 new vulnerabilities
#   - No new install scripts
#   - Maintainer unchanged
#   - 2 files changed (diff link)"
```

### 3. "DNA fingerprint" for packages
Hash the behavioral profile of a package (what files it reads, what network calls it makes, what env vars it accesses) and track changes across versions. If `lodash@4.17.21` suddenly reads `~/.ssh/id_rsa`, the DNA changed.

### 4. "Neighborhood Watch"
Monitor what other projects SIMILAR to yours use. If 90% of Express apps use `helmet` for security headers and you don't, flag it. If a package you use gets removed by 80% of similar projects in one week, something happened.

### 5. "Dead Man's Switch"
If your CI hasn't run `depsec scan` in X days but your dependencies were updated, alert. The gap between "last scan" and "last dependency change" is the danger window.

---

## What's Our Unique Story?

Every tool in this space tells a story:

- **Socket:** "We catch malware before you install it" (API-powered, real-time)
- **Snyk:** "We fix vulnerabilities for you" (enterprise, developer-friendly)
- **Garnet:** "We see what code actually DOES" (runtime, eBPF, deep tech)
- **zizmor:** "We harden your GitHub Actions" (narrow but deep)

**What's our story?**

Option A: "One binary to protect everything" — the Swiss Army knife
Option B: "See what your code does on the network" — the network watchdog
Option C: "Security that's always on" — the invisible guardian
Option D: "Own your security" — self-contained, no cloud, no API keys, trust nothing

I think **Option D** resonates with the 1000-stars goal. Developers are tired of signing up for services. They want a tool they install once and it just works. The "trust nothing, own everything" philosophy — including not trusting US.
