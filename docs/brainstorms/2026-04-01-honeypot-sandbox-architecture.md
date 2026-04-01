---
date: 2026-04-01
topic: honeypot-sandbox-architecture
---

# Honeypot Sandbox Architecture

## What We're Building
Replace the current "block network + detect canary tamper" model with a honeypot model: plant realistic fake credentials in a fake $HOME, leave network OPEN but monitored, and catch the attacker red-handed when they exfiltrate worthless fake data to their C2 server.

## Why This Approach
- No network blocking needed → no two-phase install complexity
- Less sandbox detectable → network works normally, environment looks real
- Forensic evidence → we capture the C2 destination IP
- Definitive proof → "read fake SSH key AND connected to external IP" = airtight kill chain
- Fake data is worthless → even if exfiltrated, attacker gets randomized garbage
- esbuild/core-js work without workarounds → single-phase install

## Key Decisions
- Mount fake HOME as $HOME in sandbox (not empty tmpfs stubs)
- Block reads to REAL credential paths (existing deny rules)
- Leave network OPEN but fully monitored
- Kill chain: read canary + unexpected network = BLOCK with evidence
- No two-phase install needed (simplifies architecture significantly)

## Architecture

```
Sandbox setup:
1. Create realistic fake HOME with canary tokens + dotfiles
2. Mount fake HOME as $HOME in sandbox
3. Block reads to REAL credential paths (existing deny rules)
4. Leave network OPEN but MONITORED

Detection (during install):
- Network monitor: logs all connections with process attribution
- Canary hash: checks if fake credentials were read/modified
- Kill chain: canary accessed + unexpected network = definitive exfiltration

Verdict:
- Canary untouched + expected network only → PASS (clean install)
- Canary accessed + no network → WARN (suspicious but no exfiltration)
- Canary accessed + unexpected network → BLOCK (exfiltration of fake data)
- No canary + unexpected network → WARN (unknown behavior)
```

## Advantages Over Previous Approaches

| Property | Block Network | Honeypot |
|---|---|---|
| Exfiltration prevented | Yes (blocked) | Yes (fake data only) |
| Network detectable? | Yes (ENETUNREACH) | No (network works) |
| esbuild/binary downloads | Broken (needs two-phase) | Works naturally |
| Forensic value | None | C2 server IP captured |
| Architecture complexity | Two-phase install | Single-phase |
| Sandbox detectability | Higher | Lower |

## Next Steps
→ Implementation plan with tasks
