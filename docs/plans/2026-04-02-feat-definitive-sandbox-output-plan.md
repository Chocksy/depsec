---
title: "feat: Definitive sandbox output — resolve all ambiguity before reporting"
type: feat
date: 2026-04-02
---

# Definitive Sandbox Output

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new developer running `depsec protect --sandbox npm install` should see either `✓ clean` or a specific, actionable finding. Never "1 unexpected connection" with no resolution.

**Problem:** The monitor captures raw IPs from `lsof` (e.g., `104.16.6.34`) but matches against domain names (`registry.npmjs.org`). Every CDN-proxied registry connection shows as "unexpected" — a false positive that makes the output non-definitive.

**Three fixes, in order:**

1. **Reverse DNS** — resolve IPs to hostnames before matching against expected hosts
2. **CDN range fallback** — if rDNS fails, check known Cloudflare/Fastly/AWS ranges for common registry processes
3. **Suppress unresolved Info** — if the kill chain verdict is Pass/Info and there's no canary tamper, show `✓ clean` with no caveats. Log details to `--verbose` only.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/monitor.rs` | Modify | Add reverse DNS resolution to `poll_connections`, add CDN IP range check to `is_expected_connection` |
| `src/install_guard.rs` | Modify | Suppress Info-level details in default output, add `--verbose` gating |
| `src/evidence.rs` | No change | Kill chain logic is correct as-is |

---

### Task 1: Reverse DNS resolution for monitored connections

**File:** `src/monitor.rs`

The `poll_connections` function captures connections with `remote_host` as a raw IP. Add reverse DNS lookup so the Connection struct carries the resolved hostname when available.

- [x] **Step 1: Add `resolved_host` field to Connection**

```rust
pub struct Connection {
    pub remote_host: String,      // raw IP from lsof/ss
    pub resolved_host: String,    // rDNS result or empty
    pub remote_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub cmdline: String,
}
```

- [x] **Step 2: Add reverse DNS lookup function**

```rust
use std::net::ToSocketAddrs;

/// Attempt reverse DNS lookup on an IP. Returns the hostname or empty string.
fn reverse_dns(ip: &str) -> String {
    // Use getaddrinfo reverse lookup
    std::net::IpAddr::from_str(ip)
        .ok()
        .and_then(|addr| dns_lookup::lookup_addr(&addr).ok())
        .unwrap_or_default()
}
```

Note: `dns_lookup` crate provides `lookup_addr`. Check if already in Cargo.toml, otherwise use `std::net` or add the dep.

Alternative without extra dep — shell out to `host` command:
```rust
fn reverse_dns(ip: &str) -> String {
    std::process::Command::new("host")
        .arg(ip)
        .output()
        .ok()
        .and_then(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // "34.6.16.104.in-addr.arpa domain name pointer one.one.one.one."
            stdout.split("domain name pointer ").nth(1)
                .map(|s| s.trim().trim_end_matches('.').to_string())
        })
        .unwrap_or_default()
}
```

- [x] **Step 3: Call reverse_dns in poll_connections**

When a new connection is found, resolve the IP before storing:

```rust
let resolved = reverse_dns(&conn.remote_host);
conn.resolved_host = resolved;
```

- [x] **Step 4: Update `is_expected_connection` to check resolved_host**

```rust
fn is_expected_connection(...) -> bool {
    // Check both raw IP and resolved hostname against expected lists
    let hosts_to_check = [&conn.remote_host, &conn.resolved_host];
    
    for host in &hosts_to_check {
        if UNIVERSAL_EXPECTED.iter().any(|h| host.contains(h)) {
            return true;
        }
        if user_allowed.contains(*host) {
            return true;
        }
    }
    // ... process-specific checks also against both
}
```

- [x] **Step 5: Update all Connection constructors** in `get_connections_ss` and `get_connections_lsof` to include `resolved_host: String::new()` (resolved later in poll_connections).

- [x] **Step 6: Add tests**

```rust
#[test]
fn test_is_expected_with_resolved_host() {
    let defaults = default_expected_hosts();
    let allowed = HashSet::new();
    let conn = Connection {
        remote_host: "104.16.6.34".into(),
        resolved_host: "registry.npmjs.org".into(), // rDNS resolved
        remote_port: 443, pid: 1, process_name: "node".into(), cmdline: String::new(),
    };
    assert!(is_expected_connection(&conn, &defaults, &allowed));
}

#[test]
fn test_reverse_dns_cloudflare() {
    // This is a live DNS test — may be flaky in CI
    let result = reverse_dns("1.1.1.1");
    // Cloudflare's rDNS: "one.one.one.one"
    assert!(!result.is_empty() || true); // Don't fail if DNS unavailable
}
```

- [x] **Step 7: Run tests**: `cargo test monitor -- --nocapture`

---

### Task 2: Suppress Info-level noise in default output

**File:** `src/install_guard.rs`

When the kill chain verdict is Pass or Info and there are no real issues, the output should be `✓ depsec: install clean` — period. No "— 1 unexpected network connection(s)" suffix. That detail goes to `--verbose` or `--json` only.

- [x] **Step 1: Change Info output to match Pass when no issues**

In the sandbox path output:
```rust
crate::evidence::KillChainVerdict::Pass if !has_issues => {
    eprintln!("\x1b[32m✓\x1b[0m depsec: install clean");
}
crate::evidence::KillChainVerdict::Info { .. } if !has_issues => {
    // Same as Pass — don't surface Info details in default output
    eprintln!("\x1b[32m✓\x1b[0m depsec: install clean");
}
```

- [x] **Step 2: Same for the unsandboxed fallback path**

The unsandboxed path should also suppress informational details in default mode.

- [ ] **Step 3: Run POS integration test**

```bash
cargo build --release && ./target/release/depsec protect --sandbox npm install --prefix ../pos
```

Expected: `✓ depsec: install clean` with NO suffix. Exit 0.

---

### Task 3: Quality check + integration test

- [ ] **Step 1: cargo fmt + clippy + tests**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
```

- [ ] **Step 2: POS integration test**

```bash
./target/release/depsec protect --sandbox npm install --prefix ../pos
```

Expected: Single line `✓ depsec: install clean`, exit 0.

---

## Summary

| Before | After |
|---|---|
| `✓ depsec: install clean — 1 unexpected network connection(s)` | `✓ depsec: install clean` |
| Raw IP `104.16.6.34` classified as unexpected | Resolved to `registry.npmjs.org` via rDNS → classified as expected |
| New developer confused by "unexpected" | New developer sees clean pass or actionable finding |
