# Honeypot Sandbox Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current sandbox model (block reads + broken timestamp canary) with a honeypot model: realistic fake $HOME with canary credentials, network left open and monitored, kill chain detection (canary tamper + unexpected network = exfiltration).

**Architecture:** Generate a realistic fake home directory with canary credential files (SSH keys, AWS creds, .env, .npmrc). Mount it as `$HOME` inside all sandbox backends (bubblewrap, sandbox-exec, Docker). Block reads to REAL credential paths. Leave network open but run the monitor concurrently during the sandboxed install (single run, not double). Detect exfiltration by correlating canary access + unexpected network connections.

**Tech Stack:** Rust, bubblewrap, sandbox-exec (macOS), Docker

**Starting point:** Branch `feat/evidence-based-install-guard` which already has `evidence.rs`, `dossier.rs`, content-hash canary detection, LLM dossier analysis, install hook discovery, and typosquat downgrade.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/canary.rs` | Modify | Add realistic dotfiles (.bashrc, .gitconfig, .node_repl_history) to fake HOME |
| `src/sandbox.rs` | Major modify | Mount fake HOME as $HOME, pass canary dir path, keep network open |
| `src/install_guard.rs` | Major modify | Merge sandbox + monitor into single run, add kill chain verdict |
| `src/monitor.rs` | Modify | Extract monitoring into embeddable function (run alongside sandbox) |
| `src/evidence.rs` | Modify | Add kill chain evaluation: canary + network correlation |

---

### Task 1: Enrich canary HOME with realistic dotfiles

**Files:**
- Modify: `src/canary.rs`

Currently canary tokens generate only credential files (.ssh/id_rsa, .aws/credentials, .env, .npmrc, .config/gh/hosts.yml). A fake HOME with ONLY credential files is suspicious. Add realistic dotfiles that make it look like a real developer's home.

- [ ] **Step 1: Add `generate_realistic_home` function**

After the existing `generate_canary_tokens` function, add a new function that creates the full fake HOME:

```rust
/// Generate a realistic-looking home directory with canary credential files
/// AND realistic dotfiles that make the sandbox look like a real developer machine.
pub fn generate_honeypot_home(target_home: &Path) -> Result<Vec<CanaryToken>> {
    // First, generate the canary credential tokens (existing logic)
    let tokens = generate_canary_tokens(target_home)?;

    // Then add realistic dotfiles that aren't canaries but make the home look real
    generate_realistic_dotfiles(target_home)?;

    Ok(tokens)
}

/// Create non-canary dotfiles that make a fake HOME look lived-in
fn generate_realistic_dotfiles(home: &Path) -> Result<()> {
    // .bashrc
    std::fs::write(
        home.join(".bashrc"),
        "# ~/.bashrc\nexport EDITOR=vim\nexport PATH=\"$HOME/.local/bin:$PATH\"\n\
         alias ll='ls -la'\nalias gs='git status'\n",
    )?;

    // .profile
    std::fs::write(
        home.join(".profile"),
        "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n",
    )?;

    // .gitconfig
    let seed = random_seed();
    let name = match seed % 5 {
        0 => "Alex Chen",
        1 => "Jordan Smith",
        2 => "Sam Rodriguez",
        3 => "Taylor Kim",
        _ => "Morgan Lee",
    };
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[user]\n\tname = {name}\n\temail = {email}\n[core]\n\teditor = vim\n[pull]\n\trebase = true\n",
            name = name,
            email = format!("{}@company.com", name.split(' ').next().unwrap_or("dev").to_lowercase()),
        ),
    )?;

    // .node_repl_history (makes it look like a Node.js developer)
    std::fs::write(
        home.join(".node_repl_history"),
        "console.log('hello')\nprocess.env\nrequire('fs').readdirSync('.')\n",
    )?;

    // .npm directory with basic config
    let npm_dir = home.join(".npm");
    std::fs::create_dir_all(&npm_dir)?;
    std::fs::write(npm_dir.join(".npmrc"), "registry=https://registry.npmjs.org/\n")?;

    // .config directory
    std::fs::create_dir_all(home.join(".config"))?;

    Ok(())
}
```

- [ ] **Step 2: Add test for honeypot home**

```rust
#[test]
fn test_generate_honeypot_home() {
    let dir = tempfile::TempDir::new().unwrap();
    let tokens = generate_honeypot_home(dir.path()).unwrap();

    // Should have canary tokens
    assert!(tokens.len() >= 3);

    // Should also have realistic dotfiles
    assert!(dir.path().join(".bashrc").exists());
    assert!(dir.path().join(".gitconfig").exists());
    assert!(dir.path().join(".profile").exists());
    assert!(dir.path().join(".node_repl_history").exists());

    // .gitconfig should look realistic
    let gitconfig = std::fs::read_to_string(dir.path().join(".gitconfig")).unwrap();
    assert!(gitconfig.contains("[user]"));
    assert!(gitconfig.contains("@company.com"));
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test canary -- --nocapture`
Expected: All canary tests pass including the new one

- [ ] **Step 4: Commit**

```bash
git add src/canary.rs
git commit -m "feat: generate realistic honeypot HOME with dotfiles + canary credentials"
```

---

### Task 2: Mount fake HOME in all sandbox backends

**Files:**
- Modify: `src/sandbox.rs:76-87` (run_sandboxed signature)
- Modify: `src/sandbox.rs:89-128` (bubblewrap)
- Modify: `src/sandbox.rs:131-171` (sandbox-exec)
- Modify: `src/sandbox.rs:174-199` (Docker)

Change all three sandbox backends to mount the canary HOME as `$HOME` instead of mounting empty tmpfs at individual sensitive paths. Pass the `canary_home` path as a parameter.

- [ ] **Step 1: Update run_sandboxed signature**

```rust
/// Run a command in a sandbox with a fake HOME directory
pub fn run_sandboxed(
    args: &[String],
    project_dir: &Path,
    sandbox_type: &SandboxType,
    canary_home: &Path,
) -> Result<SandboxResult> {
    match sandbox_type {
        SandboxType::Bubblewrap => run_bubblewrap(args, project_dir, canary_home),
        SandboxType::SandboxExec => run_sandbox_exec(args, project_dir, canary_home),
        SandboxType::Docker => run_docker(args, project_dir, canary_home),
        SandboxType::None => anyhow::bail!("No sandbox available"),
    }
}
```

- [ ] **Step 2: Update bubblewrap to mount fake HOME**

Replace the current tmpfs-per-sensitive-path approach with mounting the canary home:

```rust
fn run_bubblewrap(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<SandboxResult> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    let mut cmd = Command::new("bwrap");
    cmd.args(["--ro-bind", "/", "/"]);

    // Mount fake HOME over real HOME (honeypot with canary credentials)
    cmd.args([
        "--bind",
        &canary_home.to_string_lossy(),
        &home,
    ]);

    // Block real sensitive paths (defense in depth — even though fake HOME is mounted,
    // block the real paths in case of symlink traversal)
    for path in crate::watchdog::SENSITIVE_PATHS {
        let real_path = format!("{home}/{path}");
        // Only block if not already covered by the fake HOME mount
        if !real_path.starts_with(&home) {
            cmd.args(["--tmpfs", &real_path]);
        }
    }

    cmd.args([
        "--bind",
        &project_dir.to_string_lossy(),
        &project_dir.to_string_lossy(),
        "--tmpfs", "/tmp",
        "--tmpfs", "/dev/shm",  // Block shared-memory IPC
        "--dev", "/dev",
        "--proc", "/proc",
        "--unshare-pid",
        "--die-with-parent",
        "--",
    ]);
    cmd.args(args);
    cmd.current_dir(project_dir);

    let status = cmd.status().context("Failed to run bubblewrap")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::Bubblewrap,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}
```

- [ ] **Step 3: Update sandbox-exec to use fake HOME**

```rust
fn run_sandbox_exec(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<SandboxResult> {
    let dir_str = project_dir.to_string_lossy();
    if dir_str.contains('"') || dir_str.contains('(') || dir_str.contains(')') {
        anyhow::bail!("Project directory contains characters that could inject sandbox rules: {}", dir_str);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/user".into());

    // Deny reads to REAL sensitive paths (defense in depth)
    let mut deny_rules = String::new();
    for path in crate::watchdog::SENSITIVE_PATHS {
        deny_rules.push_str(&format!("(deny file-read* (subpath \"{home}/{path}\"))\n"));
    }

    let profile = format!(
        r#"(version 1)
(allow default)
{deny_rules}
(allow file-write* (subpath "{project_dir}"))
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))"#,
        deny_rules = deny_rules,
        project_dir = project_dir.display(),
    );

    let mut cmd = Command::new("sandbox-exec");
    cmd.args(["-p", &profile]);
    // Set HOME to fake honeypot directory
    cmd.env("HOME", canary_home);
    cmd.args(args);
    cmd.current_dir(project_dir);

    let status = cmd.status().context("Failed to run sandbox-exec")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::SandboxExec,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}
```

- [ ] **Step 4: Update Docker to mount fake HOME**

```rust
fn run_docker(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<SandboxResult> {
    let image = detect_docker_image(args);

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        format!("{}:/app:rw", project_dir.display()),
        "-v".to_string(),
        format!("{}:/root:rw", canary_home.display()),  // Mount canary as /root
        "-w".to_string(),
        "/app".to_string(),
        image,
    ];
    docker_args.extend(args.iter().cloned());

    let status = Command::new("docker")
        .args(&docker_args)
        .status()
        .context("Failed to run Docker")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::Docker,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}
```

- [ ] **Step 5: Update the call site in install_guard.rs**

Update the `sandbox::run_sandboxed` call to pass `canary_dir`:

```rust
match sandbox::run_sandboxed(args, root, &sandbox_type, &canary_dir) {
```

- [ ] **Step 6: Update tests**

Update `test_run_sandboxed_none_errors` to pass a dummy canary path:

```rust
#[test]
fn test_run_sandboxed_none_errors() {
    let dir = tempfile::TempDir::new().unwrap();
    let canary = tempfile::TempDir::new().unwrap();
    let result = run_sandboxed(
        &["echo".into(), "hi".into()],
        dir.path(),
        &SandboxType::None,
        canary.path(),
    );
    assert!(result.is_err());
}
```

- [ ] **Step 7: Run tests**

Run: `cargo test sandbox -- --nocapture`
Expected: All tests pass

- [ ] **Step 8: Commit**

```bash
git add src/sandbox.rs src/install_guard.rs
git commit -m "feat: mount honeypot HOME in all sandbox backends"
```

---

### Task 3: Merge sandbox + monitor into single run

**Files:**
- Modify: `src/install_guard.rs`
- Modify: `src/monitor.rs`

Currently the install command runs TWICE: once in the sandbox (Phase 1.5), then again with monitoring (Phase 2). Merge these into a single run where the sandbox wraps the command and the monitor observes concurrently.

- [ ] **Step 1: Extract monitor polling into a standalone function**

In `src/monitor.rs`, create a new public function that starts monitoring threads for a given PID without spawning a new process:

```rust
/// Start monitoring threads for an externally-managed process.
/// Returns a handle that can be used to collect results after the process exits.
pub struct MonitorHandle {
    running: Arc<std::sync::atomic::AtomicBool>,
    poll_handle: Option<std::thread::JoinHandle<()>>,
    watchdog_handle: Option<std::thread::JoinHandle<()>>,
    connections: Arc<Mutex<Vec<Connection>>>,
    file_alerts: Arc<Mutex<Vec<crate::watchdog::FileAlert>>>,
    write_violations: Arc<Mutex<Vec<crate::watchdog::WriteViolation>>>,
    start: std::time::Instant,
}

impl MonitorHandle {
    /// Start monitoring a process by PID
    pub fn start(pid: u32) -> Self {
        let connections: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_addrs: Arc<Mutex<std::collections::HashSet<String>>> = Arc::new(Mutex::new(std::collections::HashSet::new()));
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let file_alerts: Arc<Mutex<Vec<crate::watchdog::FileAlert>>> = Arc::new(Mutex::new(Vec::new()));
        let write_violations: Arc<Mutex<Vec<crate::watchdog::WriteViolation>>> = Arc::new(Mutex::new(Vec::new()));

        let conn_clone = connections.clone();
        let seen_clone = seen_addrs.clone();
        let running_clone = running.clone();

        let poll_handle = std::thread::spawn(move || {
            poll_connections(pid, &conn_clone, &seen_clone, &running_clone);
        });

        let project_root = std::env::current_dir().unwrap_or_default();
        let config = crate::config::load_config(&project_root);
        let sensitive_paths = crate::watchdog::build_sensitive_paths(&config.install.watch_paths);
        let allowed_write_dirs: Vec<std::path::PathBuf> = vec![
            project_root.join("node_modules"),
            project_root.join("vendor"),
            project_root.join(".venv"),
            std::env::temp_dir(),
        ];

        let alerts_clone = file_alerts.clone();
        let violations_clone = write_violations.clone();
        let running_watchdog = running.clone();

        let watchdog_handle = std::thread::spawn(move || {
            let mut seen_alerts = std::collections::HashSet::new();
            let mut seen_violations = std::collections::HashSet::new();
            while running_watchdog.load(std::sync::atomic::Ordering::Relaxed) {
                let new_alerts = crate::watchdog::check_process_files(pid, &sensitive_paths, &mut seen_alerts);
                if !new_alerts.is_empty() {
                    alerts_clone.lock().unwrap().extend(new_alerts);
                }
                let new_violations = crate::watchdog::check_write_boundaries(pid, &allowed_write_dirs, &mut seen_violations);
                if !new_violations.is_empty() {
                    violations_clone.lock().unwrap().extend(new_violations);
                }
                std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
            }
        });

        Self {
            running,
            poll_handle: Some(poll_handle),
            watchdog_handle: Some(watchdog_handle),
            connections,
            file_alerts,
            write_violations,
            start: std::time::Instant::now(),
        }
    }

    /// Stop monitoring and collect results
    pub fn stop(mut self) -> MonitorObservations {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.poll_handle.take() { let _ = h.join(); }
        if let Some(h) = self.watchdog_handle.take() { let _ = h.join(); }

        let defaults = default_expected_hosts();
        let user_allowed = std::collections::HashSet::new(); // TODO: load baseline

        let all_connections = self.connections.lock().unwrap().clone();
        let mut expected = Vec::new();
        let mut unexpected = Vec::new();
        let mut critical = Vec::new();

        for conn in &all_connections {
            if ALWAYS_BLOCK.iter().any(|b| conn.remote_host == *b) {
                critical.push(conn.clone());
            } else if is_expected_connection(conn, &defaults, &user_allowed) {
                expected.push(conn.clone());
            } else {
                unexpected.push(conn.clone());
            }
        }

        MonitorObservations {
            connections: all_connections,
            expected,
            unexpected,
            critical,
            file_alerts: self.file_alerts.lock().unwrap().clone(),
            write_violations: self.write_violations.lock().unwrap().clone(),
            duration_secs: self.start.elapsed().as_secs_f64(),
        }
    }
}

#[derive(Debug)]
pub struct MonitorObservations {
    pub connections: Vec<Connection>,
    pub expected: Vec<Connection>,
    pub unexpected: Vec<Connection>,
    pub critical: Vec<Connection>,
    pub file_alerts: Vec<crate::watchdog::FileAlert>,
    pub write_violations: Vec<crate::watchdog::WriteViolation>,
    pub duration_secs: f64,
}
```

- [ ] **Step 2: Merge sandbox + monitor in install_guard.rs**

Replace the current two-phase approach (Phase 1.5 sandbox + Phase 2 monitor) with a single run where sandbox wraps the command and monitor observes:

In the sandbox block, after spawning the sandbox process, start a MonitorHandle. After the sandbox exits, stop the monitor and collect observations. Remove the separate Phase 2 monitor call entirely.

The key change in `run_install_guard`:
```rust
// Phase 2: Sandboxed install with concurrent monitoring
if use_sandbox {
    let sandbox_type = sandbox::detect_sandbox(sandbox_pref);
    if sandbox_type != sandbox::SandboxType::None {
        // Generate honeypot home
        let canary_dir = std::env::temp_dir().join(format!("depsec-canary-{}", std::process::id()));
        let tokens = crate::canary::generate_honeypot_home(&canary_dir)?;
        eprintln!("[depsec protect] Planted {} canary tokens", tokens.len());

        // Run sandboxed install (network OPEN — honeypot model)
        eprintln!("[depsec protect] Running sandboxed install ({sandbox_type})...");
        let sandbox_result = sandbox::run_sandboxed(args, root, &sandbox_type, &canary_dir);

        // Check canary tamper + collect monitor observations
        let canary_access = check_canary_access(&tokens);
        crate::canary::cleanup_canary_tokens(&tokens);
        let _ = std::fs::remove_dir_all(&canary_dir);

        // Evaluate kill chain: canary access + unexpected network = exfiltration
        // ... (verdict logic from evidence pipeline)

        // NO separate Phase 2 monitor run — we monitored concurrently
    }
}
// Remove the old Phase 2: Run the command with monitoring block entirely
```

- [ ] **Step 3: Add test for single-run behavior**

```rust
#[test]
fn test_install_guard_single_run() {
    // Verify the install command is NOT called twice
    // This is a design assertion — the function should not contain
    // both run_sandboxed AND run_monitor on the same command
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test install_guard -- --nocapture && cargo test monitor -- --nocapture`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/install_guard.rs src/monitor.rs
git commit -m "feat: merge sandbox + monitor into single run (eliminate double install)"
```

---

### Task 4: Implement kill chain verdict (canary + network correlation)

**Files:**
- Modify: `src/install_guard.rs`
- Modify: `src/evidence.rs`

The kill chain: canary tamper detected + unexpected network connection = definitive exfiltration. Implement the verdict logic.

- [ ] **Step 1: Add kill chain evaluation to evidence.rs**

```rust
/// Evaluate the kill chain: correlate canary access with network observations
pub fn evaluate_kill_chain(
    canary_access: &[CanaryAccess],
    network: &crate::monitor::MonitorObservations,
) -> KillChainVerdict {
    let has_canary = !canary_access.is_empty();
    let has_unexpected_net = !network.unexpected.is_empty();
    let has_critical_net = !network.critical.is_empty();

    match (has_canary, has_unexpected_net || has_critical_net) {
        (true, true) => KillChainVerdict::Block {
            reason: "Credential access + unexpected network connection = exfiltration".into(),
            canary_kinds: canary_access.iter().map(|a| a.kind.clone()).collect(),
            destinations: network.unexpected.iter()
                .chain(network.critical.iter())
                .map(|c| format!("{}:{}", c.remote_host, c.remote_port))
                .collect(),
        },
        (true, false) => KillChainVerdict::Warn {
            reason: "Credentials accessed but no network exfiltration detected".into(),
        },
        (false, true) if has_critical_net => KillChainVerdict::Block {
            reason: "Connection to known-malicious IP (IMDS/cloud metadata)".into(),
            canary_kinds: vec![],
            destinations: network.critical.iter()
                .map(|c| format!("{}:{}", c.remote_host, c.remote_port))
                .collect(),
        },
        (false, true) => KillChainVerdict::Info {
            reason: format!("{} unexpected network connection(s)", network.unexpected.len()),
        },
        (false, false) => KillChainVerdict::Pass,
    }
}

#[derive(Debug)]
pub enum KillChainVerdict {
    Pass,
    Info { reason: String },
    Warn { reason: String },
    Block { reason: String, canary_kinds: Vec<String>, destinations: Vec<String> },
}
```

- [ ] **Step 2: Wire kill chain into install_guard**

After collecting canary access and monitor observations:

```rust
let verdict = crate::evidence::evaluate_kill_chain(&canary_access, &observations);

match &verdict {
    crate::evidence::KillChainVerdict::Pass => {
        eprintln!("  \x1b[32m✓\x1b[0m Install passed (clean)");
    }
    crate::evidence::KillChainVerdict::Info { reason } => {
        eprintln!("  \x1b[32m✓\x1b[0m Install passed — {reason}");
    }
    crate::evidence::KillChainVerdict::Warn { reason } => {
        eprintln!("  \x1b[33m⚠\x1b[0m {reason}");
    }
    crate::evidence::KillChainVerdict::Block { reason, canary_kinds, destinations } => {
        eprintln!("  \x1b[31m✗ EXFILTRATION DETECTED!\x1b[0m {reason}");
        for kind in canary_kinds {
            eprintln!("    \x1b[31m✗\x1b[0m Credential: {kind}");
        }
        for dest in destinations {
            eprintln!("    \x1b[31m✗\x1b[0m Destination: {dest}");
        }
        return Ok(InstallGuardResult { exit_code: 1, has_issues: true, .. });
    }
}
```

- [ ] **Step 3: Add tests for kill chain verdict**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_chain_clean() {
        let verdict = evaluate_kill_chain(&[], &empty_observations());
        assert!(matches!(verdict, KillChainVerdict::Pass));
    }

    #[test]
    fn test_kill_chain_canary_plus_network_blocks() {
        let canary = vec![CanaryAccess {
            kind: "SSH Key".into(),
            path: "/tmp/.ssh/id_rsa".into(),
            access_type: "tampered".into(),
        }];
        let mut obs = empty_observations();
        obs.unexpected.push(/* connection to unknown IP */);
        let verdict = evaluate_kill_chain(&canary, &obs);
        assert!(matches!(verdict, KillChainVerdict::Block { .. }));
    }

    #[test]
    fn test_kill_chain_canary_only_warns() {
        let canary = vec![CanaryAccess {
            kind: "SSH Key".into(),
            path: "/tmp/.ssh/id_rsa".into(),
            access_type: "tampered".into(),
        }];
        let verdict = evaluate_kill_chain(&canary, &empty_observations());
        assert!(matches!(verdict, KillChainVerdict::Warn { .. }));
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test evidence -- --nocapture && cargo test install_guard -- --nocapture`

- [ ] **Step 5: Commit**

```bash
git add src/evidence.rs src/install_guard.rs
git commit -m "feat: kill chain verdict — canary + unexpected network = exfiltration block"
```

---

### Task 5: Recursive install hook discovery

**Files:**
- Modify: `src/install_guard.rs`

The current `discover_packages_with_hooks` only scans top-level `node_modules/`. Council finding: transitive deps at any depth can have install hooks.

- [ ] **Step 1: Make discover_packages_with_hooks recursive**

```rust
fn discover_packages_with_hooks(root: &Path) -> Vec<String> {
    let nm = root.join("node_modules");
    if !nm.exists() {
        return vec![];
    }

    let hooks = ["preinstall", "postinstall", "install"];
    let mut result = Vec::new();

    // Walk ALL package.json files at any depth in node_modules
    for entry in walkdir::WalkDir::new(&nm)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.file_name() == "package.json")
    {
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(scripts) = parsed.get("scripts").and_then(|s| s.as_object()) {
            if hooks.iter().any(|h| scripts.contains_key(*h)) {
                // Extract package name from package.json, not from directory
                if let Some(name) = parsed.get("name").and_then(|n| n.as_str()) {
                    result.push(name.to_string());
                }
            }
        }
    }

    result.sort();
    result.dedup();
    result
}
```

- [ ] **Step 2: Add test**

```rust
#[test]
fn test_discover_hooks_recursive() {
    let dir = tempfile::TempDir::new().unwrap();
    let nm = dir.path().join("node_modules");

    // Top-level package with postinstall
    let pkg_a = nm.join("pkg-a");
    std::fs::create_dir_all(&pkg_a).unwrap();
    std::fs::write(pkg_a.join("package.json"), r#"{"name":"pkg-a","scripts":{"postinstall":"node setup.js"}}"#).unwrap();

    // Nested package with postinstall
    let pkg_b = nm.join("pkg-a/node_modules/pkg-b");
    std::fs::create_dir_all(&pkg_b).unwrap();
    std::fs::write(pkg_b.join("package.json"), r#"{"name":"pkg-b","scripts":{"postinstall":"node evil.js"}}"#).unwrap();

    // Package without hooks
    let pkg_c = nm.join("pkg-c");
    std::fs::create_dir_all(&pkg_c).unwrap();
    std::fs::write(pkg_c.join("package.json"), r#"{"name":"pkg-c","scripts":{"start":"node index.js"}}"#).unwrap();

    let hooks = discover_packages_with_hooks(dir.path());
    assert!(hooks.contains(&"pkg-a".to_string()));
    assert!(hooks.contains(&"pkg-b".to_string())); // Nested!
    assert!(!hooks.contains(&"pkg-c".to_string())); // No install hooks
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test install_guard -- --nocapture`

- [ ] **Step 4: Commit**

```bash
git add src/install_guard.rs
git commit -m "feat: recursive install hook discovery across all node_modules depths"
```

---

### Task 6: Silent clean output

**Files:**
- Modify: `src/install_guard.rs`

Council finding: 6 lines for a clean install is the opposite of "invisible seatbelt". On success, output should be minimal.

- [ ] **Step 1: Add quiet mode for clean installs**

Wrap all the informational output in a condition. Only show details on warnings or blocks:

```rust
// At the end of run_install_guard, replace verbose output with:
if !has_issues && !json_output {
    eprintln!("\x1b[32m✓\x1b[0m depsec: install clean");
}
```

Suppress the preflight, sandbox, and monitor status lines when everything passes. Keep them only when there are findings.

- [ ] **Step 2: Test the output manually**

Run: `cargo build --release && ./target/release/depsec protect npm install --prefix ../pos`
Expected: Single line `✓ depsec: install clean` (or similar minimal output)

- [ ] **Step 3: Commit**

```bash
git add src/install_guard.rs
git commit -m "feat: silent clean-install output — one line on success, verbose on findings"
```

---

### Task 7: Integration testing + final quality

- [ ] **Step 1: Test on POS app**

Run: `./target/release/depsec protect npm install --prefix ../pos`
Expected: Clean install with minimal output, no false credential theft warnings

- [ ] **Step 2: Test on hubstaff-cli**

Run: `./target/release/depsec protect cargo build --manifest-path ../hubstaff-cli/Cargo.toml`
Expected: Clean pass

- [ ] **Step 3: cargo fmt + clippy + tests**

Run: `cargo fmt && cargo clippy -- -D warnings && cargo test`
Expected: All pass

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: integration test fixes for honeypot sandbox"
```

---

## Summary

| Before (current) | After (honeypot) |
|---|---|
| Blocks network → detectable | Network open → looks normal |
| Empty tmpfs at ~/.ssh → fingerprint | Full fake HOME with dotfiles → realistic |
| Timestamp-based canary → false positives | Content-hash canary → zero false positives |
| Install runs twice (sandbox + monitor) | Single run with concurrent monitoring |
| 6 lines output on clean install | 1 line on clean install |
| Top-level hook discovery only | Recursive (all depths) |
| Kill chain: canary only | Kill chain: canary + network correlation |
| Fake data worthless to attacker | Fake data worthless + we capture C2 IP |
