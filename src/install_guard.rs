use std::path::Path;

use anyhow::{Context, Result};

use crate::config::InstallConfig;
use crate::monitor;
use crate::sandbox;

/// Run the install-guard pipeline: preflight → sandbox + canary → monitor → attestation → report
pub fn run_install_guard(
    args: &[String],
    root: &Path,
    config: &InstallConfig,
    json_output: bool,
    learn: bool,
    strict: bool,
    sandbox_enabled: bool,
) -> Result<InstallGuardResult> {
    if args.is_empty() {
        anyhow::bail!("No command specified. Usage: depsec protect <command> [args...]");
    }

    let command_str = args.join(" ");

    // Detect if this is an install command (not just any command)
    let is_install = is_install_command(args);

    // Phase 1: Preflight check (for install commands with new packages)
    // Only print output on findings — silent on clean (invisible seatbelt)
    if config.preflight && is_install {
        let new_packages = extract_new_packages(args);
        if !new_packages.is_empty() {
            if let Ok(result) = crate::preflight::run_preflight_quiet(root) {
                // Typosquat matches are informational only — never block
                // (too many false positives: sha1/sha2, slab/clap, etc.)
                let non_typosquat_high_risk = result.findings.iter().any(|f| {
                    f.rule_id != "DEPSEC-T001"
                        && matches!(
                            f.severity,
                            crate::checks::Severity::Critical | crate::checks::Severity::High
                        )
                });

                if non_typosquat_high_risk {
                    eprintln!(
                        "\x1b[1m[depsec protect]\x1b[0m \x1b[31m⚠ Preflight found high-risk issues!\x1b[0m"
                    );
                    for f in &result.findings {
                        if f.rule_id != "DEPSEC-T001"
                            && matches!(
                                f.severity,
                                crate::checks::Severity::Critical | crate::checks::Severity::High
                            )
                        {
                            eprintln!("    \x1b[31m✗\x1b[0m {}", f.message);
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Sandboxed install with concurrent monitoring (single run)
    let use_sandbox = sandbox_enabled;
    let sandbox_pref = if config.sandbox == "none" {
        "auto"
    } else {
        &config.sandbox
    };

    let sandbox_type = if use_sandbox {
        sandbox::detect_sandbox(sandbox_pref)
    } else {
        sandbox::SandboxType::None
    };

    if use_sandbox && sandbox_type == sandbox::SandboxType::None {
        eprintln!(
            "\x1b[1m[depsec protect]\x1b[0m \x1b[33m⚠\x1b[0m No sandbox backend available (tried: {})",
            sandbox_pref
        );
    }

    // Choose path: sandboxed single-run or unsandboxed monitor
    if sandbox_type != sandbox::SandboxType::None {
        // ── Honeypot sandbox path: spawn + monitor concurrently ──
        let canary_dir = std::env::temp_dir().join(format!("depsec-canary-{}", std::process::id()));
        std::fs::create_dir_all(&canary_dir).context("Failed to create canary temp dir")?;
        let tokens = crate::canary::generate_honeypot_home(&canary_dir).unwrap_or_else(|e| {
            eprintln!("  \x1b[33m⚠\x1b[0m Canary token generation failed: {e}");
            vec![]
        });

        // Silent on clean — only print sandbox status on findings

        match sandbox::spawn_sandboxed(args, root, &sandbox_type, &canary_dir) {
            Ok(mut child) => {
                let child_pid = child.id();

                // Start concurrent monitoring (skip for Docker — container PID
                // isn't visible to the host process tree, so network/file
                // monitoring would be blind. Rely on canary tamper detection.)
                let use_monitor = sandbox_type != sandbox::SandboxType::Docker;
                let monitor = if use_monitor {
                    Some(monitor::MonitorHandle::start(child_pid))
                } else {
                    None
                };

                // Wait for sandboxed install to finish
                let status = child
                    .wait()
                    .context("Failed to wait for sandboxed process")?;

                // Stop monitor and collect observations
                let observations = if let Some(m) = monitor {
                    m.stop()
                } else {
                    monitor::MonitorObservations::empty()
                };

                // Canonicalize canary path BEFORE cleanup (macOS: /var → /private/var)
                let canonical_canary = canary_dir
                    .canonicalize()
                    .unwrap_or_else(|_| canary_dir.clone());

                // Check canary tamper
                let canary_accessed = check_canary_access(&tokens);
                crate::canary::cleanup_canary_tokens(&tokens);
                let _ = std::fs::remove_dir_all(&canary_dir);

                // Build CanaryAccess for kill chain evaluation
                let canary_evidence: Vec<crate::evidence::CanaryAccess> = canary_accessed
                    .iter()
                    .map(|(kind, access_type)| crate::evidence::CanaryAccess {
                        kind: kind.clone(),
                        path: String::new(),
                        access_type: access_type.clone(),
                    })
                    .collect();

                // Evaluate kill chain: canary + network correlation
                let verdict = crate::evidence::evaluate_kill_chain(&canary_evidence, &observations);

                // In the honeypot sandbox, the file watchdog will flag reads
                // from the fake HOME's sensitive paths (.ssh, .aws, etc.) —
                // that's expected. We rely on canary hash tamper detection instead.
                // Only count file alerts from OUTSIDE the canary home.
                let canary_prefix = canonical_canary.to_string_lossy().to_string();
                let real_file_alerts: Vec<_> = observations
                    .file_alerts
                    .iter()
                    .filter(|a| !a.path.starts_with(&canary_prefix))
                    .collect();
                // Also filter write violations from the canary home (npm creates
                // .npm/_logs inside fake HOME — expected behavior)
                let real_write_violations: Vec<_> = observations
                    .write_violations
                    .iter()
                    .filter(|v| !v.path.starts_with(&canary_prefix))
                    .collect();
                let has_file_issues =
                    !real_file_alerts.is_empty() || !real_write_violations.is_empty();

                let child_failed = !status.success();
                let has_issues = match &verdict {
                    crate::evidence::KillChainVerdict::Pass => {
                        has_file_issues
                            || child_failed
                            || (strict && !observations.unexpected.is_empty())
                    }
                    crate::evidence::KillChainVerdict::Info { .. } => {
                        has_file_issues
                            || child_failed
                            || (strict && !observations.unexpected.is_empty())
                    }
                    crate::evidence::KillChainVerdict::Warn { .. } => true,
                    crate::evidence::KillChainVerdict::Block { .. } => true,
                };

                if !json_output {
                    if has_issues
                        && !matches!(
                            verdict,
                            crate::evidence::KillChainVerdict::Warn { .. }
                                | crate::evidence::KillChainVerdict::Block { .. }
                        )
                    {
                        // File/write violations or child failure outside of kill chain
                        eprintln!(
                            "\x1b[1m[depsec protect]\x1b[0m \x1b[31m⚠ Issues detected during install\x1b[0m"
                        );
                    }
                    match &verdict {
                        crate::evidence::KillChainVerdict::Pass if !has_issues => {
                            eprintln!("\x1b[32m✓\x1b[0m depsec: install clean");
                        }
                        crate::evidence::KillChainVerdict::Info { reason } if !has_issues => {
                            eprintln!("\x1b[32m✓\x1b[0m depsec: install clean — {reason}");
                        }
                        crate::evidence::KillChainVerdict::Pass
                        | crate::evidence::KillChainVerdict::Info { .. } => {
                            // has_issues from file/write/exit — already printed above
                        }
                        crate::evidence::KillChainVerdict::Warn { reason } => {
                            eprintln!("  \x1b[33m⚠\x1b[0m {reason}");
                        }
                        crate::evidence::KillChainVerdict::Block {
                            reason,
                            canary_kinds,
                            destinations,
                        } => {
                            eprintln!("  \x1b[31m✗ EXFILTRATION DETECTED!\x1b[0m {reason}");
                            for kind in canary_kinds {
                                eprintln!("    \x1b[31m✗\x1b[0m Credential: {kind}");
                            }
                            for dest in destinations {
                                eprintln!("    \x1b[31m✗\x1b[0m Destination: {dest}");
                            }
                        }
                    }
                }

                // Generate attestation (same as unsandboxed path)
                if config.attestation {
                    // Build a MonitorResult-compatible struct for attestation
                    let monitor_result_for_attestation = monitor::MonitorResult {
                        command: command_str.clone(),
                        exit_code: status.code().unwrap_or(-1),
                        duration_secs: observations.duration_secs,
                        connections: observations.connections.clone(),
                        expected: observations.expected.clone(),
                        unexpected: observations.unexpected.clone(),
                        critical: observations.critical.clone(),
                        file_alerts: observations.file_alerts.clone(),
                        write_violations: observations.write_violations.clone(),
                    };
                    let project_name = crate::scanner::detect_project_name(root);
                    let attestation = crate::attestation::generate_attestation(
                        &monitor_result_for_attestation,
                        &project_name,
                        root,
                    );
                    match crate::attestation::save_attestation(&attestation, root) {
                        Ok(path) => {
                            if !json_output {
                                eprintln!("  \x1b[32m✓\x1b[0m Attestation saved to {path}");
                            }
                        }
                        Err(e) => {
                            eprintln!("  \x1b[33m⚠\x1b[0m Failed to save attestation: {e}");
                        }
                    }
                }

                return Ok(InstallGuardResult {
                    command: command_str,
                    exit_code: if has_issues {
                        1
                    } else {
                        status.code().unwrap_or(-1)
                    },
                    has_issues,
                    unexpected_connections: observations.unexpected.len(),
                    critical_connections: observations.critical.len(),
                    file_alerts: observations.file_alerts.len() + canary_accessed.len(),
                    write_violations: observations.write_violations.len(),
                });
            }
            Err(e) => {
                crate::canary::cleanup_canary_tokens(&tokens);
                let _ = std::fs::remove_dir_all(&canary_dir);
                eprintln!("  \x1b[33m⚠\x1b[0m Sandbox execution failed: {e}");
                // Fall through to unsandboxed monitor
            }
        }
    }

    // ── Unsandboxed fallback: run command with monitoring ──

    let baseline_path_buf = root.join(".depsec/monitor-baseline.json");
    let baseline_path = if baseline_path_buf.exists() {
        Some(baseline_path_buf.as_path())
    } else {
        None
    };

    let monitor_result =
        monitor::run_monitor(args, baseline_path, learn, json_output).context("Monitor failed")?;

    let has_critical = !monitor_result.critical.is_empty();
    let has_unexpected = !monitor_result.unexpected.is_empty();
    let has_file_issues =
        !monitor_result.file_alerts.is_empty() || !monitor_result.write_violations.is_empty();
    let has_issues = has_critical || has_file_issues || (strict && has_unexpected);

    if !json_output {
        if learn {
            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m \x1b[36m✓ Learn mode: baseline recorded\x1b[0m"
            );
        }
        if has_issues {
            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m \x1b[31m⚠ Issues detected during install\x1b[0m"
            );
        } else if !learn {
            eprintln!("\x1b[32m✓\x1b[0m depsec: install clean");
        }
    }

    if config.attestation {
        let project_name = crate::scanner::detect_project_name(root);
        let attestation =
            crate::attestation::generate_attestation(&monitor_result, &project_name, root);
        match crate::attestation::save_attestation(&attestation, root) {
            Ok(path) => {
                if !json_output {
                    eprintln!("  \x1b[32m✓\x1b[0m Attestation saved to {path}");
                }
            }
            Err(e) => {
                eprintln!("  \x1b[33m⚠\x1b[0m Failed to save attestation: {e}");
            }
        }
    }

    Ok(InstallGuardResult {
        command: command_str,
        exit_code: if has_issues {
            1
        } else {
            monitor_result.exit_code
        },
        has_issues,
        unexpected_connections: monitor_result.unexpected.len(),
        critical_connections: monitor_result.critical.len(),
        file_alerts: monitor_result.file_alerts.len(),
        write_violations: monitor_result.write_violations.len(),
    })
}

/// Check if any canary token files were tampered with by the sandboxed process.
/// Uses content-hash comparison (not timestamps — APFS timestamps are unreliable).
fn check_canary_access(tokens: &[crate::canary::CanaryToken]) -> Vec<(String, String)> {
    let mut accessed = Vec::new();
    for token in tokens {
        if let Some(access_type) = crate::canary::check_canary_tamper(token) {
            accessed.push((token.kind.clone(), access_type));
        }
    }
    accessed
}

#[derive(Debug, serde::Serialize)]
pub struct InstallGuardResult {
    pub command: String,
    pub exit_code: i32,
    pub has_issues: bool,
    pub unexpected_connections: usize,
    pub critical_connections: usize,
    pub file_alerts: usize,
    pub write_violations: usize,
}

/// Detect if the command is a package install (not just any command)
fn is_install_command(args: &[String]) -> bool {
    if args.len() < 2 {
        return false;
    }

    let cmd = args[0].as_str();
    let subcmd = args[1].as_str();

    matches!(
        (cmd, subcmd),
        ("npm", "install" | "i" | "ci" | "add")
            | ("yarn", "add" | "install")
            | ("pnpm", "add" | "install" | "i")
            | ("pip", "install")
            | ("pip3", "install")
            | ("cargo", "install" | "add")
            | ("go", "get" | "install")
            | ("bundle", "install" | "add")
            | ("gem", "install")
    )
}

/// Extract new package names from install command args
fn extract_new_packages(args: &[String]) -> Vec<String> {
    if args.len() < 3 {
        return vec![]; // No package names specified (bare `npm install`)
    }

    // Skip the command and subcommand, collect package-like args
    args[2..]
        .iter()
        .filter(|a| !a.starts_with('-')) // Skip flags (covers both -f and --flag)
        .cloned()
        .collect()
}

/// Discover packages with install hooks at any depth in node_modules
#[allow(dead_code)] // Used in tests; will be wired into main flow
fn discover_packages_with_hooks(root: &Path) -> Vec<String> {
    let nm = root.join("node_modules");
    if !nm.exists() {
        return vec![];
    }

    let hooks = ["preinstall", "postinstall", "install"];
    let mut result = Vec::new();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_install_command() {
        assert!(is_install_command(&["npm".into(), "install".into()]));
        assert!(is_install_command(&["npm".into(), "i".into()]));
        assert!(is_install_command(&["npm".into(), "ci".into()]));
        assert!(is_install_command(&["npm".into(), "add".into()]));
        assert!(is_install_command(&["yarn".into(), "add".into()]));
        assert!(is_install_command(&["pip".into(), "install".into()]));
        assert!(is_install_command(&["cargo".into(), "install".into()]));
        assert!(is_install_command(&["cargo".into(), "add".into()]));
        assert!(is_install_command(&["bundle".into(), "install".into()]));

        assert!(!is_install_command(&["npm".into(), "run".into()]));
        assert!(!is_install_command(&["npm".into(), "test".into()]));
        assert!(!is_install_command(&["node".into(), "app.js".into()]));
        assert!(!is_install_command(&["npm".into()]));
    }

    #[test]
    fn test_extract_new_packages() {
        assert_eq!(
            extract_new_packages(&["npm".into(), "install".into(), "lodash".into()]),
            vec!["lodash"]
        );
        assert_eq!(
            extract_new_packages(&[
                "npm".into(),
                "install".into(),
                "--save-dev".into(),
                "jest".into()
            ]),
            vec!["jest"]
        );
        assert!(extract_new_packages(&["npm".into(), "install".into()]).is_empty());
        assert_eq!(
            extract_new_packages(&[
                "npm".into(),
                "install".into(),
                "lodash".into(),
                "express".into()
            ]),
            vec!["lodash", "express"]
        );
    }

    #[test]
    fn test_discover_hooks_recursive() {
        let dir = tempfile::TempDir::new().unwrap();
        let nm = dir.path().join("node_modules");

        // Top-level package with postinstall
        let pkg_a = nm.join("pkg-a");
        std::fs::create_dir_all(&pkg_a).unwrap();
        std::fs::write(
            pkg_a.join("package.json"),
            r#"{"name":"pkg-a","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();

        // Nested package with postinstall
        let pkg_b = nm.join("pkg-a/node_modules/pkg-b");
        std::fs::create_dir_all(&pkg_b).unwrap();
        std::fs::write(
            pkg_b.join("package.json"),
            r#"{"name":"pkg-b","scripts":{"postinstall":"node evil.js"}}"#,
        )
        .unwrap();

        // Package without hooks
        let pkg_c = nm.join("pkg-c");
        std::fs::create_dir_all(&pkg_c).unwrap();
        std::fs::write(
            pkg_c.join("package.json"),
            r#"{"name":"pkg-c","scripts":{"start":"node index.js"}}"#,
        )
        .unwrap();

        let hooks = discover_packages_with_hooks(dir.path());
        assert!(hooks.contains(&"pkg-a".to_string()));
        assert!(hooks.contains(&"pkg-b".to_string())); // Nested!
        assert!(!hooks.contains(&"pkg-c".to_string())); // No install hooks
    }

    #[test]
    fn test_discover_hooks_no_node_modules() {
        let dir = tempfile::TempDir::new().unwrap();
        let hooks = discover_packages_with_hooks(dir.path());
        assert!(hooks.is_empty());
    }

    #[test]
    fn test_canary_filter_with_private_prefix() {
        // macOS: /var → /private/var symlink means lsof reports /private/var/...
        // but temp_dir() returns /var/... — canary filter must handle both.
        let canary_prefix = "/private/var/folders/xx/depsec-canary-1234";
        let alert_path = "/private/var/folders/xx/depsec-canary-1234/.ssh/id_rsa";
        assert!(
            alert_path.starts_with(canary_prefix),
            "Canonicalized canary prefix must match lsof paths"
        );

        // Non-canary path should NOT match
        let real_path = "/Users/dev/.ssh/id_rsa";
        assert!(!real_path.starts_with(canary_prefix));
    }

    #[test]
    fn test_check_canary_access_content_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = crate::canary::generate_canary_tokens(dir.path()).unwrap();

        // Untouched canaries — no access detected
        let accessed = check_canary_access(&tokens);
        assert!(
            accessed.is_empty(),
            "Untouched canaries should not trigger access detection"
        );

        // Tamper one canary
        std::fs::write(&tokens[0].path, "STOLEN").unwrap();
        let accessed = check_canary_access(&tokens);
        assert_eq!(accessed.len(), 1);
        assert_eq!(accessed[0].1, "tampered");
    }
}
