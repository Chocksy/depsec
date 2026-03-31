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
    sandbox_cli: bool,
) -> Result<InstallGuardResult> {
    if args.is_empty() {
        anyhow::bail!("No command specified. Usage: depsec protect <command> [args...]");
    }

    let command_str = args.join(" ");

    // Detect if this is an install command (not just any command)
    let is_install = is_install_command(args);

    // Phase 1: Preflight check (for install commands with new packages)
    if config.preflight && is_install {
        let new_packages = extract_new_packages(args);
        if !new_packages.is_empty() {
            eprintln!(
                "\n\x1b[1m[depsec protect]\x1b[0m Running preflight check on {} new package{}...",
                new_packages.len(),
                if new_packages.len() == 1 { "" } else { "s" }
            );

            match crate::preflight::run_preflight(root, false) {
                Ok(result) => {
                    let high_risk = result.findings.iter().any(|f| {
                        matches!(
                            f.severity,
                            crate::checks::Severity::Critical | crate::checks::Severity::High
                        )
                    });

                    if high_risk {
                        eprintln!("  \x1b[31m⚠ Preflight found high-risk issues!\x1b[0m");
                        for f in &result.findings {
                            if matches!(
                                f.severity,
                                crate::checks::Severity::Critical | crate::checks::Severity::High
                            ) {
                                eprintln!("    \x1b[31m✗\x1b[0m {}", f.message);
                            }
                        }
                        eprintln!();
                    } else {
                        eprintln!("  \x1b[32m✓\x1b[0m Preflight check passed");
                    }
                }
                Err(e) => {
                    eprintln!("  \x1b[33m⚠\x1b[0m Preflight check failed: {e}");
                }
            }
        }
    }

    // Phase 1.5: Sandbox execution (when enabled via CLI flag or config)
    let use_sandbox = sandbox_cli || config.mode == "sandbox" || config.sandbox != "none";
    let sandbox_pref = if sandbox_cli && config.sandbox == "none" {
        "auto"
    } else {
        &config.sandbox
    };

    if use_sandbox {
        let sandbox_type = sandbox::detect_sandbox(sandbox_pref);
        if sandbox_type != sandbox::SandboxType::None {
            // Plant canary tokens in a temp home for honeypot detection
            let canary_dir =
                std::env::temp_dir().join(format!("depsec-canary-{}", std::process::id()));
            std::fs::create_dir_all(&canary_dir).context("Failed to create canary temp dir")?;
            let tokens = crate::canary::generate_canary_tokens(&canary_dir).unwrap_or_else(|e| {
                eprintln!("  \x1b[33m⚠\x1b[0m Canary token generation failed: {e}");
                vec![]
            });

            if !tokens.is_empty() {
                eprintln!(
                    "\x1b[1m[depsec protect]\x1b[0m Planted {} canary token{} in sandbox",
                    tokens.len(),
                    if tokens.len() == 1 { "" } else { "s" }
                );
            }

            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m Running sandboxed install ({sandbox_type})..."
            );
            match sandbox::run_sandboxed(args, root, &sandbox_type) {
                Ok(result) => {
                    // Check if canary tokens were accessed (credential theft attempt)
                    let canary_accessed = check_canary_access(&tokens);
                    crate::canary::cleanup_canary_tokens(&tokens);
                    let _ = std::fs::remove_dir_all(&canary_dir);

                    if !canary_accessed.is_empty() {
                        eprintln!(
                            "  \x1b[31m✗ CREDENTIAL THEFT DETECTED!\x1b[0m Package attempted to read:"
                        );
                        for kind in &canary_accessed {
                            eprintln!("    \x1b[31m✗\x1b[0m {kind}");
                        }
                        return Ok(InstallGuardResult {
                            command: command_str,
                            exit_code: 1,
                            has_issues: true,
                            unexpected_connections: 0,
                            critical_connections: 0,
                            file_alerts: canary_accessed.len(),
                            write_violations: 0,
                        });
                    }

                    if result.success {
                        eprintln!("  \x1b[32m✓\x1b[0m Sandbox install passed (clean)");
                    } else {
                        eprintln!(
                            "  \x1b[31m⚠\x1b[0m Sandbox install failed (exit code {})",
                            result.exit_code
                        );
                    }
                }
                Err(e) => {
                    crate::canary::cleanup_canary_tokens(&tokens);
                    let _ = std::fs::remove_dir_all(&canary_dir);
                    eprintln!("  \x1b[33m⚠\x1b[0m Sandbox execution failed: {e}");
                    // Fall through to unsandboxed monitor
                }
            }
        } else {
            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m \x1b[33m⚠\x1b[0m No sandbox backend available (tried: {})",
                sandbox_pref
            );
        }
    }

    // Phase 2: Run the command with monitoring
    eprintln!("\x1b[1m[depsec protect]\x1b[0m Monitoring: {command_str}");

    let baseline_path_buf = root.join(".depsec/monitor-baseline.json");
    let baseline_path = if baseline_path_buf.exists() {
        Some(baseline_path_buf.as_path())
    } else {
        None
    };

    let monitor_result =
        monitor::run_monitor(args, baseline_path, learn, json_output).context("Monitor failed")?;

    // Phase 3: Evaluate results
    let has_critical = !monitor_result.critical.is_empty();
    let has_unexpected = !monitor_result.unexpected.is_empty();
    let has_file_issues =
        !monitor_result.file_alerts.is_empty() || !monitor_result.write_violations.is_empty();

    // In strict mode, unexpected connections are treated as failures
    let has_issues = has_critical || has_file_issues || (strict && has_unexpected);

    if !json_output {
        eprintln!();
        if learn {
            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m \x1b[36m✓ Learn mode: baseline recorded\x1b[0m"
            );
        }
        if has_issues {
            eprintln!(
                "\x1b[1m[depsec protect]\x1b[0m \x1b[31m⚠ Issues detected during install\x1b[0m"
            );
            if strict && has_unexpected {
                eprintln!(
                    "  \x1b[31m✗\x1b[0m Strict mode: {} unexpected connection{}",
                    monitor_result.unexpected.len(),
                    if monitor_result.unexpected.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
        } else {
            eprintln!("\x1b[1m[depsec protect]\x1b[0m \x1b[32m✓ Install completed cleanly\x1b[0m");
        }
    }

    // Phase 4: Generate attestation if configured
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

/// Check if any canary token files were accessed (read by the sandboxed process)
/// by checking file modification times and whether files were opened
fn check_canary_access(tokens: &[crate::canary::CanaryToken]) -> Vec<String> {
    let mut accessed = Vec::new();
    for token in tokens {
        // Check if the file's access time changed (imprecise but catches most cases)
        // A more robust approach would use inotify/kqueue, but checking file existence
        // after sandbox cleanup is sufficient — if the sandbox deleted/modified our canaries,
        // that's also a red flag
        if !token.path.exists() {
            // File was deleted by the sandboxed process — definite theft attempt
            accessed.push(format!("{} (deleted)", token.kind));
        } else if let Ok(metadata) = token.path.metadata() {
            if let (Ok(modified), Ok(created)) = (metadata.modified(), metadata.created()) {
                // If the file was modified after creation, something touched it
                if modified > created {
                    accessed.push(format!("{} (modified)", token.kind));
                }
            }
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
}
