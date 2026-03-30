use std::path::Path;

use anyhow::{Context, Result};

use crate::config::InstallConfig;
use crate::monitor;
use crate::sandbox;

/// Run the install-guard pipeline: preflight → monitor (with watchdog) → report
pub fn run_install_guard(
    args: &[String],
    root: &Path,
    config: &InstallConfig,
    json_output: bool,
) -> Result<InstallGuardResult> {
    if args.is_empty() {
        anyhow::bail!("No command specified. Usage: depsec install-guard <command> [args...]");
    }

    let command_str = args.join(" ");

    // Detect if this is an install command (not just any command)
    let is_install = is_install_command(args);

    // Phase 1: Preflight check (for install commands with new packages)
    if config.preflight && is_install {
        let new_packages = extract_new_packages(args);
        if !new_packages.is_empty() {
            eprintln!(
                "\n\x1b[1m[depsec install-guard]\x1b[0m Running preflight check on {} new package{}...",
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

    // Phase 1.5: Optional sandbox pre-check
    if config.mode == "sandbox" || config.sandbox == "auto" {
        let sandbox_type = sandbox::detect_sandbox(&config.sandbox);
        if sandbox_type != sandbox::SandboxType::None {
            eprintln!(
                "\x1b[1m[depsec install-guard]\x1b[0m Running sandbox pre-check ({sandbox_type})..."
            );
            match sandbox::run_sandboxed(args, root, &sandbox_type) {
                Ok(result) => {
                    if result.success {
                        eprintln!("  \x1b[32m✓\x1b[0m Sandbox pre-check passed");
                    } else {
                        eprintln!(
                            "  \x1b[31m⚠\x1b[0m Sandbox pre-check failed (exit code {})",
                            result.exit_code
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  \x1b[33m⚠\x1b[0m Sandbox pre-check skipped: {e}");
                }
            }
        }
    }

    // Phase 2: Run the command with monitoring
    eprintln!("\x1b[1m[depsec install-guard]\x1b[0m Monitoring: {command_str}");

    let monitor_result =
        monitor::run_monitor(args, None, false, json_output).context("Monitor failed")?;

    // Phase 3: Summarize results
    let has_issues = !monitor_result.unexpected.is_empty()
        || !monitor_result.critical.is_empty()
        || !monitor_result.file_alerts.is_empty()
        || !monitor_result.write_violations.is_empty();

    if !json_output {
        eprintln!();
        if has_issues {
            eprintln!(
                "\x1b[1m[depsec install-guard]\x1b[0m \x1b[31m⚠ Issues detected during install\x1b[0m"
            );
        } else {
            eprintln!(
                "\x1b[1m[depsec install-guard]\x1b[0m \x1b[32m✓ Install completed cleanly\x1b[0m"
            );
        }
    }

    Ok(InstallGuardResult {
        command: command_str,
        exit_code: monitor_result.exit_code,
        has_issues,
        unexpected_connections: monitor_result.unexpected.len(),
        critical_connections: monitor_result.critical.len(),
        file_alerts: monitor_result.file_alerts.len(),
        write_violations: monitor_result.write_violations.len(),
    })
}

#[derive(Debug)]
#[allow(dead_code)]
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
        .filter(|a| !a.starts_with('-')) // Skip flags
        .filter(|a| !a.starts_with("--")) // Skip long flags
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
