use std::process::ExitCode;

use crate::{config, install_guard, preflight};

pub struct ProtectOpts {
    pub json: bool,
    #[allow(dead_code)] // Scaffolded for sandbox integration
    pub sandbox: bool,
    #[allow(dead_code)] // Scaffolded for learn mode
    pub learn: bool,
    #[allow(dead_code)] // Scaffolded for strict mode
    pub strict: bool,
    pub preflight_only: bool,
}

pub fn run(command: &[String], opts: &ProtectOpts) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let config = config::load_config(&root);

    // Preflight-only mode: just run typosquat/metadata checks
    if opts.preflight_only {
        return match preflight::run_preflight(&root, opts.json) {
            Ok(result) => {
                let has_high = result.findings.iter().any(|f| {
                    matches!(
                        f.severity,
                        crate::checks::Severity::Critical | crate::checks::Severity::High
                    )
                });
                if has_high {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::from(2)
            }
        };
    }

    // Full protect mode: preflight + monitor + watchdog (via install-guard)
    match install_guard::run_install_guard(command, &root, &config.install, opts.json) {
        Ok(result) => {
            if result.has_issues {
                ExitCode::from(1)
            } else {
                ExitCode::from(result.exit_code as u8)
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}
