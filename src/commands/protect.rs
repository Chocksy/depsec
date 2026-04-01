use std::process::ExitCode;

use crate::{config, install_guard, preflight};

pub struct ProtectOpts {
    pub json: bool,
    pub sandbox: Option<bool>,
    pub learn: bool,
    pub strict: bool,
    pub preflight_only: bool,
}

pub fn run(command: &[String], opts: &ProtectOpts) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let project_config = config::load_config(&root);
    let global_config = config::load_global_config();

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

    // Resolve sandbox: CLI flag > project config > global config > off
    let use_sandbox = config::resolve_sandbox(opts.sandbox, &project_config, &global_config);

    // Full protect mode: preflight + sandbox + monitor + watchdog
    match install_guard::run_install_guard(
        command,
        &root,
        &project_config.install,
        opts.json,
        opts.learn,
        opts.strict,
        use_sandbox,
    ) {
        Ok(result) => {
            if opts.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            }
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
