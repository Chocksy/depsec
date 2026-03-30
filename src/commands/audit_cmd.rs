use std::path::Path;
use std::process::ExitCode;

use crate::{audit, config, llm};
#[allow(unused_imports)]
use crate::llm::LlmApi;

pub fn run(package: &str, root: &Path, dry_run: bool, color: bool) -> ExitCode {
    let config = config::load_config(root);

    let profile = match audit::locate_package(package, root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(2);
        }
    };

    if dry_run {
        print!(
            "{}",
            audit::render_audit_results(
                &audit::AuditResult {
                    profile,
                    findings: vec![],
                    total_tokens: 0,
                    rounds: 0,
                },
                color,
            )
        );
        return ExitCode::SUCCESS;
    }

    let client = match llm::LlmClient::from_config(&config.triage) {
        Some(c) => c,
        None => {
            llm::print_setup_instructions();
            return ExitCode::from(2);
        }
    };

    match audit::run_audit(&profile, &client, &config.triage, false) {
        Ok(result) => {
            print!("{}", audit::render_audit_results(&result, color));
            if result.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("Error during audit: {e}");
            ExitCode::from(2)
        }
    }
}
