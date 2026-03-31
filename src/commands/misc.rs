use std::path::Path;
use std::process::ExitCode;

use crate::{
    attestation, baseline, config, fixer, install_guard, monitor, preflight, rules, scanner,
    scorecard, selfcheck, shellhook, triage_cache,
};

pub fn fix(root: &Path, dry_run: bool) -> ExitCode {
    match fixer::fix_workflow_pinning(root, dry_run) {
        Ok(results) => {
            fixer::print_fix_results(&results, dry_run);
            if results.iter().any(|r| !r.applied) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn monitor_cmd(
    command: &[String],
    baseline: Option<&Path>,
    learn: bool,
    json: bool,
    strict: bool,
) -> ExitCode {
    match monitor::run_monitor(command, baseline, learn, json) {
        Ok(result) => {
            let has_critical = !result.critical.is_empty();
            let has_unexpected = !result.unexpected.is_empty();
            if has_critical || (strict && has_unexpected) {
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

pub fn preflight(root: &Path, json: bool) -> ExitCode {
    match preflight::run_preflight(root, json) {
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
    }
}

pub fn rules_list() -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    rules::list_rules(&root);
    ExitCode::SUCCESS
}

pub fn rules_update() -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    match rules::update_rules(&root) {
        Ok(count) => {
            println!("{count} rules updated.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn rules_add(path: &Path) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    match rules::add_rule(&root, path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn baseline_init(root: &Path) -> ExitCode {
    match baseline::init_baseline(root) {
        Ok(output_path) => {
            println!("Baseline created: {output_path}");
            println!("Edit allowed_hosts and commit the file.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn baseline_check(capture: Option<&Path>, color: bool) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    match baseline::check_baseline(&root, capture) {
        Ok(result) => {
            baseline::print_baseline_check(&result, color);
            if result.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn self_check(root: &Path) -> ExitCode {
    selfcheck::run_self_check(root);
    ExitCode::SUCCESS
}

pub fn shell_hook() -> ExitCode {
    print!("{}", shellhook::generate_shell_hook());
    ExitCode::SUCCESS
}

pub fn scorecard(root: &Path, output: &Path) -> ExitCode {
    let config = config::load_config(root);
    match scanner::run_scan(root, &config, None) {
        Ok(report) => {
            let svg = scorecard::generate_svg(&report);
            match std::fs::write(output, &svg) {
                Ok(()) => {
                    println!("Scorecard saved to {}", output.display());
                    println!(
                        "Add to README: <img src=\"{}\" width=\"800\">",
                        output.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error writing scorecard: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn install_guard(command: &[String], json: bool) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let config = config::load_config(&root);
    match install_guard::run_install_guard(
        command,
        &root,
        &config.install,
        json,
        false,
        false,
        false,
    ) {
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

pub fn attestation_verify(root: &Path) -> ExitCode {
    match attestation::verify_attestation(root) {
        Ok(result) => {
            println!("{}", result.message);
            if result.valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn attestation_summary(root: &Path) -> ExitCode {
    match attestation::attestation_summary(root) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn cache_clear() -> ExitCode {
    match triage_cache::clear_cache() {
        Ok(count) => {
            println!("Cleared {count} cached triage results.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error clearing cache: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn cache_stats() -> ExitCode {
    let (count, size) = triage_cache::cache_stats();
    println!(
        "Triage cache: {count} entries, {:.1}KB",
        size as f64 / 1024.0
    );
    ExitCode::SUCCESS
}

pub fn badge(root: &Path) -> ExitCode {
    let config = config::load_config(root);
    match scanner::run_scan(root, &config, None) {
        Ok(report) => {
            let color_code = report.grade.color_code();
            println!(
                "[![DepSec Score](https://img.shields.io/badge/depsec-{}-{color_code})](https://github.com/chocksy/depsec)",
                report.grade
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}
