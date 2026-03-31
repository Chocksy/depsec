use std::path::Path;
use std::process::ExitCode;

use crate::{baseline, config, output, reachability, sarif, scanner};

pub fn run(root: &Path, checks: Option<&[String]>) -> ExitCode {
    let config = config::load_config(root);

    match scanner::run_scan(root, &config, checks) {
        Ok(mut report) => {
            // Tag findings with reachability
            let app_imports = reachability::scan_app_imports(root);
            for result in &mut report.results {
                for finding in &mut result.findings {
                    if let Some(pkg) = &finding.package {
                        finding.reachable = Some(app_imports.packages.contains(pkg));
                    }
                }
            }

            // Output SARIF (CI-native format)
            match sarif::render_sarif(&report) {
                Ok(sarif_str) => println!("{sarif_str}"),
                Err(e) => {
                    eprintln!("Error rendering SARIF: {e}");
                    return ExitCode::from(2);
                }
            }

            // Also print human summary to stderr for CI logs
            eprint!(
                "{}",
                output::render_human(&report, false, crate::Persona::Regular, false)
            );

            // Check network baseline if file exists
            let baseline_file = root.join("depsec.baseline.json");
            if baseline_file.exists() {
                // Baseline check is informational in CI — don't fail the job
                if let Ok(result) = baseline::check_baseline(root, None) {
                    baseline::print_baseline_check(&result, false);
                }
            }

            // Exit code: 0 = clean, 1 = findings
            let has_findings = report.results.iter().any(|r| !r.findings.is_empty());

            if has_findings {
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
