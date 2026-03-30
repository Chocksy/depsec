use std::path::Path;
use std::process::ExitCode;

use crate::{config, llm, output, reachability, sarif, scanner, triage, Persona};
use crate::llm::LlmApi; // trait import for .model() and .estimate_cost()

pub struct ScanOpts<'a> {
    pub checks: Option<&'a [String]>,
    pub format: Option<&'a str>,
    pub json: bool,
    pub persona: Persona,
    pub verbose: bool,
    pub triage: bool,
    pub triage_dry_run: bool,
    pub color: bool,
}

pub fn run(root: &Path, opts: &ScanOpts) -> ExitCode {
    let config = config::load_config(root);

    match scanner::run_scan(root, &config, opts.checks) {
        Ok(mut report) => {
            // Tag pattern findings with reachability
            let app_imports = reachability::scan_app_imports(root);
            for result in &mut report.results {
                for finding in &mut result.findings {
                    if let Some(pkg) = &finding.package {
                        finding.reachable = Some(app_imports.packages.contains(pkg));
                    }
                }
            }

            let fmt = opts.format.unwrap_or(if opts.json { "json" } else { "human" });
            match fmt {
                "json" => match output::render_json(&report) {
                    Ok(json_str) => println!("{json_str}"),
                    Err(e) => {
                        eprintln!("Error rendering JSON: {e}");
                        return ExitCode::from(2);
                    }
                },
                "sarif" => match sarif::render_sarif(&report) {
                    Ok(sarif_str) => println!("{sarif_str}"),
                    Err(e) => {
                        eprintln!("Error rendering SARIF: {e}");
                        return ExitCode::from(2);
                    }
                },
                _ => {
                    print!(
                        "{}",
                        output::render_human(&report, opts.color, opts.persona, opts.verbose)
                    );
                }
            }

            // LLM triage (optional)
            if opts.triage || opts.triage_dry_run {
                let visible_findings: Vec<crate::checks::Finding> = report
                    .results
                    .iter()
                    .flat_map(|r| &r.findings)
                    .filter(|f| opts.verbose || output::finding_visible(f, opts.persona))
                    .cloned()
                    .collect();

                if visible_findings.is_empty() {
                    eprintln!("No findings to triage.");
                } else if opts.triage_dry_run {
                    triage::dry_run_findings(&visible_findings, root, &config.triage);
                } else {
                    let client = match llm::LlmClient::from_config(&config.triage) {
                        Some(c) => c,
                        None => {
                            llm::print_setup_instructions();
                            return ExitCode::from(2);
                        }
                    };

                    let est_tokens = visible_findings.len() as u32 * 2000;
                    let est_cost =
                        client.estimate_cost(est_tokens, visible_findings.len() as u32 * 200);
                    eprintln!(
                        "\nTriaging {} findings with {} (~${:.4} estimated)...\n",
                        visible_findings.len(),
                        client.model(),
                        est_cost,
                    );

                    let results = triage::triage_findings(
                        &visible_findings,
                        root,
                        &client,
                        &config.triage,
                    );

                    print!(
                        "{}",
                        triage::render_triage_results(&visible_findings, &results, opts.color)
                    );
                }
            }

            // Exit code respects persona
            let has_visible_findings = report.results.iter().any(|r| {
                r.findings
                    .iter()
                    .any(|f| opts.verbose || output::finding_visible(f, opts.persona))
            });

            if has_visible_findings {
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
