use std::path::Path;
use std::process::ExitCode;

use crate::llm::LlmApi;
use crate::{config, llm, output, reachability, sarif, scanner, triage, Persona}; // trait import for .model() and .estimate_cost()

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

    // Print banner before spinner so terminal isn't blank during scan
    let is_human = opts
        .format
        .unwrap_or(if opts.json { "json" } else { "human" })
        == "human";
    if is_human {
        eprintln!(
            "depsec v{} \u{2014} Supply Chain Security Scanner\n",
            env!("CARGO_PKG_VERSION")
        );
    }

    let spinner = crate::spinner::Spinner::new("Scanning...");
    let result = scanner::run_scan_with_spinner(root, &config, opts.checks, Some(&spinner));

    // Run reachability inside spinner scope (avoids post-scan hang)
    spinner.set_status("reachability");
    let app_imports = reachability::scan_app_imports(root);
    let categories = reachability::read_package_categories(root);
    spinner.stop();

    match result {
        Ok(mut report) => {
            // Tag findings with reachability + package category
            for result in &mut report.results {
                for finding in &mut result.findings {
                    if let Some(pkg) = &finding.package {
                        // Extract package name, handling scoped packages and @version suffix
                        // "lodash@4.17.21" -> "lodash"
                        // "@scope/name@1.0.0" -> "@scope/name"
                        let pkg_name = if let Some(rest) = pkg.strip_prefix('@') {
                            // Scoped: find the second @ (version separator)
                            match rest.find('@') {
                                Some(pos) => &pkg[..pos + 1],
                                None => pkg.as_str(),
                            }
                        } else {
                            pkg.split('@').next().unwrap_or(pkg)
                        };

                        let is_imported = app_imports.packages.contains(pkg_name);
                        let is_dev = categories.dev.contains(pkg_name);

                        // reachable=true means: runtime dep imported by app
                        // reachable=false means: dev dep, build tool, or not imported
                        finding.reachable = Some(is_imported && !is_dev);
                    }
                }

                // Compound risk tiers: downgrade capability findings for build/dev packages
                if result.category == "capabilities" {
                    for finding in &mut result.findings {
                        if finding.reachable == Some(false) {
                            // Downgrade build-tool capability severity by 1-2 levels
                            finding.severity = match finding.severity {
                                crate::checks::Severity::Critical => {
                                    crate::checks::Severity::Medium
                                }
                                crate::checks::Severity::High => crate::checks::Severity::Low,
                                _ => crate::checks::Severity::Low,
                            };
                            // Soften messaging for build tools
                            if let Some(ref mut suggestion) = finding.suggestion {
                                if suggestion.contains("Remove immediately") {
                                    *suggestion = suggestion.replace(
                                        "Remove immediately",
                                        "Build tool — review if concerned",
                                    );
                                }
                            }
                        }
                    }
                }
            }

            let fmt = opts
                .format
                .unwrap_or(if opts.json { "json" } else { "human" });
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

                    let results =
                        triage::triage_findings(&visible_findings, root, &client, &config.triage);

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
