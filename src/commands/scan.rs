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
    pub no_triage: bool,
    pub color: bool,
    pub full: bool,
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
                        let pkg_name = if let Some(rest) = pkg.strip_prefix('@') {
                            match rest.find('@') {
                                Some(pos) => &pkg[..pos + 1],
                                None => pkg.as_str(),
                            }
                        } else {
                            pkg.split('@').next().unwrap_or(pkg)
                        };

                        let is_imported = app_imports.packages.contains(pkg_name);
                        let is_dev = categories.dev.contains(pkg_name);
                        finding.reachable = Some(is_imported && !is_dev);
                    }
                }

                // Compound risk tiers: downgrade capability findings for build/dev packages
                if result.category == "capabilities" {
                    for finding in &mut result.findings {
                        if finding.reachable == Some(false) {
                            finding.severity = match finding.severity {
                                crate::checks::Severity::Critical => {
                                    crate::checks::Severity::Medium
                                }
                                crate::checks::Severity::High => crate::checks::Severity::Low,
                                _ => crate::checks::Severity::Low,
                            };
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

            // --- LLM Triage: default ON when API key available ---
            // Determines whether to run LLM triage before rendering output.
            // Priority: --no-triage disables, --triage forces, otherwise auto-detect API key.
            let llm_client: Option<Box<dyn LlmApi>> = if opts.no_triage {
                None
            } else if opts.triage || opts.triage_dry_run {
                // Explicitly requested
                match llm::LlmClient::from_config(&config.triage) {
                    Some(c) => Some(Box::new(c)),
                    None => {
                        if !opts.triage_dry_run {
                            llm::print_setup_instructions();
                        }
                        None
                    }
                }
            } else {
                // Auto-detect: silently check if API key is available
                llm::LlmClient::from_config(&config.triage).map(|c| Box::new(c) as Box<dyn LlmApi>)
            };

            // Collect visible findings for triage
            let visible_findings: Vec<crate::checks::Finding> = report
                .results
                .iter()
                .flat_map(|r| &r.findings)
                .filter(|f| opts.verbose || output::finding_visible(f, opts.persona))
                .cloned()
                .collect();

            // Run triage if client available and findings exist
            let triage_results = if opts.triage_dry_run && !visible_findings.is_empty() {
                triage::dry_run_findings(&visible_findings, root, &config.triage);
                vec![]
            } else if let Some(ref client) = llm_client {
                if visible_findings.is_empty() {
                    vec![]
                } else {
                    let est_tokens = visible_findings.len() as u32 * 2000;
                    let est_cost =
                        client.estimate_cost(est_tokens, visible_findings.len() as u32 * 200);

                    if is_human {
                        eprintln!(
                            "Triaging {} findings with {} (~${:.4})...\n",
                            visible_findings.len(),
                            client.model(),
                            est_cost,
                        );
                    }

                    triage::triage_findings(
                        &visible_findings,
                        root,
                        client.as_ref(),
                        &config.triage,
                    )
                }
            } else {
                vec![]
            };

            // --- Render output ---
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
                    if opts.full || opts.verbose {
                        // --full or --verbose: detailed output (for auditors)
                        print!(
                            "{}",
                            output::render_human(&report, opts.color, opts.persona, opts.verbose)
                        );
                        if !triage_results.is_empty() {
                            print!(
                                "{}",
                                triage::render_triage_results(
                                    &visible_findings,
                                    &triage_results,
                                    opts.color
                                )
                            );
                        }
                    } else if !triage_results.is_empty() {
                        // Definitive mode: package-focused output with LLM verdicts
                        print!(
                            "{}",
                            output::render_definitive(
                                &report,
                                &triage_results,
                                &visible_findings,
                                opts.color,
                                opts.persona,
                            )
                        );
                    } else {
                        // Static-only mode: executive summary
                        print!(
                            "{}",
                            output::render_executive(&report, opts.color, opts.persona)
                        );
                        if llm_client.is_none() && !opts.no_triage && !visible_findings.is_empty() {
                            eprintln!(
                                "\n\x1b[2mTip: Set OPENROUTER_API_KEY for AI-powered definitive verdicts\x1b[0m"
                            );
                        }
                    }
                }
            }

            // --- Exit code ---
            // With triage: only True Positives count as issues
            // Without triage: any visible finding counts (existing behavior)
            let has_issues = if !triage_results.is_empty() {
                // LLM triaged: only TP findings are real issues
                triage_results.iter().any(|(_, result, _)| {
                    matches!(result.classification, triage::Classification::TruePositive)
                })
            } else {
                // Static-only: any visible finding
                !visible_findings.is_empty()
            };

            if has_issues {
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
