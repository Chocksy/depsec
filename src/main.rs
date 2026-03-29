mod ast;
mod audit;
mod baseline;
mod checks;
mod config;
mod fixer;
mod llm;
mod monitor;
mod output;
mod parsers;
mod preflight;
mod reachability;
mod rules;
mod sarif;
mod scanner;
mod scorecard;
mod scoring;
mod selfcheck;
mod shellhook;
mod triage;
mod triage_cache;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Persona {
    /// High-confidence findings only (default — minimal noise)
    Regular,
    /// Medium+ confidence findings
    Pedantic,
    /// All findings including low confidence
    Auditor,
}

#[derive(Parser)]
#[command(name = "depsec", version, about = "Supply Chain Security Scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run security checks on a project
    Scan {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Comma-separated list of checks to run
        #[arg(long, value_delimiter = ',')]
        checks: Option<Vec<String>>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output format: human (default), json, sarif
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Finding visibility level: regular (high-confidence only), pedantic (medium+), auditor (all)
        #[arg(long, value_enum, default_value = "regular")]
        persona: Persona,

        /// Show all findings (no persona filtering, no aggregation)
        #[arg(long)]
        verbose: bool,

        /// Run LLM triage on findings (requires OPENROUTER_API_KEY)
        #[arg(long)]
        triage: bool,

        /// Show what would be sent to LLM without making API calls
        #[arg(long)]
        triage_dry_run: bool,
    },

    /// Auto-fix security issues
    Fix {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Preview changes without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Manage network baselines
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Monitor network activity of a command
    Monitor {
        /// Record connections as expected (learning mode)
        #[arg(long)]
        learn: bool,

        /// Fail on unexpected connections
        #[arg(long)]
        strict: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Path to baseline file
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Command and arguments to monitor
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Pre-install threat analysis
    Preflight {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Verify depsec's own integrity
    SelfCheck {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Generate shell aliases for invisible protection
    ShellHook,

    /// Generate SVG scorecard image
    Scorecard {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output file (default: depsec-scorecard.svg)
        #[arg(short, long, default_value = "depsec-scorecard.svg")]
        output: PathBuf,
    },

    /// Deep security audit of a specific package
    Audit {
        /// Package name to audit (e.g., shelljs, @scope/pkg)
        package: String,

        /// Path to the project root
        #[arg(long, default_value = ".")]
        path: PathBuf,

        /// Preview what would be analyzed without calling LLM
        #[arg(long)]
        dry_run: bool,

        /// Maximum budget in USD
        #[arg(long, default_value = "5.0")]
        budget: f64,
    },

    /// Manage triage cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Output badge markdown
    Badge {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum CacheAction {
    /// Clear all cached triage results
    Clear,
    /// Show cache statistics
    Stats,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all active rules
    List,

    /// Update rules from community repository
    Update,

    /// Add a custom rule file
    Add {
        /// Path to the rule file
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Generate a network baseline file
    Init {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Compare CI run against baseline
    Check {
        /// Path to the capture file
        #[arg(long)]
        capture: Option<PathBuf>,
    },
}

fn use_color(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    true
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = use_color(cli.no_color);

    match cli.command {
        Commands::Scan {
            path,
            checks,
            json,
            format,
            persona,
            verbose,
            triage,
            triage_dry_run,
        } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            let config = config::load_config(&root);
            let filter = checks.as_deref();

            match scanner::run_scan(&root, &config, filter) {
                Ok(mut report) => {
                    // Tag pattern findings with reachability
                    let app_imports = reachability::scan_app_imports(&root);
                    for result in &mut report.results {
                        for finding in &mut result.findings {
                            if let Some(pkg) = &finding.package {
                                finding.reachable = Some(app_imports.packages.contains(pkg));
                            }
                        }
                    }

                    let fmt = format
                        .as_deref()
                        .unwrap_or(if json { "json" } else { "human" });
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
                            print!("{}", output::render_human(&report, color, persona, verbose));
                        }
                    }

                    // LLM triage (optional)
                    if triage || triage_dry_run {
                        // Collect visible findings for triage
                        let visible_findings: Vec<crate::checks::Finding> = report
                            .results
                            .iter()
                            .flat_map(|r| &r.findings)
                            .filter(|f| verbose || output::finding_visible(f, persona))
                            .cloned()
                            .collect();

                        if visible_findings.is_empty() {
                            eprintln!("No findings to triage.");
                        } else if triage_dry_run {
                            // Dry run: show what would be sent, no API calls needed
                            triage::dry_run_findings(&visible_findings, &root, &config.triage);
                        } else {
                            // Real triage: requires API key
                            let client = match llm::LlmClient::from_config(&config.triage) {
                                Some(c) => c,
                                None => {
                                    llm::print_setup_instructions();
                                    return ExitCode::from(2);
                                }
                            };

                            let est_tokens = visible_findings.len() as u32 * 2000;
                            let est_cost = client
                                .estimate_cost(est_tokens, visible_findings.len() as u32 * 200);
                            eprintln!(
                                "\nTriaging {} findings with {} (~${:.4} estimated)...\n",
                                visible_findings.len(),
                                client.model(),
                                est_cost,
                            );

                            let results = triage::triage_findings(
                                &visible_findings,
                                &root,
                                &client,
                                &config.triage,
                            );

                            print!(
                                "{}",
                                triage::render_triage_results(&visible_findings, &results, color)
                            );
                        }
                    }

                    // Exit code respects persona: only visible findings cause non-zero exit
                    let has_visible_findings = report.results.iter().any(|r| {
                        r.findings
                            .iter()
                            .any(|f| verbose || output::finding_visible(f, persona))
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

        Commands::Fix { path, dry_run } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            match fixer::fix_workflow_pinning(&root, dry_run) {
                Ok(results) => {
                    fixer::print_fix_results(&results, dry_run);
                    let any_failed = results.iter().any(|r| !r.applied);
                    if any_failed {
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

        Commands::Monitor {
            learn,
            strict,
            json,
            baseline,
            command,
        } => match monitor::run_monitor(&command, baseline.as_deref(), learn, json) {
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
        },

        Commands::Preflight { path, json } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            match preflight::run_preflight(&root, json) {
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

        Commands::Rules { action } => {
            let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
            match action {
                RulesAction::List => {
                    rules::list_rules(&root);
                    ExitCode::SUCCESS
                }
                RulesAction::Update => match rules::update_rules(&root) {
                    Ok(count) => {
                        println!("{count} rules updated.");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        ExitCode::from(2)
                    }
                },
                RulesAction::Add { path } => match rules::add_rule(&root, &path) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        ExitCode::from(2)
                    }
                },
            }
        }

        Commands::Baseline { action } => match action {
            BaselineAction::Init { path } => {
                let root = match path.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: invalid path '{}': {e}", path.display());
                        return ExitCode::from(2);
                    }
                };

                match baseline::init_baseline(&root) {
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
            BaselineAction::Check { capture } => {
                let root = std::env::current_dir().unwrap_or_else(|_| ".".into());

                match baseline::check_baseline(&root, capture.as_deref()) {
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
        },

        Commands::SelfCheck { path } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };
            selfcheck::run_self_check(&root);
            ExitCode::SUCCESS
        }

        Commands::ShellHook => {
            print!("{}", shellhook::generate_shell_hook());
            ExitCode::SUCCESS
        }

        Commands::Scorecard { path, output } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            let config = config::load_config(&root);
            match scanner::run_scan(&root, &config, None) {
                Ok(report) => {
                    let svg = scorecard::generate_svg(&report);
                    match std::fs::write(&output, &svg) {
                        Ok(()) => {
                            println!("Scorecard saved to {}", output.display());
                            println!(
                                "Add to README: <img src=\"{}\" width=\"480\">",
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

        Commands::Audit {
            package,
            path,
            dry_run,
            budget: _budget,
        } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            let config = config::load_config(&root);

            // Locate and profile the package
            let profile = match audit::locate_package(&package, &root) {
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

            // Require API key for real audit
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

        Commands::Cache { action } => match action {
            CacheAction::Clear => match triage_cache::clear_cache() {
                Ok(count) => {
                    println!("Cleared {count} cached triage results.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error clearing cache: {e}");
                    ExitCode::from(2)
                }
            },
            CacheAction::Stats => {
                let (count, size) = triage_cache::cache_stats();
                println!(
                    "Triage cache: {count} entries, {:.1}KB",
                    size as f64 / 1024.0
                );
                ExitCode::SUCCESS
            }
        },

        Commands::Badge { path } => {
            let root = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: invalid path '{}': {e}", path.display());
                    return ExitCode::from(2);
                }
            };

            let config = config::load_config(&root);

            match scanner::run_scan(&root, &config, None) {
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
    }
}
