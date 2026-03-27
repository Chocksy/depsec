mod baseline;
mod checks;
mod config;
mod fixer;
mod monitor;
mod output;
mod parsers;
mod preflight;
mod rules;
mod sarif;
mod scanner;
mod scoring;
mod selfcheck;
mod shellhook;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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

    /// Output badge markdown
    Badge {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },
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
                Ok(report) => {
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
                            print!("{}", output::render_human(&report, color));
                        }
                    }

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
