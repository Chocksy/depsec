mod ast;
#[allow(dead_code)]
mod attestation;
mod audit;
mod baseline;
#[allow(dead_code)]
mod canary;
mod checks;
mod commands;
mod config;
mod fixer;
mod install_guard;
mod llm;
mod monitor;
mod output;
mod parsers;
mod preflight;
mod reachability;
mod rules;
#[allow(dead_code)]
mod sandbox;
mod sarif;
mod scanner;
mod scorecard;
mod scoring;
mod secrets_ast;
mod selfcheck;
mod shellhook;
mod triage;
mod triage_cache;
mod utils;
mod watchdog;

use std::path::{Path, PathBuf};
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
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_delimiter = ',')]
        checks: Option<Vec<String>>,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[arg(long, value_enum, default_value = "regular")]
        persona: Persona,
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        triage: bool,
        #[arg(long)]
        triage_dry_run: bool,
    },
    /// Auto-fix security issues
    Fix {
        #[arg(default_value = ".")]
        path: PathBuf,
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
        #[arg(long)]
        learn: bool,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Pre-install threat analysis
    Preflight {
        #[arg(default_value = ".")]
        path: PathBuf,
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
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Generate shell aliases for invisible protection
    ShellHook,
    /// Generate SVG scorecard image
    Scorecard {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long, default_value = "depsec-scorecard.svg")]
        output: PathBuf,
    },
    /// Protected package install — preflight + monitor + report
    InstallGuard {
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Deep security audit of a specific package
    Audit {
        package: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "5.0")]
        budget: f64,
    },
    /// Install/uninstall git pre-commit hook for secret detection
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Check staged files for secrets (used by pre-commit hook)
    SecretsCheck {
        #[arg(long)]
        staged: bool,
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Manage build attestations
    Attestation {
        #[command(subcommand)]
        action: AttestationAction,
    },
    /// Manage triage cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Output badge markdown
    Badge {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum HookAction {
    Install,
    Uninstall,
}

#[derive(Subcommand)]
enum AttestationAction {
    Verify {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Summary {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum CacheAction {
    Clear,
    Stats,
}

#[derive(Subcommand)]
enum RulesAction {
    List,
    Update,
    Add { path: PathBuf },
}

#[derive(Subcommand)]
enum BaselineAction {
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Check {
        #[arg(long)]
        capture: Option<PathBuf>,
    },
}

fn use_color(no_color_flag: bool) -> bool {
    if no_color_flag || std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    true
}

fn canonicalize_or_exit(path: &Path) -> Result<PathBuf, ExitCode> {
    path.canonicalize().map_err(|e| {
        eprintln!("Error: invalid path '{}': {e}", path.display());
        ExitCode::from(2)
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = use_color(cli.no_color);

    match cli.command {
        Commands::Scan {
            path, checks, json, format, persona, verbose, triage, triage_dry_run,
        } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::scan::run(&root, &commands::scan::ScanOpts {
                checks: checks.as_deref(),
                format: format.as_deref(),
                json,
                persona,
                verbose,
                triage,
                triage_dry_run,
                color,
            })
        }

        Commands::Fix { path, dry_run } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::misc::fix(&root, dry_run)
        }

        Commands::Monitor { learn, strict, json, baseline, command } => {
            commands::misc::monitor_cmd(&command, baseline.as_deref(), learn, json, strict)
        }

        Commands::Preflight { path, json } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::misc::preflight(&root, json)
        }

        Commands::Rules { action } => match action {
            RulesAction::List => commands::misc::rules_list(),
            RulesAction::Update => commands::misc::rules_update(),
            RulesAction::Add { path } => commands::misc::rules_add(&path),
        },

        Commands::Baseline { action } => match action {
            BaselineAction::Init { path } => {
                let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
                commands::misc::baseline_init(&root)
            }
            BaselineAction::Check { capture } => {
                commands::misc::baseline_check(capture.as_deref(), color)
            }
        },

        Commands::SelfCheck { path } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::misc::self_check(&root)
        }

        Commands::ShellHook => commands::misc::shell_hook(),

        Commands::Scorecard { path, output } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::misc::scorecard(&root, &output)
        }

        Commands::InstallGuard { json, command } => {
            commands::misc::install_guard(&command, json)
        }

        Commands::Audit { package, path, dry_run, budget: _ } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::audit_cmd::run(&package, &root, dry_run, color)
        }

        Commands::Hook { action } => match action {
            HookAction::Install => commands::hook::install(),
            HookAction::Uninstall => commands::hook::uninstall(),
        },

        Commands::SecretsCheck { staged, path } => {
            let root = path.canonicalize().unwrap_or(path);
            commands::secrets::check(staged, &root)
        }

        Commands::Attestation { action } => match action {
            AttestationAction::Verify { path } => {
                let root = path.canonicalize().unwrap_or(path);
                commands::misc::attestation_verify(&root)
            }
            AttestationAction::Summary { path } => {
                let root = path.canonicalize().unwrap_or(path);
                commands::misc::attestation_summary(&root)
            }
        },

        Commands::Cache { action } => match action {
            CacheAction::Clear => commands::misc::cache_clear(),
            CacheAction::Stats => commands::misc::cache_stats(),
        },

        Commands::Badge { path } => {
            let root = match canonicalize_or_exit(&path) { Ok(r) => r, Err(e) => return e };
            commands::misc::badge(&root)
        }
    }
}
