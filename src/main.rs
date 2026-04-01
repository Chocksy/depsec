mod ast;

mod attestation;
mod audit;
mod baseline;

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

mod sandbox;
mod sarif;
mod scanner;
mod scorecard;
mod scoring;
mod secrets_ast;
mod selfcheck;
mod shellhook;
mod spinner;
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
    // ── Core Commands ──────────────────────────────────────────
    /// Scan project for security issues
    Scan {
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
        /// Show full detailed output (default shows executive summary)
        #[arg(long)]
        full: bool,
        /// Strict mode: show all findings including low-confidence
        #[arg(long)]
        strict: bool,
        /// Relaxed mode: show medium+ confidence findings
        #[arg(long)]
        relaxed: bool,
        /// Show all findings including build tools (no filtering)
        #[arg(long)]
        verbose: bool,
        /// Run LLM triage on findings
        #[arg(long)]
        triage: bool,
        /// Show what would be sent to LLM
        #[arg(long)]
        triage_dry_run: bool,
        /// Only check staged files (for pre-commit hook)
        #[arg(long)]
        staged: bool,
    },

    /// Safe package installs with monitoring
    Protect {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Force sandbox ON (override config)
        #[arg(long)]
        sandbox: bool,
        /// Force sandbox OFF (override config)
        #[arg(long)]
        no_sandbox: bool,
        /// Record connections as baseline
        #[arg(long)]
        learn: bool,
        /// Fail on unexpected connections
        #[arg(long)]
        strict: bool,
        /// Only run preflight checks (no monitoring)
        #[arg(long)]
        preflight_only: bool,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Auto-fix security issues (pin actions to SHA)
    Fix {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Preview changes without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// CI-optimized scan (SARIF output, exit codes)
    Ci {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Comma-separated list of checks to run
        #[arg(long, value_delimiter = ',')]
        checks: Option<Vec<String>>,
    },

    /// Configure hooks, baselines, and shell aliases
    Setup {
        /// Install pre-commit hook for secret detection
        #[arg(long)]
        hook: bool,
        /// Remove pre-commit hook
        #[arg(long)]
        unhook: bool,
        /// Initialize network baseline file
        #[arg(long)]
        baseline: bool,
        /// Print shell aliases for package manager monitoring
        #[arg(long)]
        shell: bool,
        /// Verify depsec's own integrity
        #[arg(long)]
        self_check: bool,
        /// Install all default protections (non-interactive)
        #[arg(long)]
        all: bool,
        /// Run non-interactively (for LLMs/CI)
        #[arg(long)]
        non_interactive: bool,
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    // ── Utility Commands ───────────────────────────────────────
    /// Generate SVG scorecard image
    Scorecard {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long, default_value = "depsec-scorecard.svg")]
        output: PathBuf,
    },

    /// Output badge markdown
    Badge {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Deep LLM-powered security audit of a package
    Audit {
        /// Package name to audit
        package: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "5.0")]
        budget: f64,
    },

    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Manage triage cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Manage build attestations
    Attestation {
        #[command(subcommand)]
        action: AttestationAction,
    },

    // ── Hidden (backward compat) ───────────────────────────────
    /// [deprecated] Use 'depsec protect' instead
    #[command(hide = true)]
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

    /// [deprecated] Use 'depsec protect --preflight-only' instead
    #[command(hide = true)]
    Preflight {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// [deprecated] Use 'depsec protect' instead
    #[command(hide = true)]
    InstallGuard {
        #[arg(long)]
        json: bool,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// [deprecated] Use 'depsec setup --hook' instead
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// [deprecated] Use 'depsec scan --staged' instead
    #[command(hide = true)]
    SecretsCheck {
        #[arg(long)]
        staged: bool,
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// [deprecated] Use 'depsec setup --baseline' instead
    #[command(hide = true)]
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// [deprecated] Use 'depsec setup --self-check' instead
    #[command(hide = true)]
    SelfCheck {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// [deprecated] Use 'depsec setup --shell' instead
    #[command(hide = true)]
    ShellHook,
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
        // ── Core Commands ──────────────────────────────────────
        Commands::Scan {
            path,
            checks,
            json,
            format,
            full,
            strict,
            relaxed,
            verbose,
            triage,
            triage_dry_run,
            staged,
        } => {
            // --staged mode: check staged files for secrets (pre-commit hook)
            if staged {
                let root = path.canonicalize().unwrap_or(path);
                return commands::secrets::check(true, &root);
            }

            // Derive persona from flags: --strict = Auditor, --relaxed = Pedantic
            let persona = if strict {
                Persona::Auditor
            } else if relaxed {
                Persona::Pedantic
            } else {
                Persona::Regular
            };

            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::scan::run(
                &root,
                &commands::scan::ScanOpts {
                    checks: checks.as_deref(),
                    format: format.as_deref(),
                    json,
                    persona,
                    verbose,
                    triage,
                    triage_dry_run,
                    color,
                    full,
                },
            )
        }

        Commands::Protect {
            json,
            sandbox,
            no_sandbox,
            learn,
            strict,
            preflight_only,
            command,
        } => {
            let sandbox_opt = if sandbox {
                Some(true)
            } else if no_sandbox {
                Some(false)
            } else {
                None
            };
            commands::protect::run(
                &command,
                &commands::protect::ProtectOpts {
                    json,
                    sandbox: sandbox_opt,
                    learn,
                    strict,
                    preflight_only,
                },
            )
        }

        Commands::Fix { path, dry_run } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::misc::fix(&root, dry_run)
        }

        Commands::Ci { path, checks } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::ci::run(&root, checks.as_deref())
        }

        Commands::Setup {
            hook,
            unhook,
            baseline,
            shell,
            self_check,
            all,
            non_interactive,
            path,
        } => {
            let root = path.canonicalize().unwrap_or(path);
            commands::setup::run(&commands::setup::SetupOpts {
                hook,
                unhook,
                baseline,
                shell,
                self_check,
                all,
                non_interactive,
                path: &root,
            })
        }

        // ── Utility Commands ───────────────────────────────────
        Commands::Scorecard { path, output } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::misc::scorecard(&root, &output)
        }

        Commands::Badge { path } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::misc::badge(&root)
        }

        Commands::Audit {
            package,
            path,
            dry_run,
            budget,
        } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::audit_cmd::run(&package, &root, dry_run, color, budget)
        }

        Commands::Rules { action } => match action {
            RulesAction::List => commands::misc::rules_list(),
            RulesAction::Update => commands::misc::rules_update(),
            RulesAction::Add { path } => commands::misc::rules_add(&path),
        },

        Commands::Cache { action } => match action {
            CacheAction::Clear => commands::misc::cache_clear(),
            CacheAction::Stats => commands::misc::cache_stats(),
        },

        // ── Hidden (backward compat) ───────────────────────────
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

        Commands::Monitor {
            learn,
            strict,
            json,
            baseline,
            command,
        } => commands::misc::monitor_cmd(&command, baseline.as_deref(), learn, json, strict),

        Commands::Preflight { path, json } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::misc::preflight(&root, json)
        }

        Commands::InstallGuard { json, command } => commands::misc::install_guard(&command, json),

        Commands::Hook { action } => match action {
            HookAction::Install => commands::hook::install(),
            HookAction::Uninstall => commands::hook::uninstall(),
        },

        Commands::SecretsCheck { staged, path } => {
            let root = path.canonicalize().unwrap_or(path);
            commands::secrets::check(staged, &root)
        }

        Commands::Baseline { action } => match action {
            BaselineAction::Init { path } => {
                let root = match canonicalize_or_exit(&path) {
                    Ok(r) => r,
                    Err(e) => return e,
                };
                commands::misc::baseline_init(&root)
            }
            BaselineAction::Check { capture } => {
                commands::misc::baseline_check(capture.as_deref(), color)
            }
        },

        Commands::SelfCheck { path } => {
            let root = match canonicalize_or_exit(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            commands::misc::self_check(&root)
        }

        Commands::ShellHook => commands::misc::shell_hook(),
    }
}
