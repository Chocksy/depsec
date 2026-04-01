use std::path::Path;
use std::process::ExitCode;

use crate::{baseline, config, sandbox, selfcheck, shellhook};

pub struct SetupOpts<'a> {
    pub hook: bool,
    pub unhook: bool,
    pub baseline: bool,
    pub shell: bool,
    pub self_check: bool,
    pub all: bool,
    pub non_interactive: bool,
    pub path: &'a Path,
}

/// Marker in hook scripts to identify depsec-owned hooks
const HOOK_MARKER: &str = "# depsec pre-commit hook";

pub fn run(opts: &SetupOpts) -> ExitCode {
    // --shell: print aliases to stdout (for eval) — always works, no wizard
    if opts.shell {
        print!("{}", shellhook::generate_shell_hook());
        return ExitCode::SUCCESS;
    }

    // --unhook: remove hook
    if opts.unhook {
        return match uninstall_hook() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Hook uninstall failed: {e}");
                ExitCode::from(2)
            }
        };
    }

    // If any specific flag is set, run in flag mode (backward compat)
    let has_specific_flag = opts.hook || opts.baseline || opts.self_check;
    if has_specific_flag {
        return run_flagged(opts);
    }

    // --all, --non-interactive, or no TTY: install defaults silently
    let is_interactive =
        std::io::IsTerminal::is_terminal(&std::io::stdin()) && !opts.non_interactive && !opts.all;

    if !is_interactive {
        return run_defaults(opts);
    }

    // Interactive wizard
    run_wizard(opts)
}

/// Run the interactive checkbox wizard
fn run_wizard(opts: &SetupOpts) -> ExitCode {
    let global = config::load_global_config();

    println!("depsec v{} — Setup\n", env!("CARGO_PKG_VERSION"));

    // Build options with pre-selection based on existing config
    let items = vec![
        "Shell protection    Wraps npm/yarn/pip/cargo with monitoring",
        "Pre-commit hook     Blocks secrets from being committed",
        "Sandbox by default  Sandboxes all protected installs",
        "Network baseline    Initialize connection baseline for this project",
        "Self-check          Verify depsec binary integrity",
    ];

    let defaults = vec![
        global.setup.shell_hook || !global_config_exists(), // default ON for first run
        !global.setup.hook_scope.is_empty() || !global_config_exists(),
        global.protect.sandbox || !global_config_exists(),
        false,
        false,
    ];

    let selections = match dialoguer::MultiSelect::new()
        .with_prompt("Select protections to install")
        .items(&items)
        .defaults(&defaults)
        .interact_opt()
    {
        Ok(Some(s)) => s,
        Ok(None) | Err(_) => {
            println!("Setup cancelled, no changes made.");
            return ExitCode::SUCCESS;
        }
    };

    if selections.is_empty() {
        println!("Nothing selected.");
        return ExitCode::SUCCESS;
    }

    let want_shell = selections.contains(&0);
    let want_hook = selections.contains(&1);
    let want_sandbox = selections.contains(&2);
    let want_baseline = selections.contains(&3);
    let want_selfcheck = selections.contains(&4);

    // Hook scope sub-prompt
    let hook_scope = if want_hook {
        let scope_items = vec![
            "This project only   .git/hooks/pre-commit",
            "Global (all repos)  git config --global core.hooksPath",
        ];
        match dialoguer::Select::new()
            .with_prompt("Pre-commit hook scope")
            .items(&scope_items)
            .default(0)
            .interact_opt()
        {
            Ok(Some(0)) => HookScope::Project,
            Ok(Some(1)) => HookScope::Global,
            Ok(None) | Err(_) => {
                println!("Setup cancelled, no changes made.");
                return ExitCode::SUCCESS;
            }
            _ => HookScope::Project,
        }
    } else {
        HookScope::Project
    };

    // Show sandbox status
    if want_sandbox {
        let sandbox_type = sandbox::detect_sandbox("auto");
        if sandbox_type != sandbox::SandboxType::None {
            println!("\n\x1b[32m✓\x1b[0m Sandbox available: {sandbox_type}");
        } else {
            println!("\n\x1b[33m⚠\x1b[0m No sandbox backend available (bubblewrap, sandbox-exec, or Docker)");
        }
    }

    println!("\nInstalling...");

    // Execute selections
    let mut new_config = global.clone();
    let mut success = true;

    if want_shell {
        match shellhook::install_to_profile() {
            Ok(shellhook::InstallResult::Installed(path)) => {
                println!(
                    "  \x1b[32m✓\x1b[0m Shell protection added to {}",
                    path.display()
                );
                new_config.setup.shell_hook = true;
                new_config.setup.shell_profile = path.to_string_lossy().to_string();
            }
            Ok(shellhook::InstallResult::AlreadyPresent(path)) => {
                println!(
                    "  \x1b[32m✓\x1b[0m Shell protection already in {}",
                    path.display()
                );
                new_config.setup.shell_hook = true;
                new_config.setup.shell_profile = path.to_string_lossy().to_string();
            }
            Ok(shellhook::InstallResult::UnknownShell) => {
                eprintln!("  \x1b[33m⚠\x1b[0m Could not detect shell (set $SHELL)");
            }
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m Shell protection failed: {e}");
                success = false;
            }
        }
    }

    if want_hook {
        match install_hook(&hook_scope) {
            Ok(()) => {
                let scope_str = match hook_scope {
                    HookScope::Project => "project",
                    HookScope::Global => "global",
                };
                new_config.setup.hook_scope = scope_str.to_string();
            }
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m Hook install failed: {e}");
                success = false;
            }
        }
    }

    if want_sandbox {
        new_config.protect.sandbox = true;
        println!("  \x1b[32m✓\x1b[0m Sandbox enabled by default");
    }

    if want_baseline {
        match baseline::init_baseline(opts.path) {
            Ok(output_path) => {
                println!("  \x1b[32m✓\x1b[0m Baseline created: {output_path}");
            }
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m Baseline failed: {e}");
                success = false;
            }
        }
    }

    if want_selfcheck {
        selfcheck::run_self_check(opts.path);
    }

    // Save config
    match config::save_global_config(&new_config) {
        Ok(()) => {
            println!("  \x1b[32m✓\x1b[0m Config saved to ~/.depsec/config.toml");
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Config save failed: {e}");
            success = false;
        }
    }

    // Summary
    if want_shell {
        println!("\nRestart your shell or run: source ~/.zshrc");
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Install all default protections non-interactively
fn run_defaults(opts: &SetupOpts) -> ExitCode {
    let mut config = config::load_global_config();
    let mut success = true;

    // Shell protection
    match shellhook::install_to_profile() {
        Ok(shellhook::InstallResult::Installed(path)) => {
            eprintln!(
                "  \x1b[32m✓\x1b[0m Shell protection added to {}",
                path.display()
            );
            config.setup.shell_hook = true;
            config.setup.shell_profile = path.to_string_lossy().to_string();
        }
        Ok(shellhook::InstallResult::AlreadyPresent(path)) => {
            eprintln!(
                "  \x1b[32m✓\x1b[0m Shell protection already in {}",
                path.display()
            );
            config.setup.shell_hook = true;
            config.setup.shell_profile = path.to_string_lossy().to_string();
        }
        Ok(shellhook::InstallResult::UnknownShell) => {
            eprintln!("  \x1b[33m⚠\x1b[0m Could not detect shell — skipping shell protection");
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Shell protection failed: {e}");
            success = false;
        }
    }

    // Pre-commit hook (project-local if .git exists)
    let git_dir = opts.path.join(".git");
    if git_dir.exists() {
        match install_hook(&HookScope::Project) {
            Ok(()) => {
                config.setup.hook_scope = "project".to_string();
            }
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m Hook install failed: {e}");
                success = false;
            }
        }
    } else {
        eprintln!("  \x1b[33m⚠\x1b[0m Not in a git repo — skipping pre-commit hook");
    }

    // Sandbox default
    config.protect.sandbox = true;
    eprintln!("  \x1b[32m✓\x1b[0m Sandbox enabled by default");

    // Save config
    match config::save_global_config(&config) {
        Ok(()) => {
            eprintln!("  \x1b[32m✓\x1b[0m Config saved to ~/.depsec/config.toml");
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Config save failed: {e}");
            success = false;
        }
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Run individual flag-based setup (backward compat)
fn run_flagged(opts: &SetupOpts) -> ExitCode {
    let mut success = true;

    if opts.hook {
        match install_hook(&HookScope::Project) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Hook install failed: {e}");
                success = false;
            }
        }
    }

    if opts.baseline {
        match baseline::init_baseline(opts.path) {
            Ok(output_path) => {
                println!("Baseline created: {output_path}");
                println!("Edit allowed_hosts and commit the file.");
            }
            Err(e) => {
                eprintln!("Baseline init failed: {e}");
                success = false;
            }
        }
    }

    if opts.self_check {
        selfcheck::run_self_check(opts.path);
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

// ── Hook Installation ─────────────────────────────────────────

#[derive(Debug, Clone)]
enum HookScope {
    Project,
    Global,
}

fn install_hook(scope: &HookScope) -> anyhow::Result<()> {
    match scope {
        HookScope::Project => install_project_hook(),
        HookScope::Global => install_global_hook(),
    }
}

fn install_project_hook() -> anyhow::Result<()> {
    let git_hooks = std::path::Path::new(".git/hooks");
    if !git_hooks.exists() {
        anyhow::bail!(".git/hooks not found. Are you in a git repository?");
    }

    let hook_path = git_hooks.join("pre-commit");

    // Check for existing non-depsec hook — back it up and chain
    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) {
            let backup = git_hooks.join("pre-commit.bak");
            std::fs::copy(&hook_path, &backup)?;
            println!("  \x1b[32m✓\x1b[0m Backed up existing hook to .git/hooks/pre-commit.bak");
        }
    }

    // Write hook with chaining support
    let hook_content = format!(
        "#!/bin/sh\n\
         {HOOK_MARKER} — blocks commits with hardcoded secrets\n\
         depsec scan --staged --checks secrets\n\
         DEPSEC_EXIT=$?\n\
         # Chain to original hook if it was backed up\n\
         if [ -f .git/hooks/pre-commit.bak ]; then\n\
             .git/hooks/pre-commit.bak\n\
             CHAIN_EXIT=$?\n\
             [ $CHAIN_EXIT -ne 0 ] && exit $CHAIN_EXIT\n\
         fi\n\
         exit $DEPSEC_EXIT\n"
    );
    std::fs::write(&hook_path, hook_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    println!("  \x1b[32m✓\x1b[0m Pre-commit hook installed at .git/hooks/pre-commit");
    Ok(())
}

fn install_global_hook() -> anyhow::Result<()> {
    // Check if core.hooksPath is already set to something else
    let existing = std::process::Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output();

    if let Ok(output) = existing {
        if output.status.success() {
            let current = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let depsec_hooks = config::global_config_dir()
                .join("hooks")
                .to_string_lossy()
                .to_string();
            if !current.is_empty() && current != depsec_hooks {
                anyhow::bail!(
                    "core.hooksPath is already set to '{current}'.\n\
                     Overwriting would break your existing hook setup.\n\
                     Unset it first: git config --global --unset core.hooksPath"
                );
            }
        }
    }

    // Create hooks directory
    let hooks_dir = config::global_config_dir().join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    // Write global hook with per-project chaining
    let hook_content = format!(
        "#!/bin/sh\n\
         {HOOK_MARKER} (global)\n\
         depsec scan --staged --checks secrets\n\
         DEPSEC_EXIT=$?\n\
         # Chain to per-project hook if it exists\n\
         if [ -n \"$GIT_DIR\" ] && [ -f \"$GIT_DIR/hooks/pre-commit\" ]; then\n\
             \"$GIT_DIR/hooks/pre-commit\"\n\
             CHAIN_EXIT=$?\n\
             [ $CHAIN_EXIT -ne 0 ] && exit $CHAIN_EXIT\n\
         fi\n\
         exit $DEPSEC_EXIT\n"
    );

    let hook_path = hooks_dir.join("pre-commit");
    std::fs::write(&hook_path, hook_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Set git global hooksPath
    let status = std::process::Command::new("git")
        .args([
            "config",
            "--global",
            "core.hooksPath",
            &hooks_dir.to_string_lossy(),
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to set git config --global core.hooksPath");
    }

    println!(
        "  \x1b[32m✓\x1b[0m Global pre-commit hook installed at {}",
        hook_path.display()
    );
    Ok(())
}

fn uninstall_hook() -> anyhow::Result<()> {
    // Check global config to determine scope
    let global = config::load_global_config();

    if global.setup.hook_scope == "global" {
        // Remove global hook
        let hook_path = config::global_config_dir().join("hooks").join("pre-commit");
        if hook_path.exists() {
            std::fs::remove_file(&hook_path)?;
        }
        // Unset core.hooksPath
        let _ = std::process::Command::new("git")
            .args(["config", "--global", "--unset", "core.hooksPath"])
            .status();
        println!("Removed global pre-commit hook.");
    } else {
        // Remove project hook
        let hook_path = std::path::Path::new(".git/hooks/pre-commit");
        if hook_path.exists() {
            // Restore backup if it exists
            let backup = std::path::Path::new(".git/hooks/pre-commit.bak");
            if backup.exists() {
                std::fs::rename(backup, hook_path)?;
                println!("Removed depsec hook, restored original from .bak");
            } else {
                std::fs::remove_file(hook_path)?;
                println!("Removed pre-commit hook.");
            }
        } else {
            println!("No pre-commit hook found.");
        }
    }
    Ok(())
}

/// Check if global config file exists (for first-run detection)
fn global_config_exists() -> bool {
    config::global_config_path().exists()
}
