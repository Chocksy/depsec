use std::path::Path;
use std::process::ExitCode;

use crate::{baseline, selfcheck, shellhook};

pub struct SetupOpts<'a> {
    pub hook: bool,
    pub unhook: bool,
    pub baseline: bool,
    pub shell: bool,
    pub self_check: bool,
    pub path: &'a Path,
}

pub fn run(opts: &SetupOpts) -> ExitCode {
    // If no specific flag, show what's available
    if !opts.hook && !opts.unhook && !opts.baseline && !opts.shell && !opts.self_check {
        println!("depsec setup — configure your project\n");
        println!("  --hook        Install pre-commit hook for secret detection");
        println!("  --unhook      Remove pre-commit hook");
        println!("  --baseline    Initialize network baseline file");
        println!("  --shell       Print shell aliases for package manager monitoring");
        println!("  --self-check  Verify depsec's own integrity");
        println!("\nExample: depsec setup --hook --baseline");
        return ExitCode::SUCCESS;
    }

    let mut success = true;

    if opts.hook {
        match install_hook() {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Hook install failed: {e}");
                success = false;
            }
        }
    }

    if opts.unhook {
        match uninstall_hook() {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Hook uninstall failed: {e}");
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

    if opts.shell {
        print!("{}", shellhook::generate_shell_hook());
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

fn install_hook() -> anyhow::Result<()> {
    let git_hooks = std::path::Path::new(".git/hooks");
    if !git_hooks.exists() {
        anyhow::bail!(".git/hooks not found. Are you in a git repository?");
    }
    let hook_path = git_hooks.join("pre-commit");
    let hook_content =
        "#!/bin/sh\n# depsec pre-commit hook — blocks commits with hardcoded secrets\nexec depsec scan --staged --checks secrets\n";
    std::fs::write(&hook_path, hook_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    println!("Installed pre-commit hook at .git/hooks/pre-commit");
    println!("Secrets will be checked on every commit.");
    println!("To bypass: git commit --no-verify");
    Ok(())
}

fn uninstall_hook() -> anyhow::Result<()> {
    let hook_path = std::path::Path::new(".git/hooks/pre-commit");
    if hook_path.exists() {
        std::fs::remove_file(hook_path)?;
        println!("Removed pre-commit hook.");
    } else {
        println!("No pre-commit hook found.");
    }
    Ok(())
}
