use std::process::ExitCode;

pub fn install() -> ExitCode {
    let git_hooks = std::path::Path::new(".git/hooks");
    if !git_hooks.exists() {
        eprintln!("Error: .git/hooks not found. Are you in a git repository?");
        return ExitCode::from(2);
    }
    let hook_path = git_hooks.join("pre-commit");
    let hook_content = "#!/bin/sh\n# depsec pre-commit hook — blocks commits with hardcoded secrets\nexec depsec scan --staged --checks secrets\n";
    match std::fs::write(&hook_path, hook_content) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755));
            }
            println!("Installed pre-commit hook at .git/hooks/pre-commit");
            println!("Secrets will be checked on every commit.");
            println!("To bypass: git commit --no-verify");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error installing hook: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn uninstall() -> ExitCode {
    let hook_path = std::path::Path::new(".git/hooks/pre-commit");
    if hook_path.exists() {
        match std::fs::remove_file(hook_path) {
            Ok(()) => {
                println!("Removed pre-commit hook.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error removing hook: {e}");
                ExitCode::from(2)
            }
        }
    } else {
        println!("No pre-commit hook found.");
        ExitCode::SUCCESS
    }
}
