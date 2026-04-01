use std::io::Write;
use std::path::PathBuf;

/// Result of installing shell hooks to a profile
#[derive(Debug)]
pub enum InstallResult {
    /// Hook line was added to the given path
    Installed(PathBuf),
    /// Hook line was already present in the given path
    AlreadyPresent(PathBuf),
    /// Shell could not be detected
    UnknownShell,
}

/// Detected shell type
#[derive(Debug, Clone, PartialEq)]
pub enum ShellType {
    Zsh,
    Bash,
    Fish,
    Unknown(String),
}

/// Detect the user's shell from $SHELL
pub fn detect_shell() -> ShellType {
    let shell = std::env::var("SHELL").unwrap_or_default();
    if shell.contains("zsh") {
        ShellType::Zsh
    } else if shell.contains("bash") {
        ShellType::Bash
    } else if shell.contains("fish") {
        ShellType::Fish
    } else if shell.is_empty() {
        ShellType::Unknown(String::new())
    } else {
        ShellType::Unknown(shell)
    }
}

/// Get the RC file path for a given shell
pub fn rc_file_for(shell: &ShellType) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let home = PathBuf::from(home);

    match shell {
        ShellType::Zsh => Some(home.join(".zshrc")),
        ShellType::Bash => Some(home.join(".bashrc")),
        ShellType::Fish => {
            // Respect XDG_CONFIG_HOME for fish
            let config_dir = std::env::var("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join(".config"));
            Some(config_dir.join("fish").join("config.fish"))
        }
        ShellType::Unknown(_) => None,
    }
}

/// Get the eval line for a given shell
fn eval_line_for(shell: &ShellType) -> &'static str {
    match shell {
        ShellType::Fish => "depsec setup --shell | source",
        _ => "eval \"$(depsec setup --shell)\"",
    }
}

/// Install the shell hook eval line into the user's shell RC file.
/// Creates a backup before modifying. Idempotent — skips if already present.
pub fn install_to_profile() -> anyhow::Result<InstallResult> {
    let shell = detect_shell();
    if matches!(shell, ShellType::Unknown(_)) {
        return Ok(InstallResult::UnknownShell);
    }

    let rc_path = match rc_file_for(&shell) {
        Some(p) => p,
        None => return Ok(InstallResult::UnknownShell),
    };

    let eval_line = eval_line_for(&shell);

    // Idempotency: check if already present
    if rc_path.exists() {
        let content = std::fs::read_to_string(&rc_path)?;
        if content.contains("depsec setup --shell") {
            return Ok(InstallResult::AlreadyPresent(rc_path));
        }
        // Backup before modifying
        let backup = rc_path.with_extension("depsec-backup");
        std::fs::copy(&rc_path, &backup)?;
    }

    // Ensure parent directory exists (for fish: ~/.config/fish/)
    if let Some(parent) = rc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Append the eval line
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)?;
    writeln!(file)?;
    writeln!(file, "# depsec — supply chain protection")?;
    writeln!(file, "{eval_line}")?;

    Ok(InstallResult::Installed(rc_path))
}

/// Generate shell aliases for invisible protection
pub fn generate_shell_hook() -> String {
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.contains("fish") {
        generate_fish_hook()
    } else {
        generate_posix_hook()
    }
}

fn generate_posix_hook() -> String {
    let mut output = String::new();
    output.push_str("# depsec shell hooks — wraps package managers with network monitoring\n");

    let commands = [
        "npm", "npx", "yarn", "pnpm", "pip", "pip3", "cargo", "go", "bundle", "gem",
    ];

    for cmd in &commands {
        output.push_str(&format!("alias {cmd}='depsec protect {cmd}'\n"));
    }

    output.push_str("echo 'depsec: shell hooks active — package installs monitored'\n");
    output
}

fn generate_fish_hook() -> String {
    let mut output = String::new();
    output.push_str("# depsec shell hooks for fish\n");

    let commands = [
        "npm", "npx", "yarn", "pnpm", "pip", "pip3", "cargo", "go", "bundle", "gem",
    ];

    for cmd in &commands {
        output.push_str(&format!("alias {cmd} 'depsec protect {cmd}'\n"));
    }

    output.push_str("echo 'depsec: shell hooks active — package installs monitored'\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_shell_zsh() {
        std::env::set_var("SHELL", "/bin/zsh");
        assert_eq!(detect_shell(), ShellType::Zsh);
    }

    #[test]
    fn test_eval_line_fish() {
        assert_eq!(
            eval_line_for(&ShellType::Fish),
            "depsec setup --shell | source"
        );
    }

    #[test]
    fn test_eval_line_posix() {
        assert_eq!(
            eval_line_for(&ShellType::Zsh),
            "eval \"$(depsec setup --shell)\""
        );
        assert_eq!(
            eval_line_for(&ShellType::Bash),
            "eval \"$(depsec setup --shell)\""
        );
    }

    #[test]
    fn test_install_to_profile_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let rc_path = dir.path().join(".zshrc");

        // Pre-populate with the eval line
        std::fs::write(&rc_path, "eval \"$(depsec setup --shell)\"\n").unwrap();

        // Override HOME and SHELL for the test
        std::env::set_var("HOME", dir.path().to_str().unwrap());
        std::env::set_var("SHELL", "/bin/zsh");

        let result = install_to_profile().unwrap();
        assert!(matches!(result, InstallResult::AlreadyPresent(_)));
    }

    #[test]
    fn test_install_to_profile_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();

        std::env::set_var("HOME", dir.path().to_str().unwrap());
        std::env::set_var("SHELL", "/bin/zsh");

        let result = install_to_profile().unwrap();
        assert!(matches!(result, InstallResult::Installed(_)));

        let content = std::fs::read_to_string(dir.path().join(".zshrc")).unwrap();
        assert!(content.contains("depsec setup --shell"));
        assert!(content.contains("# depsec"));
    }

    #[test]
    fn test_install_to_profile_creates_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let rc_path = dir.path().join(".zshrc");
        std::fs::write(&rc_path, "# existing config\n").unwrap();

        std::env::set_var("HOME", dir.path().to_str().unwrap());
        std::env::set_var("SHELL", "/bin/zsh");

        let result = install_to_profile().unwrap();
        assert!(matches!(result, InstallResult::Installed(_)));

        // Backup should exist
        let backup = dir.path().join(".depsec-backup");
        assert!(backup.exists() || dir.path().join(".zshrc.depsec-backup").exists());
    }

    #[test]
    fn test_posix_hook_output() {
        let hook = generate_posix_hook();
        assert!(hook.contains("alias npm='depsec protect npm'"));
        assert!(hook.contains("alias pip='depsec protect pip'"));
        assert!(hook.contains("alias cargo='depsec protect cargo'"));
    }

    #[test]
    fn test_fish_hook_output() {
        let hook = generate_fish_hook();
        assert!(hook.contains("alias npm 'depsec protect npm'"));
    }

    #[test]
    fn test_generate_shell_hook() {
        let hook = generate_shell_hook();
        assert!(hook.contains("depsec protect"));
    }
}
