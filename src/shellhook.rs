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
        output.push_str(&format!("alias {cmd}='depsec monitor {cmd}'\n"));
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
        output.push_str(&format!("alias {cmd} 'depsec monitor {cmd}'\n"));
    }

    output.push_str("echo 'depsec: shell hooks active — package installs monitored'\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_hook_output() {
        let hook = generate_posix_hook();
        assert!(hook.contains("alias npm='depsec monitor npm'"));
        assert!(hook.contains("alias pip='depsec monitor pip'"));
        assert!(hook.contains("alias cargo='depsec monitor cargo'"));
    }

    #[test]
    fn test_fish_hook_output() {
        let hook = generate_fish_hook();
        assert!(hook.contains("alias npm 'depsec monitor npm'"));
    }

    #[test]
    fn test_generate_shell_hook() {
        let hook = generate_shell_hook();
        assert!(hook.contains("depsec monitor"));
    }
}
