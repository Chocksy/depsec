use std::path::Path;
use std::process::ExitCode;

use crate::secrets_ast;

pub fn check(staged: bool, root: &Path) -> ExitCode {
    let files: Vec<std::path::PathBuf> = if staged {
        match std::process::Command::new("git")
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .current_dir(root)
            .output()
        {
            Ok(output) => String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| root.join(l))
                .filter(|p| p.exists())
                .collect(),
            Err(_) => {
                eprintln!("Error: failed to get staged files from git");
                return ExitCode::from(2);
            }
        }
    } else {
        match std::process::Command::new("git")
            .args(["ls-files"])
            .current_dir(root)
            .output()
        {
            Ok(output) => String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| root.join(l))
                .filter(|p| p.exists())
                .collect(),
            Err(_) => vec![],
        }
    };

    if files.is_empty() {
        println!("No files to check.");
        return ExitCode::SUCCESS;
    }

    let findings = secrets_ast::scan_for_secrets(root, &files);

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "\n\x1b[31mdepsec: {} potential secret{} detected in {}files\x1b[0m\n",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            if staged { "staged " } else { "" },
        );
        for f in &findings {
            let location = match (&f.file, f.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.clone(),
                _ => "?".into(),
            };
            eprintln!("  \x1b[31m✗\x1b[0m {location} — {}", f.message);
            if let Some(ref suggestion) = f.suggestion {
                eprintln!("    → {suggestion}");
            }
        }
        eprintln!("\nCommit blocked. To proceed anyway: git commit --no-verify");
        eprintln!("To allowlist: add '// depsec:allow' comment on the line");
        ExitCode::from(1)
    }
}
