use crate::checks::{Check, CheckResult, Finding, ScanContext, Severity};

pub struct HygieneCheck;

impl Check for HygieneCheck {
    fn name(&self) -> &str {
        "hygiene"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("hygiene") as f64;
        let mut findings = Vec::new();
        let mut pass_messages = Vec::new();

        // DEPSEC-H001: SECURITY.md exists
        check_security_md(ctx, &mut findings, &mut pass_messages);

        // DEPSEC-H002: .gitignore covers sensitive patterns
        check_gitignore(ctx, &mut findings, &mut pass_messages);

        // DEPSEC-H003: Lockfile committed
        check_lockfile_committed(ctx, &mut findings, &mut pass_messages);

        // DEPSEC-H004: Branch protection (optional, requires GITHUB_TOKEN)
        check_branch_protection(ctx, &mut findings, &mut pass_messages);

        Ok(CheckResult::new(
            "hygiene",
            findings,
            max_score,
            pass_messages,
        ))
    }
}

fn check_security_md(ctx: &ScanContext, findings: &mut Vec<Finding>, pass: &mut Vec<String>) {
    let security_md = ctx.root.join("SECURITY.md");
    let security_md_lower = ctx.root.join("security.md");

    if security_md.exists() || security_md_lower.exists() {
        pass.push("SECURITY.md exists".into());
    } else {
        findings.push(Finding {
            rule_id: "DEPSEC-H001".into(),
            severity: Severity::Medium,
            message: "No SECURITY.md found".into(),
            file: None,
            line: None,
            suggestion: Some(
                "Create a SECURITY.md with vulnerability reporting instructions".into(),
            ),
            auto_fixable: false,
        });
    }
}

fn check_gitignore(ctx: &ScanContext, findings: &mut Vec<Finding>, pass: &mut Vec<String>) {
    let gitignore = ctx.root.join(".gitignore");

    if !gitignore.exists() {
        findings.push(Finding {
            rule_id: "DEPSEC-H002".into(),
            severity: Severity::Low,
            message: "No .gitignore file found".into(),
            file: None,
            line: None,
            suggestion: Some("Create a .gitignore covering sensitive files".into()),
            auto_fixable: false,
        });
        return;
    }

    let content = match std::fs::read_to_string(&gitignore) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Required patterns (always)
    let required_always = vec![".env", "*.pem", "*.key"];

    let mut missing: Vec<&str> = Vec::new();
    for pattern in &required_always {
        if !gitignore_contains(&content, pattern) {
            missing.push(pattern);
        }
    }

    if missing.is_empty() {
        pass.push(".gitignore covers sensitive patterns".into());
    } else {
        findings.push(Finding {
            rule_id: "DEPSEC-H002".into(),
            severity: Severity::Low,
            message: format!(
                ".gitignore missing sensitive patterns: {}",
                missing.join(", ")
            ),
            file: Some(".gitignore".into()),
            line: None,
            suggestion: Some(format!(
                "Add these patterns to .gitignore: {}",
                missing.join(", ")
            )),
            auto_fixable: false,
        });
    }
}

fn gitignore_contains(content: &str, pattern: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == pattern || trimmed == format!("/{pattern}")
    })
}

fn check_lockfile_committed(
    ctx: &ScanContext,
    findings: &mut Vec<Finding>,
    pass: &mut Vec<String>,
) {
    let lockfiles = [
        "Cargo.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Gemfile.lock",
        "go.sum",
        "poetry.lock",
        "Pipfile.lock",
    ];

    let mut found_lockfile = false;

    for lockfile in &lockfiles {
        let path = ctx.root.join(lockfile);
        if path.exists() {
            found_lockfile = true;

            // Check if it's gitignored
            let output = std::process::Command::new("git")
                .args(["check-ignore", "-q", lockfile])
                .current_dir(ctx.root)
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    findings.push(Finding {
                        rule_id: "DEPSEC-H003".into(),
                        severity: Severity::High,
                        message: format!("Lockfile {lockfile} is gitignored"),
                        file: Some(lockfile.to_string()),
                        line: None,
                        suggestion: Some(format!(
                            "Remove {lockfile} from .gitignore and commit it"
                        )),
                        auto_fixable: false,
                    });
                }
            }
        }
    }

    if found_lockfile && findings.iter().all(|f| f.rule_id != "DEPSEC-H003") {
        pass.push("Lockfile committed".into());
    }
}

fn check_branch_protection(ctx: &ScanContext, findings: &mut Vec<Finding>, pass: &mut Vec<String>) {
    let token = match std::env::var("GITHUB_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            // No token — skip check silently (no point deduction)
            return;
        }
    };

    // Parse remote URL to get owner/repo
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(ctx.root)
        .output();

    let remote_url = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => return, // No remote — skip
    };

    let (owner, repo) = match parse_github_remote(&remote_url) {
        Some(pair) => pair,
        None => return, // Not a GitHub remote
    };

    // Check branch protection via API
    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(10))
        .user_agent("depsec")
        .build();
    let url = format!("https://api.github.com/repos/{owner}/{repo}/branches/main/protection");

    let resp = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github.v3+json")
        .call();

    match resp {
        Ok(_) => {
            pass.push("Branch protection enabled on main".into());
        }
        Err(ureq::Error::Status(404, _)) => {
            findings.push(Finding {
                rule_id: "DEPSEC-H004".into(),
                severity: Severity::Medium,
                message: "No branch protection on main".into(),
                file: None,
                line: None,
                suggestion: Some(format!(
                    "Enable at https://github.com/{owner}/{repo}/settings/branches"
                )),
                auto_fixable: false,
            });
        }
        Err(_) => {} // API error — skip silently
    }
}

fn parse_github_remote(url: &str) -> Option<(String, String)> {
    // Handle SSH: git@github.com:owner/repo.git
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        let path = rest.trim_end_matches(".git");
        let parts: Vec<&str> = path.splitn(2, '/').collect();
        if parts.len() == 2 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
    }

    // Handle HTTPS: https://github.com/owner/repo.git
    if url.contains("github.com/") {
        let after = url.split("github.com/").nth(1)?;
        let path = after.trim_end_matches(".git");
        let parts: Vec<&str> = path.splitn(2, '/').collect();
        if parts.len() == 2 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;
    use tempfile::TempDir;

    fn setup_repo(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .ok();

        for (name, content) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, content).unwrap();
        }

        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .ok();

        dir
    }

    #[test]
    fn test_security_md_found() {
        let dir = setup_repo(&[(
            "SECURITY.md",
            "# Security Policy\nReport to security@example.com",
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = HygieneCheck.run(&ctx).unwrap();
        assert!(!result.findings.iter().any(|f| f.rule_id == "DEPSEC-H001"));
    }

    #[test]
    fn test_security_md_missing() {
        let dir = setup_repo(&[("README.md", "# Project")]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = HygieneCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-H001"));
    }

    #[test]
    fn test_gitignore_good() {
        let dir = setup_repo(&[(".gitignore", ".env\n*.pem\n*.key\n")]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = HygieneCheck.run(&ctx).unwrap();
        assert!(!result.findings.iter().any(|f| f.rule_id == "DEPSEC-H002"));
    }

    #[test]
    fn test_gitignore_missing_patterns() {
        let dir = setup_repo(&[(".gitignore", "/target\n")]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = HygieneCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-H002"));
    }

    #[test]
    fn test_parse_github_remote_ssh() {
        let result = parse_github_remote("git@github.com:chocksy/depsec.git");
        assert_eq!(result, Some(("chocksy".into(), "depsec".into())));
    }

    #[test]
    fn test_parse_github_remote_https() {
        let result = parse_github_remote("https://github.com/chocksy/depsec.git");
        assert_eq!(result, Some(("chocksy".into(), "depsec".into())));
    }

    #[test]
    fn test_parse_github_remote_invalid() {
        let result = parse_github_remote("https://gitlab.com/user/repo");
        assert_eq!(result, None);
    }
}
