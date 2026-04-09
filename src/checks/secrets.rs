use std::path::Path;

use regex::Regex;
use walkdir::WalkDir;

use crate::checks::{Check, CheckResult, Finding, ScanContext, Severity};

struct SecretPattern {
    rule_id: &'static str,
    name: &'static str,
    pattern: &'static str,
    severity: Severity,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        rule_id: "DEPSEC-S001",
        name: "AWS Access Key",
        pattern: r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S002",
        name: "AWS Secret Key",
        pattern: r#"(?i)aws_secret_access_key\s*[=:].*?['"]?[A-Za-z0-9/+=]{40}"#,
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S003",
        name: "GitHub Token (classic)",
        pattern: r"ghp_[A-Za-z0-9_]{36,}",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S004",
        name: "GitHub Token (fine-grained)",
        pattern: r"github_pat_[A-Za-z0-9_]{22,}",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S005",
        name: "GitHub App Token",
        pattern: r"ghs_[A-Za-z0-9_]{36,}",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S006",
        name: "Private Key",
        pattern: r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S007",
        name: "JWT Token",
        pattern: r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S008",
        name: "Slack Webhook",
        pattern: r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S009",
        name: "Slack Bot Token",
        pattern: r"xoxb-[0-9]{10,}-[A-Za-z0-9]+",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S010",
        name: "Generic API Key",
        // Allows type annotations between name and value (e.g., API_KEY: string = "value")
        // Expanded character class includes _-/+= for base64 and URL-safe secrets
        pattern: r#"(?i)(api[_\-]?key|api[_\-]?secret)\s*[=:].*?['"][A-Za-z0-9_\-/+=]{20,}['"]"#,
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S011",
        name: "Generic Secret",
        // Allows type annotations between name and value (e.g., CLIENT_SECRET: &str = "value")
        // Expanded character class includes _-/+= for base64 and URL-safe secrets
        pattern: r#"(?i)(secret[_\-]?key|client[_\-]?secret)\s*[=:].*?['"][A-Za-z0-9_\-/+=]{20,}['"]"#,
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S012",
        name: "Postgres Connection String",
        pattern: r#"postgres(ql)?://[^\s'"]+:[^\s'"]+@[^\s'"]+"#,
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S013",
        name: "MySQL Connection String",
        pattern: r#"mysql://[^\s'"]+:[^\s'"]+@[^\s'"]+"#,
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S014",
        name: "MongoDB Connection String",
        pattern: r#"mongodb(\+srv)?://[^\s'"]+:[^\s'"]+@[^\s'"]+"#,
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S015",
        name: "Stripe Key",
        pattern: r"(sk|pk)_(live|test)_[A-Za-z0-9]{20,}",
        severity: Severity::Critical,
    },
    SecretPattern {
        rule_id: "DEPSEC-S016",
        name: "SendGrid Key",
        pattern: r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S017",
        name: "Twilio Key",
        pattern: r"\bSK[0-9a-fA-F]{32}\b",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S018",
        name: "Google API Key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S019",
        name: "Heroku API Key",
        pattern: r"(?i)heroku.{0,50}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity: Severity::High,
    },
    SecretPattern {
        rule_id: "DEPSEC-S020",
        name: "NPM Token",
        pattern: r"npm_[A-Za-z0-9]{36}",
        severity: Severity::High,
    },
];

/// Test/fixture directories where secrets are expected to be fake
const SECRETS_TEST_DIRS: &[&str] = &[
    "spec/",
    "test/",
    "tests/",
    "__tests__/",
    "fixtures/",
    "factories/",
    "e2e/",
    "cypress/",
    "docs/",
];

/// Check if a file is in a test/fixture directory (secrets are expected to be fake there)
fn is_test_fixture_path(rel_path: &str) -> bool {
    SECRETS_TEST_DIRS
        .iter()
        .any(|dir| rel_path.starts_with(dir) || rel_path.contains(&format!("/{dir}")))
}

/// Check if the matched "secret" is actually an ENV var reference, not a real secret.
/// Catches: ENV['CLIENT_SECRET'], process.env.SECRET, os.environ['KEY'], ${VAR}
fn is_env_var_reference(line: &str) -> bool {
    // Ruby ERB templates: <%= ENV['...'] %>
    if line.contains("<%=") || line.contains("<%") {
        return true;
    }
    // Ruby: ENV['...'] or ENV.fetch('...')
    if line.contains("ENV[") || line.contains("ENV.fetch") {
        return true;
    }
    // JS/Node: process.env.SECRET
    if line.contains("process.env") {
        return true;
    }
    // Python: os.environ['...'], os.environ.get('...'), os.getenv('...')
    if line.contains("os.environ") || line.contains("os.getenv") {
        return true;
    }
    // Python Flask/Django: app.config.get('...'), settings.SECRET_KEY
    if line.contains(".config.get(") || line.contains(".config[") {
        return true;
    }
    // Shell: ${VAR} or $VAR
    if line.contains("${") {
        return true;
    }
    // YAML/ERB template interpolation: #{ENV['...']}
    if line.contains("#{ENV") {
        return true;
    }
    false
}

/// Check if the matched value is a URL, not a secret
fn is_url_value(line: &str, re: &Regex) -> bool {
    if let Some(m) = re.find(line) {
        let matched = m.as_str();
        // Check if the matched portion contains a URL
        if matched.contains("http://") || matched.contains("https://") {
            return true;
        }
        // Check surrounding context for URL patterns
        let start = m.start().saturating_sub(10);
        let end = (m.end() + 10).min(line.len());
        let context = &line[start..end];
        if context.contains("http://") || context.contains("https://") {
            return true;
        }
    }
    false
}

/// Check if the matched "secret" value is a placeholder template.
/// e.g., '__OPENROUTER_API_KEY__', '{{SECRET_KEY}}', 'REPLACE_ME'
fn is_placeholder_value(line: &str, re: &Regex) -> bool {
    if let Some(m) = re.find(line) {
        let matched = m.as_str();
        // Look for __PLACEHOLDER__ patterns in the matched text
        if matched.contains("__") {
            // Check if the quoted value is a __PLACEHOLDER__
            for part in matched.split(&['\'', '"'][..]) {
                let trimmed = part.trim();
                if trimmed.starts_with("__") && trimmed.ends_with("__") && trimmed.len() > 4 {
                    return true;
                }
            }
        }
        // {{PLACEHOLDER}} patterns
        if matched.contains("{{") && matched.contains("}}") {
            return true;
        }
    }
    false
}

pub struct SecretsCheck;

impl Check for SecretsCheck {
    fn name(&self) -> &str {
        "secrets"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("secrets") as f64;

        let files = collect_scannable_files(ctx.root, &ctx.config.ignore.secrets);

        if files.is_empty() {
            return Ok(CheckResult::new(
                "secrets",
                vec![],
                max_score,
                vec!["No files to scan".into()],
            ));
        }

        let compiled_patterns: Vec<(&SecretPattern, Regex)> = SECRET_PATTERNS
            .iter()
            .filter_map(|sp| Regex::new(sp.pattern).ok().map(|re| (sp, re)))
            .collect();

        let mut findings = Vec::new();

        for file_path in &files {
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue, // Skip unreadable files (binary, permissions)
            };

            // Skip binary files (check for null bytes in first 8KB)
            if content.len() >= 8192 {
                if content.as_bytes()[..8192].contains(&0) {
                    continue;
                }
            } else if content.as_bytes().contains(&0) {
                continue;
            }

            let rel_path = file_path
                .strip_prefix(ctx.root)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let in_test_dir = is_test_fixture_path(&rel_path);

            for (line_num, line) in content.lines().enumerate() {
                // Skip lines that are ENV var references (not real secrets)
                if is_env_var_reference(line) {
                    continue;
                }

                for (sp, re) in &compiled_patterns {
                    if re.is_match(line) {
                        // Skip test fixtures (JWTs, private keys in spec/ etc.)
                        if in_test_dir {
                            continue;
                        }

                        // Skip URL values flagged as secrets
                        if is_url_value(line, re) {
                            continue;
                        }

                        // Skip placeholder templates: '__KEY__', '{{KEY}}', etc.
                        if is_placeholder_value(line, re) {
                            continue;
                        }

                        let masked = mask_secret(line, re);
                        findings.push(
                            Finding::new(
                                sp.rule_id,
                                sp.severity,
                                format!("{} detected: {masked}", sp.name),
                            )
                            .with_file(&rel_path, line_num + 1)
                            .with_suggestion(format!(
                                "Remove {} and use environment variables instead",
                                sp.name
                            )),
                        );
                    }
                }
            }
        }

        // AST-based secret detection: finds secrets by variable name + entropy
        let ast_findings = crate::secrets_ast::scan_for_secrets(ctx.root, &files);
        // Deduplicate: don't report same file:line from both regex and AST
        use std::collections::HashSet;
        let existing_locations: HashSet<(String, usize)> = findings
            .iter()
            .filter_map(|f| {
                let file = f.file.as_ref()?;
                let line = f.line?;
                Some((file.clone(), line))
            })
            .collect();

        for af in ast_findings {
            let loc = (af.file.clone().unwrap_or_default(), af.line.unwrap_or(0));
            if !existing_locations.contains(&loc) {
                // Apply same test dir filtering to AST findings
                if let Some(ref file) = af.file {
                    if is_test_fixture_path(file) {
                        continue;
                    }
                }
                findings.push(af);
            }
        }

        let file_count = files.len();
        let mut pass_messages = Vec::new();
        if findings.is_empty() {
            pass_messages.push(format!(
                "No hardcoded secrets found (scanned {file_count} files)"
            ));
        } else {
            pass_messages.push(format!("Scanned {file_count} files"));
        }

        Ok(CheckResult::new(
            "secrets",
            findings,
            max_score,
            pass_messages,
        ))
    }
}

/// Collect files to scan, respecting .gitignore-style ignore patterns.
/// Tries `git ls-files` first, falls back to walkdir.
fn collect_scannable_files(root: &Path, ignore_globs: &[String]) -> Vec<std::path::PathBuf> {
    // Try git ls-files first
    if let Ok(output) = std::process::Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let files: Vec<std::path::PathBuf> = stdout
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| root.join(l))
                .filter(|p| p.is_file())
                .filter(|p| !is_in_hidden_dir(p, root)) // skip .cursor/, .svelte-kit/, etc.
                .filter(|p| !is_ignored(p, root, ignore_globs))
                .filter(|p| !is_large_file(p))
                .collect();

            if !files.is_empty() {
                return files;
            }
        }
    }

    // Fallback: walkdir
    WalkDir::new(root)
        .follow_links(false) // Security: don't follow symlinks out of project
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| !is_in_hidden_dir(p, root))
        .filter(|p| !is_ignored(p, root, ignore_globs))
        .filter(|p| !is_large_file(p))
        .collect()
}

fn is_ignored(path: &Path, root: &Path, ignore_globs: &[String]) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();

    for glob in ignore_globs {
        if glob_matches(&rel, glob) {
            return true;
        }
    }

    false
}

fn glob_matches(path: &str, pattern: &str) -> bool {
    // Handle ** (matches any path segments)
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1].trim_start_matches('/');
            let matches_prefix = prefix.is_empty() || path.starts_with(prefix);
            let matches_suffix = if suffix.is_empty() {
                true
            } else if let Some(ext) = suffix.strip_prefix("*.") {
                path.ends_with(&format!(".{ext}"))
            } else {
                path.ends_with(suffix) || path.contains(suffix)
            };
            return matches_prefix && matches_suffix;
        }
    }

    // Handle dir/* (matches files directly in that directory, not subdirectories)
    if let Some(dir_prefix) = pattern.strip_suffix("/*") {
        if let Some(rest) = path.strip_prefix(&format!("{dir_prefix}/")) {
            // Only match if there are no further directory separators
            return !rest.contains('/');
        }
        return false;
    }

    // Handle *.ext
    if let Some(ext) = pattern.strip_prefix("*.") {
        return path.ends_with(&format!(".{ext}"));
    }

    // Exact match or prefix match
    path == pattern || path.starts_with(&format!("{pattern}/"))
}

fn is_in_hidden_dir(path: &Path, root: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    })
}

fn is_large_file(path: &Path) -> bool {
    path.metadata()
        .map(|m| m.len() > 1_048_576)
        .unwrap_or(false) // 1MB
}

fn mask_secret(line: &str, re: &Regex) -> String {
    if let Some(m) = re.find(line) {
        let matched = m.as_str();
        let chars: Vec<char> = matched.chars().collect();
        if chars.len() <= 8 {
            return "****".to_string();
        }
        let first4: String = chars[..4].iter().collect();
        let last4: String = chars[chars.len() - 4..].iter().collect();
        format!("{first4}...{last4}")
    } else {
        "****".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;
    use tempfile::TempDir;

    fn setup_project(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        // Init a git repo so git ls-files works
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

        // Stage all files
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .ok();

        dir
    }

    #[test]
    fn test_no_secrets_clean() {
        let dir = setup_project(&[("main.rs", "fn main() { println!(\"hello\"); }")]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 25.0);
    }

    #[test]
    fn test_aws_key_detected() {
        let dir = setup_project(&[("config.py", "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'")]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-S001"));
    }

    #[test]
    fn test_github_token_detected() {
        let dir = setup_project(&[(
            "env.sh",
            "export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-S003"));
    }

    #[test]
    fn test_private_key_detected() {
        let dir = setup_project(&[(
            "key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-S006"));
    }

    #[test]
    fn test_stripe_key_detected() {
        let dir = setup_project(&[(
            "billing.rb",
            "Stripe.api_key = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'",
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-S015"));
    }

    #[test]
    fn test_connection_string_detected() {
        let dir = setup_project(&[(
            "db.py",
            "DB_URL = 'postgresql://admin:secret123@db.example.com:5432/mydb'",
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-S012"));
    }

    #[test]
    fn test_ignore_path_respected() {
        let dir = setup_project(&[("tests/fixtures/secrets.txt", "AKIAIOSFODNN7EXAMPLE")]);
        let mut config = Config::default();
        config.ignore.secrets = vec!["tests/fixtures/*".into()];
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_mask_secret() {
        let re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let masked = mask_secret("key = AKIAIOSFODNN7EXAMPLE", &re);
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains("..."));
        assert!(masked.ends_with("MPLE"));
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("tests/fixtures/test.txt", "tests/fixtures/*"));
        assert!(glob_matches("src/deep/file.rs", "**/*.rs"));
        assert!(glob_matches("file.pem", "*.pem"));
    }

    #[test]
    fn test_rust_typed_secret_detected() {
        // Rust syntax: CLIENT_SECRET: &str = "value" — has type annotation between name and =
        let dir = setup_project(&[(
            "auth.rs",
            // gitleaks:allow — this is a test fixture, not a real secret
            r#"const CLIENT_SECRET: &str = "1PHTn28JDE1H5_NTwbN7Anmsf8klxwKc_g5ScKdOUU2qV-EthOGCZUI6OKeVFoihWSS7lvKQC-vhadk6ChFomw";"#,
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-S011"),
            "Should detect CLIENT_SECRET with Rust type annotation"
        );
    }

    #[test]
    fn test_secret_with_special_chars_detected() {
        // Secrets containing underscores, dashes, slashes, plus, equals (base64 alphabet)
        let dir = setup_project(&[(
            "config.js",
            // gitleaks:allow — this is a test fixture, not a real secret
            r#"const CLIENT_SECRET = "abc_DEF-123/GHI+jkl=MNO_pqr-STU/vwx+yz0";"#,
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-S011"),
            "Should detect secrets with base64/URL-safe characters"
        );
    }

    #[test]
    fn test_api_key_with_type_annotation() {
        // TypeScript: const API_KEY: string = "value"
        let dir = setup_project(&[(
            "config.ts",
            r#"const API_KEY: string = "abcdefghijklmnopqrstuvwxyz1234567890";"#,
        )]);
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = SecretsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-S010"),
            "Should detect API_KEY with TypeScript type annotation"
        );
    }
}
