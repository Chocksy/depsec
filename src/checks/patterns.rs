use std::path::Path;

use regex::Regex;
use walkdir::WalkDir;

use crate::checks::{Check, CheckResult, Finding, ScanContext, Severity};

struct PatternRule {
    rule_id: &'static str,
    description: &'static str,
    pattern: &'static str,
    severity: Severity,
}

const PATTERN_RULES: &[PatternRule] = &[
    PatternRule {
        rule_id: "DEPSEC-P001",
        description: "eval()/exec() with decoded or variable input",
        pattern: r"(?i)\b(eval|exec)\s*\(\s*[a-zA-Z_]",
        severity: Severity::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P002",
        description: "base64 decode → execute chain",
        pattern: r#"(?i)(atob|base64[._\-]?decode|Buffer\.from\([^)]+,\s*['"]base64['"]).*\b(eval|exec|Function|spawn|child_process|require)\b"#,
        severity: Severity::Critical,
    },
    PatternRule {
        rule_id: "DEPSEC-P003",
        description: "HTTP calls to raw IP addresses",
        pattern: r#"(?i)(https?://|fetch\s*\(\s*['"]https?://|request\s*\(\s*['"]https?://|axios\.\w+\s*\(\s*['"]https?://)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#,
        severity: Severity::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P004",
        description: "File reads targeting sensitive directories",
        pattern: r#"(?i)(readFile|read_file|open)\s*\(\s*['"]?(~/?\.(ssh|aws|env|gnupg)|/home/[^/]+/\.(ssh|aws|env|gnupg)|/root/\.(ssh|aws|env|gnupg))"#,
        severity: Severity::Critical,
    },
    PatternRule {
        rule_id: "DEPSEC-P005",
        description: "Binary file read → byte extraction → execution",
        pattern: r"(?i)(readFileSync|read_file|open)\s*\(.*\.(wav|mp3|png|jpg|ico|bmp)\b",
        severity: Severity::Critical,
    },
    PatternRule {
        rule_id: "DEPSEC-P006",
        description: "postinstall/preinstall scripts with network calls",
        pattern: r"(?i)(curl|wget|fetch|https?\.get|request\(|axios\.\w+)\s*\(",
        severity: Severity::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P008",
        description: "new Function() with dynamic input",
        pattern: r"new\s+Function\s*\(\s*[a-zA-Z_]",
        severity: Severity::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P010",
        description: "Cloud IMDS credential probing",
        pattern: r"169\.254\.(169\.254|170\.2)",
        severity: Severity::Critical,
    },
    PatternRule {
        rule_id: "DEPSEC-P011",
        description: "Environment variable serialization/exfiltration",
        pattern: r"(?i)(JSON\.stringify\s*\(\s*process\.env|os\.environ\b|process\.env\b.*JSON|toJSON\(secrets\))",
        severity: Severity::High,
    },
];

const BINARY_EXTENSIONS: &[&str] = &[
    ".node", ".so", ".dll", ".dylib", ".wasm", ".exe", ".bin", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".svg", ".ttf", ".woff", ".woff2", ".eot", ".zip", ".tar", ".gz", ".bz2",
    ".pdf", ".doc", ".docx",
];

const DEP_DIRS: &[&str] = &[
    "node_modules",
    "vendor/bundle",
    "vendor/gems",
    "vendor",
    ".venv",
    "venv",
];

const MAX_FILE_SIZE: u64 = 500_000; // 500KB

pub struct PatternsCheck;

impl Check for PatternsCheck {
    fn name(&self) -> &str {
        "patterns"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("patterns") as f64;

        let ignored_rules: Vec<&str> = ctx
            .config
            .ignore
            .patterns
            .iter()
            .map(|s| s.as_str())
            .collect();

        let compiled: Vec<(&PatternRule, Regex)> = PATTERN_RULES
            .iter()
            .filter(|r| !ignored_rules.contains(&r.rule_id))
            .filter_map(|r| Regex::new(r.pattern).ok().map(|re| (r, re)))
            .collect();

        let mut findings = Vec::new();
        let mut scanned_files = 0;
        let mut pass_messages = Vec::new();

        // Scan dependency directories
        for dep_dir_name in DEP_DIRS {
            let dep_dir = ctx.root.join(dep_dir_name);
            if !dep_dir.exists() {
                continue;
            }

            for entry in WalkDir::new(&dep_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();

                // Skip binary files by extension
                if is_binary_ext(path) {
                    continue;
                }

                // Skip large files
                if let Ok(meta) = path.metadata() {
                    if meta.len() > MAX_FILE_SIZE {
                        continue;
                    }
                }

                // Skip minified JS for entropy check
                let is_minified = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".min.js") || n.ends_with(".min.mjs"))
                    .unwrap_or(false);

                let content = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => continue, // Skip unreadable files
                };

                scanned_files += 1;
                let rel_path = path
                    .strip_prefix(ctx.root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                // Check regex patterns
                for (line_num, line) in content.lines().enumerate() {
                    for (rule, re) in &compiled {
                        if re.is_match(line) {
                            // Special handling for P006: only flag in package.json scripts
                            if rule.rule_id == "DEPSEC-P006" && !is_install_script(path, line) {
                                continue;
                            }

                            let snippet = truncate_line(line, 80);
                            findings.push(Finding {
                                rule_id: rule.rule_id.into(),
                                severity: rule.severity,
                                message: format!("{}: {snippet}", rule.description),
                                file: Some(rel_path.clone()),
                                line: Some(line_num + 1),
                                suggestion: Some("Review or remove this dependency".into()),
                                auto_fixable: false,
                            });
                        }
                    }
                }

                // DEPSEC-P007: High-entropy strings (skip minified files)
                if !is_minified && !ignored_rules.contains(&"DEPSEC-P007") {
                    check_entropy(&content, &rel_path, &mut findings);
                }
            }
        }

        // DEPSEC-P009: Python .pth file persistence
        if !ignored_rules.contains(&"DEPSEC-P009") {
            check_pth_files(ctx.root, &mut findings);
        }

        // DEPSEC-P012: package.json install scripts with remote fetch
        if !ignored_rules.contains(&"DEPSEC-P012") {
            check_install_scripts(ctx.root, &mut findings);
        }

        if scanned_files > 0 {
            if findings.is_empty() {
                pass_messages.push(format!(
                    "0 suspicious patterns found ({scanned_files} dependency files scanned)"
                ));
            } else {
                pass_messages.push(format!(
                    "{} suspicious pattern{} found ({scanned_files} files scanned)",
                    findings.len(),
                    if findings.len() == 1 { "" } else { "s" }
                ));
            }
        } else {
            pass_messages.push("No dependency directories found to scan".into());
        }

        Ok(CheckResult::new(
            "patterns",
            findings,
            max_score,
            pass_messages,
        ))
    }
}

fn is_binary_ext(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    BINARY_EXTENSIONS.contains(&ext.as_str())
}

fn is_install_script(path: &Path, _line: &str) -> bool {
    // P006 only applies to install scripts (postinstall.sh, preinstall.sh, package.json scripts)
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    filename == "postinstall.sh"
        || filename == "preinstall.sh"
        || filename == "install.sh"
        || filename == "postinstall"
        || filename == "preinstall"
}

fn check_entropy(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for (line_num, line) in content.lines().enumerate() {
        // Look for long strings (> 200 chars of non-whitespace)
        for word in line.split_whitespace() {
            // Strip quotes
            let word = word.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
            if word.len() > 200 {
                let entropy = shannon_entropy(word);
                if entropy > 4.5 {
                    findings.push(Finding {
                        rule_id: "DEPSEC-P007".into(),
                        severity: Severity::Medium,
                        message: format!(
                            "High-entropy string detected ({:.1} bits/char, {} chars)",
                            entropy,
                            word.len()
                        ),
                        file: Some(file.into()),
                        line: Some(line_num + 1),
                        suggestion: Some("Review this string — may be an encoded payload".into()),
                        auto_fixable: false,
                    });
                    break; // One finding per line is enough
                }
            }
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// DEPSEC-P009: Scan Python site-packages for .pth files with executable code
fn check_pth_files(root: &Path, findings: &mut Vec<Finding>) {
    let pth_dangerous = [
        "subprocess",
        "exec(",
        "eval(",
        "base64",
        "import os",
        "import sys",
    ];
    let search_dirs = [".venv", "venv", "site-packages"];

    for dir_name in &search_dirs {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("pth") {
                continue;
            }

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for keyword in &pth_dangerous {
                if content.contains(keyword) {
                    let rel_path = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .to_string();
                    findings.push(Finding {
                        rule_id: "DEPSEC-P009".into(),
                        severity: Severity::Critical,
                        message: format!(
                            ".pth file with executable code: contains '{keyword}'"
                        ),
                        file: Some(rel_path),
                        line: None,
                        suggestion: Some(
                            "Python .pth files execute on every interpreter startup — review or remove immediately".into(),
                        ),
                        auto_fixable: false,
                    });
                    break; // One finding per file is enough
                }
            }
        }
    }
}

/// DEPSEC-P012: Check package.json install scripts for remote code execution
fn check_install_scripts(root: &Path, findings: &mut Vec<Finding>) {
    let package_json = root.join("package.json");
    if !package_json.exists() {
        return;
    }

    let content = match std::fs::read_to_string(&package_json) {
        Ok(c) => c,
        Err(_) => return,
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    let scripts = match parsed.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return,
    };

    let dangerous_hooks = ["preinstall", "postinstall", "install", "prepare"];
    let safe_scripts = [
        "husky install",
        "husky",
        "patch-package",
        "node-gyp rebuild",
        "node-gyp",
        "tsc",
        "esbuild",
        "ngcc",
    ];
    let suspicious_patterns = Regex::new(
        r"(?i)(curl|wget|fetch\s*\(|https?\.get|node\s+\S+\.js|python|bash|sh\s+-c|powershell|eval|exec\s*\()",
    )
    .unwrap();

    for hook in &dangerous_hooks {
        if let Some(script_value) = scripts.get(*hook).and_then(|s| s.as_str()) {
            // Skip known-safe scripts
            if safe_scripts
                .iter()
                .any(|safe| script_value.starts_with(safe))
            {
                continue;
            }

            if suspicious_patterns.is_match(script_value) {
                findings.push(Finding {
                    rule_id: "DEPSEC-P012".into(),
                    severity: Severity::High,
                    message: format!(
                        "Install script '{}' executes suspicious command: {}",
                        hook,
                        truncate_line(script_value, 60)
                    ),
                    file: Some("package.json".into()),
                    line: None,
                    suggestion: Some(format!(
                        "Review the '{hook}' script — install scripts are a common attack vector"
                    )),
                    auto_fixable: false,
                });
            }
        }
    }
}

fn truncate_line(line: &str, max: usize) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        // Safe UTF-8 boundary slicing
        let truncated: String = trimmed.chars().take(max).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // "aaaa" has 0 entropy
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_mixed() {
        let entropy = shannon_entropy("abcdefghijklmnopqrstuvwxyz");
        assert!(entropy > 4.0);
    }

    #[test]
    fn test_is_binary_ext() {
        assert!(is_binary_ext(Path::new("file.png")));
        assert!(is_binary_ext(Path::new("file.wasm")));
        assert!(!is_binary_ext(Path::new("file.js")));
        assert!(!is_binary_ext(Path::new("file.py")));
    }

    #[test]
    fn test_truncate_line() {
        assert_eq!(truncate_line("short", 80), "short");
        let long = "a".repeat(100);
        let truncated = truncate_line(&long, 80);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 83); // 80 + "..."
    }

    #[test]
    fn test_pattern_rules_compile() {
        // Verify all pattern regexes compile
        for rule in PATTERN_RULES {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "Pattern {} failed to compile: {}",
                rule.rule_id,
                rule.pattern
            );
        }
    }
}
