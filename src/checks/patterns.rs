use std::path::Path;

use regex::Regex;
use walkdir::WalkDir;

use crate::ast::AstAnalyzer;
use crate::checks::{Check, CheckResult, Confidence, Finding, ScanContext, Severity};

struct PatternRule {
    rule_id: &'static str,
    #[allow(dead_code)]
    name: &'static str,
    description: &'static str,
    suggestion: &'static str,
    #[allow(dead_code)]
    narrative: &'static str,
    pattern: &'static str,
    severity: Severity,
    confidence: Confidence,
}

const PATTERN_RULES: &[PatternRule] = &[
    PatternRule {
        rule_id: "DEPSEC-P001",
        name: "Shell Execution",
        description: "eval()/exec() with decoded or variable input",
        suggestion: "Verify commands are static or properly escaped — safe for build tools, suspicious for runtime libraries",
        narrative: "Calls child_process.exec/spawn with variable arguments. If user-controlled, enables Remote Code Execution. Common in build tools where it's expected.",
        pattern: r"(?i)\b(eval|exec)\s*\(\s*[a-zA-Z_]",
        severity: Severity::High,
        confidence: Confidence::Low,
    },
    PatternRule {
        rule_id: "DEPSEC-P002",
        name: "Encoded Execution",
        description: "base64 decode → execute chain",
        suggestion: "Investigate immediately — base64-to-exec is the #1 malware obfuscation pattern",
        narrative: "Decodes base64/atob data and passes it to eval, exec, or Function. This is the #1 obfuscation pattern in npm malware. Legitimate uses are rare.",
        pattern: r#"(?i)(atob|base64[._\-]?decode|Buffer\.from\([^)]+,\s*['"]base64['"]).*\b(eval|exec|Function|spawn|child_process|require)\b"#,
        severity: Severity::Critical,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P003",
        name: "Raw IP Network Call",
        description: "HTTP calls to raw IP addresses",
        suggestion: "Check if the IP is a known service — raw IPs in production deps are suspicious",
        narrative: "Makes HTTP requests to a hardcoded IP address instead of a domain. Malware uses raw IPs to avoid DNS-based blocking. Could also be local dev/testing.",
        pattern: r#"(?i)(https?://|fetch\s*\(\s*['"]https?://|request\s*\(\s*['"]https?://|axios\.\w+\s*\(\s*['"]https?://)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#,
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P004",
        name: "Credential Harvesting",
        description: "File reads targeting sensitive directories",
        suggestion: "Remove immediately — no legitimate package reads your SSH keys or AWS credentials",
        narrative: "Reads files from ~/.ssh, ~/.aws, ~/.env, or ~/.gnupg. These contain credentials and private keys. Legitimate packages never need to read your credentials.",
        pattern: r#"(?i)(readFile|read_file|open)\s*\(\s*['"]?(~/?\.(ssh|aws|env|gnupg)|/home/[^/]+/\.(ssh|aws|env|gnupg)|/root/\.(ssh|aws|env|gnupg))"#,
        severity: Severity::Critical,
        confidence: Confidence::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P005",
        name: "Steganographic Payload",
        description: "Binary file read → byte extraction → execution",
        suggestion: "Investigate the binary file — hiding payloads in images/audio is a known malware technique",
        narrative: "Reads binary files (.wav, .mp3, .png, .ico) and extracts bytes. A known malware technique: hide executable payload in media files to evade text scanners.",
        pattern: r"(?i)(readFileSync|read_file|open)\s*\(.*\.(wav|mp3|png|jpg|ico|bmp)\b",
        severity: Severity::Critical,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P006",
        name: "Install Script Download",
        description: "postinstall/preinstall scripts with network calls",
        suggestion: "Review the install script — legitimate uses include downloading prebuilt binaries",
        narrative: "Install script makes network calls (curl, wget, fetch). These run automatically during npm install with full system access. Malware uses them to download second-stage payloads.",
        pattern: r"(?i)(curl|wget|fetch|https?\.get|request\(|axios\.\w+)\s*\(",
        severity: Severity::High,
        confidence: Confidence::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P008",
        name: "Dynamic Code Construction",
        description: "new Function() with dynamic input",
        suggestion: "Expected for template engines — verify template inputs are properly escaped",
        narrative: "Uses new Function() to create executable code from strings at runtime. Standard for template engines (ejs, pug, handlebars). Dangerous if the input string is user-controlled.",
        pattern: r"new\s+Function\s*\(\s*[a-zA-Z_]",
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P010",
        name: "Cloud Credential Probing",
        description: "Cloud IMDS credential probing",
        suggestion: "Remove immediately unless this is a cloud SDK — IMDS access from deps is a red flag",
        narrative: "Accesses the cloud instance metadata service (169.254.169.254). IMDS provides IAM credentials and instance identity. If your code runs in cloud, this could steal credentials.",
        pattern: r"169\.254\.(169\.254|170\.2)\b",
        severity: Severity::Critical,
        confidence: Confidence::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P011",
        name: "Environment Exfiltration",
        description: "Environment variable serialization/exfiltration",
        suggestion: "Check if serialized env is sent over the network — legitimate logging should filter secrets",
        narrative: "Serializes process.env or os.environ to JSON. Environment variables often contain API keys and secrets. Serializing all of them is a prerequisite for exfiltration.",
        pattern: r"(?i)(JSON\.stringify\s*\(\s*process\.env|os\.environ\b|process\.env\b.*JSON|toJSON\(secrets\))",
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
];

const BINARY_EXTENSIONS: &[&str] = &[
    ".node", ".so", ".dll", ".dylib", ".wasm", ".exe", ".bin", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".svg", ".ttf", ".woff", ".woff2", ".eot", ".zip", ".tar", ".gz", ".bz2",
    ".pdf", ".doc", ".docx",
];

/// Extensions that produce false positives — metadata/declarations, not executable code
const SKIP_EXTENSIONS: &[&str] = &[
    ".map",   // source maps — stringified source, never executed
    ".d.ts",  // TypeScript declarations — type definitions only
    ".d.mts", // module declaration files
    ".d.cts", // CommonJS declaration files
];

/// Directory names inside dep dirs that should be skipped entirely.
/// NOTE: test/tests/spec are NOT skipped — malicious packages can hide payloads there.
const SKIP_DIR_NAMES: &[&str] = &[
    ".vite", // Vite prebundled cache — duplicates of node_modules packages
];

/// Non-code files inside dep dirs that should be skipped
const SKIP_FILENAMES: &[&str] = &[
    "README.md",
    "readme.md",
    "CHANGELOG.md",
    "changelog.md",
    "HISTORY.md",
    "LICENSE",
    "LICENSE.md",
    "license",
];

const DEP_DIRS: &[&str] = &[
    "node_modules",
    "vendor", // covers vendor/bundle, vendor/gems, and Go/PHP vendor dirs
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
        let mut ast_analyzer = AstAnalyzer::new();

        // Scan dependency directories
        for dep_dir_name in DEP_DIRS {
            let dep_dir = ctx.root.join(dep_dir_name);
            if !dep_dir.exists() {
                continue;
            }

            let extra_skip_dirs = &ctx.config.patterns.skip_dirs;
            for entry in WalkDir::new(&dep_dir)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_str().unwrap_or("");
                    !should_skip_dir(name) && !extra_skip_dirs.iter().any(|d| d == name)
                })
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();

                // Skip binary files by extension
                if is_binary_ext(path) {
                    continue;
                }

                // Skip metadata/declaration files that produce false positives
                if is_skip_ext(path) {
                    continue;
                }

                // Skip non-code files (READMEs, CHANGELOGs, LICENSEs)
                if is_skip_filename(path) {
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

                // AST analysis for JS/TS files — handles P001 and P008 with High confidence
                // Only parse with tree-sitter if the file mentions dangerous modules or patterns.
                // Broader than regex P001 — also catches spawn, execFile, child_process imports.
                let needs_ast = AstAnalyzer::can_analyze(path)
                    && (content.contains("child_process")
                        || content.contains("shelljs")
                        || content.contains("execa")
                        || content.contains("cross-spawn")
                        || content.contains("new Function"));

                let ast_handled = if needs_ast {
                    let ast_findings = ast_analyzer.analyze(path, &content);
                    let pkg = extract_package_name(&rel_path);
                    for af in &ast_findings {
                        let suggestion = match af.rule_id.as_str() {
                            "DEPSEC-P001" => "Verify commands are static or properly escaped — safe for build tools, suspicious for runtime libraries",
                            "DEPSEC-P008" => "Expected for template engines — verify template inputs are properly escaped",
                            _ => "Review this dependency for suspicious behavior",
                        };
                        findings.push(Finding {
                            rule_id: af.rule_id.clone(),
                            severity: af.severity,
                            confidence: Some(af.confidence),
                            message: af.message.clone(),
                            file: Some(rel_path.clone()),
                            line: Some(af.line),
                            suggestion: Some(suggestion.into()),
                            package: pkg.clone(),
                            reachable: None,
                            auto_fixable: false,
                        });
                    }
                    true
                } else {
                    false
                };

                // Regex patterns — skip AST-handled rules for JS/TS files
                for (line_num, line) in content.lines().enumerate() {
                    for (rule, re) in &compiled {
                        // If AST analyzed this file, skip P001 and P008 (AST handles them)
                        if ast_handled && is_ast_rule(rule.rule_id) {
                            continue;
                        }

                        if re.is_match(line) {
                            // Special handling for P006: only flag in package.json scripts
                            if rule.rule_id == "DEPSEC-P006" && !is_install_script(path, line) {
                                continue;
                            }

                            let snippet = truncate_line(line, 80);
                            findings.push(Finding {
                                rule_id: rule.rule_id.into(),
                                severity: rule.severity,
                                confidence: Some(rule.confidence),
                                message: format!("{}: {snippet}", rule.description),
                                file: Some(rel_path.clone()),
                                line: Some(line_num + 1),
                                suggestion: Some(rule.suggestion.into()),
                                package: extract_package_name(&rel_path),
                                reachable: None,
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

        // Apply per-package allow rules from config
        let allow_rules = &ctx.config.patterns.allow;
        if !allow_rules.is_empty() {
            let before_count = findings.len();
            findings.retain(|f| {
                if let Some(pkg) = &f.package {
                    if let Some(allowed_rules) = allow_rules.get(pkg) {
                        return !allowed_rules.iter().any(|r| r == &f.rule_id);
                    }
                }
                true // Keep findings without package or without allow rules
            });
            let suppressed = before_count - findings.len();
            if suppressed > 0 {
                pass_messages.push(format!(
                    "{suppressed} finding{} suppressed by per-package allow rules",
                    if suppressed == 1 { "" } else { "s" }
                ));
            }
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

/// Extract package name from a dependency file path.
/// "node_modules/@scope/pkg/lib/file.js" → "@scope/pkg"
/// "node_modules/lodash/index.js" → "lodash"
/// "vendor/bundle/ruby/3.2.0/gems/rails-7.1.0/..." → "rails-7.1.0"
/// ".venv/lib/python3.11/site-packages/requests/..." → "requests"
fn extract_package_name(rel_path: &str) -> Option<String> {
    // Use rfind to handle nested node_modules (e.g., node_modules/a/node_modules/b/...)
    if let Some(pos) = rel_path.rfind("node_modules/") {
        let rest = &rel_path[pos + "node_modules/".len()..];
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.is_empty() {
            return None;
        }
        // Scoped package: @scope/name
        if parts[0].starts_with('@') && parts.len() >= 2 {
            return Some(format!("{}/{}", parts[0], parts[1]));
        }
        return Some(parts[0].to_string());
    }

    // vendor/bundle/ruby/X.Y.Z/gems/NAME-VERSION/...
    if let Some(rest) = rel_path.strip_prefix("vendor/") {
        if let Some(gems_pos) = rest.find("gems/") {
            let after_gems = &rest[gems_pos + 5..];
            if let Some(slash) = after_gems.find('/') {
                return Some(after_gems[..slash].to_string());
            }
            return Some(after_gems.to_string());
        }
    }

    // .venv/lib/pythonX.Y/site-packages/NAME/...
    if rel_path.starts_with(".venv/") || rel_path.starts_with("venv/") {
        if let Some(sp_pos) = rel_path.find("site-packages/") {
            let after_sp = &rel_path[sp_pos + 14..];
            if let Some(slash) = after_sp.find('/') {
                return Some(after_sp[..slash].to_string());
            }
            return Some(after_sp.to_string());
        }
    }

    None
}

/// Rules that are handled by the AST engine when the file is JS/TS
fn is_ast_rule(rule_id: &str) -> bool {
    matches!(rule_id, "DEPSEC-P001" | "DEPSEC-P008")
}

fn is_binary_ext(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    BINARY_EXTENSIONS.contains(&ext.as_str())
}

fn is_skip_ext(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Check compound extensions like .d.ts, .d.ts.map
    SKIP_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIR_NAMES.contains(&name)
}

fn is_skip_filename(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    SKIP_FILENAMES.contains(&name)
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
                        confidence: Some(Confidence::Low),
                        message: format!(
                            "High-entropy string detected ({:.1} bits/char, {} chars)",
                            entropy,
                            word.len()
                        ),
                        file: Some(file.into()),
                        line: Some(line_num + 1),
                        suggestion: Some("Check if the string is a known data table or if it decodes to executable code".into()),
                        package: extract_package_name(file),
                        reachable: None,
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
                        confidence: Some(Confidence::High),
                        message: format!(
                            ".pth file with executable code: contains '{keyword}'"
                        ),
                        file: Some(rel_path),
                        line: None,
                        suggestion: Some(
                            "Remove immediately — .pth files with executable code are almost always malicious".into(),
                        ),
                        package: None,
                        reachable: None,
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
                    confidence: Some(Confidence::High),
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
                    package: None,
                    reachable: None,
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

    #[test]
    fn test_is_skip_ext() {
        assert!(is_skip_ext(Path::new("devalue.js.map")));
        assert!(is_skip_ext(Path::new("types.d.ts")));
        assert!(is_skip_ext(Path::new("module.d.mts")));
        assert!(is_skip_ext(Path::new("cjs.d.cts")));
        assert!(!is_skip_ext(Path::new("index.js")));
        assert!(!is_skip_ext(Path::new("utils.ts")));
        assert!(!is_skip_ext(Path::new("main.py")));
    }

    #[test]
    fn test_should_skip_dir() {
        assert!(should_skip_dir(".vite"));
        // test/tests/spec are NOT skipped (security: malicious packages hide payloads there)
        assert!(!should_skip_dir("test"));
        assert!(!should_skip_dir("tests"));
        assert!(!should_skip_dir("spec"));
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir("lib"));
        assert!(!should_skip_dir("dist"));
    }

    #[test]
    fn test_is_skip_filename() {
        assert!(is_skip_filename(Path::new("README.md")));
        assert!(is_skip_filename(Path::new("CHANGELOG.md")));
        assert!(is_skip_filename(Path::new("LICENSE")));
        assert!(!is_skip_filename(Path::new("index.js")));
        assert!(!is_skip_filename(Path::new("package.json")));
    }

    #[test]
    fn test_extract_package_name_npm() {
        assert_eq!(
            extract_package_name("node_modules/lodash/index.js"),
            Some("lodash".into())
        );
    }

    #[test]
    fn test_extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("node_modules/@sveltejs/kit/src/lib.js"),
            Some("@sveltejs/kit".into())
        );
    }

    #[test]
    fn test_extract_package_name_nested() {
        // Should return innermost package
        assert_eq!(
            extract_package_name("node_modules/pkg-a/node_modules/pkg-b/lib/evil.js"),
            Some("pkg-b".into())
        );
    }

    #[test]
    fn test_extract_package_name_vendor_gems() {
        assert_eq!(
            extract_package_name("vendor/bundle/ruby/3.2.0/gems/rails-7.1.0/lib/active.rb"),
            Some("rails-7.1.0".into())
        );
    }

    #[test]
    fn test_extract_package_name_venv() {
        assert_eq!(
            extract_package_name(".venv/lib/python3.11/site-packages/requests/api.py"),
            Some("requests".into())
        );
    }

    #[test]
    fn test_extract_package_name_unknown() {
        assert_eq!(extract_package_name("src/main.rs"), None);
    }
}
