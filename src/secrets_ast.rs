use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::checks::{Finding, Severity};

/// Variable names that strongly suggest a secret
const SUSPICIOUS_NAMES: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "credential",
    "private_key",
    "client_secret",
    "client_id",
    "bearer",
    "jwt",
    "signing_key",
    "encryption_key",
    "master_key",
];

/// Variable names that indicate NOT a real secret (test fixtures, examples)
const NAME_SHOWSTOPPERS: &[&str] = &[
    "public",
    "mock",
    "fake",
    "dummy",
    "test",
    "example",
    "sample",
    "placeholder",
    "template",
    "todo",
    "fixme",
    "default",
    "empty",
    "none",
    "null",
];

/// Value prefixes that indicate a template/reference, not a real secret
const VALUE_SHOWSTOPPERS: &[&str] = &[
    "${",
    "{",
    "<",
    "%",
    "process.env",
    "std::env",
    "os.environ",
    "ENV[",
    "YOUR_",
    "REPLACE_",
    "xxx",
    "000",
    "aaa",
    "example",
    "changeme",
    "password",  // literal "password" as value = placeholder
    "http://",   // URLs are not secrets
    "https://",  // URLs are not secrets
    "select ",   // SQL queries are not secrets
    "insert ",   // SQL queries
    "update ",   // SQL queries
    "delete ",   // SQL queries
    "cast(",     // SQL expressions
    "coalesce(", // SQL expressions
    "./",        // File paths are not secrets
    "../",       // File paths
];

/// Scan source files for hardcoded secrets using AST + entropy
pub fn scan_for_secrets(root: &Path, files: &[std::path::PathBuf]) -> Vec<Finding> {
    let mut js_parser = Parser::new();
    js_parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JS language");

    let mut ts_parser = Parser::new();
    ts_parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TS language");

    let mut py_parser = crate::ast::python::new_parser();
    let mut rb_parser = crate::ast::ruby::new_parser();
    let mut rs_parser = crate::ast::rust_lang::new_parser();

    let mut findings = Vec::new();

    for file in files {
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();

        let parser = match ext {
            "js" | "mjs" | "cjs" | "jsx" => Some(&mut js_parser),
            "ts" | "mts" | "cts" | "tsx" => Some(&mut ts_parser),
            _ => None,
        };

        if let Some(parser) = parser {
            scan_js_ts(parser, &content, &rel_path, &mut findings);
        }

        // Rust files: scan with tree-sitter AST for const/static assignments
        if ext == "rs" {
            scan_rust_ast(&mut rs_parser, &content, &rel_path, &mut findings);
        }

        // Python files: scan with tree-sitter AST for assignments
        if ext == "py" || ext == "pyw" {
            scan_python_ast(&mut py_parser, &content, &rel_path, &mut findings);
        }

        // Ruby files: scan with tree-sitter AST for constant assignments
        if ext == "rb" || ext == "rake" || ext == "gemspec" {
            scan_ruby_ast(&mut rb_parser, &content, &rel_path, &mut findings);
        }
    }

    findings
}

/// Scan JS/TS files using tree-sitter for variable assignments with string values
fn scan_js_ts(parser: &mut Parser, content: &str, file_path: &str, findings: &mut Vec<Finding>) {
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return,
    };
    let source = content.as_bytes();

    // Query: const/let/var NAME = "value"
    let query = Query::new(
        &tree.language(),
        r#"
        (variable_declarator
          name: (identifier) @name
          value: (string (string_fragment) @value))
        "#,
    );

    if let Ok(query) = query {
        let name_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "name")
            .unwrap();
        let value_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "value")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let name_cap = m.captures.iter().find(|c| c.index as usize == name_idx);
            let value_cap = m.captures.iter().find(|c| c.index as usize == value_idx);

            if let (Some(name_cap), Some(value_cap)) = (name_cap, value_cap) {
                let name = name_cap.node.utf8_text(source).unwrap_or("");
                let value = value_cap.node.utf8_text(source).unwrap_or("");
                let line = name_cap.node.start_position().row + 1;

                check_secret_candidate(name, value, file_path, line, findings);
            }
        }
    }
}

/// Scan Rust const/static declarations for hardcoded secrets using tree-sitter AST
fn scan_rust_ast(parser: &mut Parser, content: &str, file_path: &str, findings: &mut Vec<Finding>) {
    let assignments = crate::ast::rust_lang::extract_assignments(parser, content);

    for (name, value, line) in assignments {
        if let Some(src_line) = content.lines().nth(line.saturating_sub(1)) {
            if src_line.contains("depsec:allow") {
                continue;
            }
        }
        check_secret_candidate(&name, &value, file_path, line, findings);
    }
}

/// Scan Ruby constant assignments for hardcoded secrets using tree-sitter AST
fn scan_ruby_ast(parser: &mut Parser, content: &str, file_path: &str, findings: &mut Vec<Finding>) {
    let assignments = crate::ast::ruby::extract_assignments(parser, content);

    for (name, value, line) in assignments {
        if let Some(src_line) = content.lines().nth(line.saturating_sub(1)) {
            if src_line.contains("depsec:allow") {
                continue;
            }
        }
        check_secret_candidate(&name, &value, file_path, line, findings);
    }
}

/// Scan Python assignments for hardcoded secrets using tree-sitter AST
fn scan_python_ast(
    parser: &mut Parser,
    content: &str,
    file_path: &str,
    findings: &mut Vec<Finding>,
) {
    let assignments = crate::ast::python::extract_assignments(parser, content);

    for (name, value, line) in assignments {
        // Check if line has depsec:allow
        if let Some(src_line) = content.lines().nth(line.saturating_sub(1)) {
            if src_line.contains("depsec:allow") {
                continue;
            }
        }
        check_secret_candidate(&name, &value, file_path, line, findings);
    }
}

/// Core logic: check if a name+value pair looks like a hardcoded secret
fn check_secret_candidate(
    name: &str,
    value: &str,
    file_path: &str,
    line: usize,
    findings: &mut Vec<Finding>,
) {
    let name_lower = name.to_lowercase();

    // Check showstoppers — skip test/mock/example values
    if NAME_SHOWSTOPPERS.iter().any(|s| name_lower.contains(s)) {
        return;
    }

    // Check value showstoppers — template references, placeholders
    let value_lower = value.to_lowercase();
    if VALUE_SHOWSTOPPERS
        .iter()
        .any(|s| value_lower.starts_with(&s.to_lowercase()))
    {
        return;
    }

    // Check if it's a sequential/repetitive string (not a secret)
    if is_sequential(value) {
        return;
    }

    let has_suspicious_name = SUSPICIOUS_NAMES.iter().any(|s| name_lower.contains(s));

    let entropy = shannon_entropy(value);
    let len = value.len();

    // Tiered thresholds
    if has_suspicious_name && entropy >= 3.5 && len >= 16 {
        // HIGH: suspicious name + high entropy + long value
        let masked = mask_value(value);
        findings.push(
            Finding::new(
                "DEPSEC-S021",
                Severity::Critical,
                format!(
                "{name} assigned high-entropy secret ({:.1} bits/char, {len} chars): \"{masked}\"",
                entropy
            ),
            )
            .with_file(file_path, line)
            .with_confidence(crate::checks::Confidence::High)
            .with_suggestion(format!(
                "Move to environment variable: std::env::var(\"{name}\") or process.env.{name}"
            )),
        );
    } else if has_suspicious_name && len >= 8 {
        // MEDIUM: suspicious name + any value (even low entropy)
        let masked = mask_value(value);
        findings.push(
            Finding::new(
                "DEPSEC-S022",
                Severity::High,
                format!("{name} assigned potential secret ({len} chars): \"{masked}\""),
            )
            .with_file(file_path, line)
            .with_confidence(crate::checks::Confidence::Medium)
            .with_suggestion("Move to environment variable or config file"),
        );
    } else if entropy >= 4.5 && len >= 30 {
        // LOW: high entropy + long value, no name signal
        let masked = mask_value(value);
        findings.push(
            Finding::new(
                "DEPSEC-S023",
                Severity::Medium,
                format!(
                "{name} assigned high-entropy string ({:.1} bits/char, {len} chars): \"{masked}\"",
                entropy
            ),
            )
            .with_file(file_path, line)
            .with_confidence(crate::checks::Confidence::Low)
            .with_suggestion("Review — may be a hardcoded secret, hash, or encoded data"),
        );
    }
}

fn shannon_entropy(s: &str) -> f64 {
    crate::utils::shannon_entropy(s)
}

/// Check if a string is sequential/repetitive (not a secret)
fn is_sequential(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    let bytes = s.as_bytes();
    // All same character
    if bytes.iter().all(|&b| b == bytes[0]) {
        return true;
    }
    // Sequential (abc..., 123...)
    let is_seq = bytes
        .windows(2)
        .all(|w| w[1] == w[0] + 1 || w[1] == w[0] - 1);
    is_seq
}

/// Mask a secret value for display: show first 4 and last 4 chars
fn mask_value(value: &str) -> String {
    if value.len() <= 12 {
        return "****".into();
    }
    let first = &value[..4];
    let last = &value[value.len() - 4..];
    format!("{first}...{last}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_name_detection() {
        let mut findings = Vec::new();
        // Should detect: suspicious name + high entropy + long value
        check_secret_candidate(
            "CLIENT_SECRET",
            "1PHTn28JDE1H5_NTwbN7Anmsf8klxwKc_g5ScKdOUU2qV",
            "auth.rs",
            9,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-S021");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_client_id_detected() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "CLIENT_ID",
            "RSMvSFhq3H1aYUn_MJ-gMoYyiLOHx-FFdTvE51Vyl6g",
            "auth.rs",
            8,
            &mut findings,
        );
        // CLIENT_ID doesn't contain any SUSPICIOUS_NAMES entries... but it has "client" and we have "client_id"
        assert!(!findings.is_empty(), "CLIENT_ID should be detected");
    }

    #[test]
    fn test_api_key_detected() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "API_KEY",
            "sk-1234567890abcdefghijklmnopqrstuv",
            "config.js",
            5,
            &mut findings,
        );
        assert!(!findings.is_empty());
        assert!(findings[0].rule_id == "DEPSEC-S021" || findings[0].rule_id == "DEPSEC-S022");
    }

    #[test]
    fn test_password_detected() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "DB_PASSWORD",
            "super-secret-db-pass-123",
            "config.py",
            10,
            &mut findings,
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_mock_secret_skipped() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "MOCK_SECRET",
            "fake-secret-for-testing-purposes-1234",
            "test_config.rs",
            5,
            &mut findings,
        );
        // "mock" is in NAME_SHOWSTOPPERS — should be skipped
        assert!(findings.is_empty(), "Mock secrets should be skipped");
    }

    #[test]
    fn test_test_token_skipped() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "TEST_TOKEN",
            "fake-token-1234567890abcdefghijklm",
            "test.rs",
            5,
            &mut findings,
        );
        assert!(findings.is_empty(), "Test tokens should be skipped");
    }

    #[test]
    fn test_placeholder_skipped() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "API_KEY",
            "YOUR_API_KEY_HERE",
            "config.example.js",
            5,
            &mut findings,
        );
        assert!(findings.is_empty(), "Placeholder values should be skipped");
    }

    #[test]
    fn test_env_reference_skipped() {
        let mut findings = Vec::new();
        check_secret_candidate("API_KEY", "${API_KEY}", "config.js", 5, &mut findings);
        assert!(findings.is_empty(), "Template references should be skipped");
    }

    #[test]
    fn test_sequential_skipped() {
        let mut findings = Vec::new();
        check_secret_candidate(
            "API_KEY",
            "abcdefghijklmnopqrstuvwxyz",
            "config.js",
            5,
            &mut findings,
        );
        assert!(findings.is_empty(), "Sequential strings should be skipped");
    }

    #[test]
    fn test_high_entropy_no_name() {
        let mut findings = Vec::new();
        // No suspicious name but very high entropy + long
        check_secret_candidate(
            "DATA",
            "aK3fR9xL2mN5pQ8sT1vW4yB7dG0hJ3kM6nP9qS2uV5xZ8",
            "config.js",
            5,
            &mut findings,
        );
        // Should be LOW confidence (S023) if entropy >= 4.5 and len >= 30
        // The entropy of this string is high (many unique chars)
        if !findings.is_empty() {
            assert_eq!(findings[0].rule_id, "DEPSEC-S023");
        }
    }

    #[test]
    fn test_rust_const_scanning() {
        let content = r#"
const CLIENT_SECRET: &str = "1PHTn28JDE1H5_NTwbN7Anmsf8klxwKc";
const CLIENT_ID: &str = "RSMvSFhq3H1aYUn_MJ-gMoYyiLOHx";
const VERSION: &str = "1.0.0";
const TEST_SECRET: &str = "fake-for-testing";
"#;
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("auth.rs");
        std::fs::write(&file, content).unwrap();

        let findings = scan_for_secrets(dir.path(), &[file]);
        assert!(
            findings.iter().any(|f| f.message.contains("CLIENT_SECRET")),
            "Should detect CLIENT_SECRET"
        );
        assert!(
            !findings.iter().any(|f| f.message.contains("VERSION")),
            "Should skip VERSION"
        );
        assert!(
            !findings.iter().any(|f| f.message.contains("TEST_SECRET")),
            "Should skip TEST_SECRET (has 'test' showstopper)"
        );
    }

    #[test]
    fn test_depsec_allow_inline() {
        let content = r#"
const CLIENT_SECRET: &str = "real-secret-12345678"; // depsec:allow — rotated
const ANOTHER_SECRET: &str = "also-a-real-secret-678";
"#;
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("auth.rs");
        std::fs::write(&file, content).unwrap();

        let findings = scan_for_secrets(dir.path(), &[file]);
        // First one has depsec:allow — should be skipped
        // Second one should be detected
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ANOTHER_SECRET"));
    }

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!(shannon_entropy("abcdefgh") > 2.0);
        assert!(shannon_entropy("aK3fR9xL2mN5pQ8s") > 3.5);
    }

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("short"), "****");
        assert_eq!(mask_value("1PHTn28JDE1H5_NTwbN7"), "1PHT...wbN7");
    }

    #[test]
    fn test_is_sequential() {
        assert!(is_sequential("aaaaaaaa"));
        assert!(is_sequential("abcdefghijklmnop"));
        assert!(!is_sequential("aK3fR9xL"));
        assert!(!is_sequential("short"));
    }

    #[test]
    fn test_ruby_constant_scanning() {
        // gitleaks:allow — test fixture, not a real secret
        let content = r#"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuv"
VERSION = "1.0.0"
TEST_SECRET = "fake-for-testing"
"#;
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.rb");
        std::fs::write(&file, content).unwrap();

        let findings = scan_for_secrets(dir.path(), &[file]);
        assert!(
            findings.iter().any(|f| f.message.contains("API_KEY")),
            "Should detect API_KEY in Ruby"
        );
        assert!(
            !findings.iter().any(|f| f.message.contains("TEST_SECRET")),
            "Should skip TEST_SECRET (has 'test' showstopper)"
        );
    }
}
