use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::checks::{Confidence, Severity};

use super::AstFinding;

/// Initialize a Rust tree-sitter parser
pub fn new_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("failed to set Rust language");
    parser
}

/// Analyze Rust source for security patterns
pub fn analyze(parser: &mut Parser, source: &str) -> Vec<AstFinding> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut findings = Vec::new();

    // P040: Command::new() / process execution
    find_command_execution(&tree, source_bytes, &mut findings);

    // P041: unsafe blocks
    find_unsafe_blocks(&tree, source_bytes, &mut findings);

    // P042: extern "C" / FFI
    find_ffi_declarations(&tree, source_bytes, &mut findings);

    // P043: include_bytes! / include_str!
    find_file_inclusion_macros(&tree, source_bytes, &mut findings);

    findings
}

/// P040: Command::new() — process execution
fn find_command_execution(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Match Command::new("...") calls via scoped_identifier
    let query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (scoped_identifier
            name: (identifier) @method)
          (#eq? @method "new"))
        "#,
    );

    if let Ok(query) = query {
        let method_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "method")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == method_idx) {
                // Check if the full scoped path contains "Command"
                if let Some(parent) = cap.node.parent() {
                    let full_path = parent.utf8_text(source).unwrap_or("");
                    if full_path.contains("Command") {
                        let line = parent.start_position().row + 1;
                        findings.push(AstFinding {
                            rule_id: "DEPSEC-P040".into(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            message: "Command::new() — process execution".into(),
                            line,
                        });
                    }
                }
            }
        }
    }
}

/// P041: unsafe blocks
fn find_unsafe_blocks(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(&tree.language(), r#"(unsafe_block) @unsafe"#);

    if let Ok(query) = query {
        let idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "unsafe")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == idx) {
                let line = cap.node.start_position().row + 1;
                findings.push(AstFinding {
                    rule_id: "DEPSEC-P041".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    message: "unsafe block — bypasses Rust memory safety guarantees".into(),
                    line,
                });
            }
        }
    }
}

/// P042: extern "C" / FFI declarations
fn find_ffi_declarations(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Try extern_block first, fallback to foreign_mod_item
    for pattern in &[r#"(extern_block) @ffi"#, r#"(foreign_mod_item) @ffi"#] {
        let query = Query::new(&tree.language(), pattern);

        if let Ok(query) = query {
            let idx = query
                .capture_names()
                .iter()
                .position(|n| *n == "ffi")
                .unwrap();

            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source);
            let pre_count = findings.len();

            while let Some(m) = matches.next() {
                if let Some(cap) = m.captures.iter().find(|c| c.index as usize == idx) {
                    let line = cap.node.start_position().row + 1;
                    findings.push(AstFinding {
                        rule_id: "DEPSEC-P042".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        message: "extern block — FFI boundary, memory safety not guaranteed".into(),
                        line,
                    });
                }
            }
            // Only skip fallback pattern if this one found matches
            if findings.len() > pre_count {
                break;
            }
        }
    }
}

/// P043: include_bytes! / include_str! macros
fn find_file_inclusion_macros(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let query = Query::new(
        &tree.language(),
        r#"
        (macro_invocation
          macro: (identifier) @name
          (#match? @name "^(include_bytes|include_str)$"))
        "#,
    );

    if let Ok(query) = query {
        let name_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "name")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == name_idx) {
                let macro_name = cap.node.utf8_text(source).unwrap_or("");
                let line = cap.node.start_position().row + 1;

                findings.push(AstFinding {
                    rule_id: "DEPSEC-P043".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    message: format!("{}!() — embeds file contents at compile time", macro_name),
                    line,
                });
            }
        }
    }
}

/// Extract Rust `use` declarations for reachability analysis.
/// Returns a list of crate names directly used.
pub fn extract_uses(parser: &mut Parser, source: &str) -> Vec<String> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut crates = Vec::new();

    // Walk use_declaration nodes and extract the root crate name
    // This handles all nesting depths: `use serde`, `use serde::Serialize`,
    // `use std::collections::HashMap`, etc.
    let query = Query::new(&tree.language(), r#"(use_declaration) @use"#);

    if let Ok(query) = query {
        let idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "use")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == idx) {
                if let Some(root_name) = find_root_identifier(&cap.node, source_bytes) {
                    if root_name != "self" && root_name != "crate" && root_name != "super" {
                        crates.push(root_name);
                    }
                }
            }
        }
    }

    // Match: extern crate name;
    let extern_query = Query::new(
        &tree.language(),
        r#"
        (extern_crate_declaration
          name: (identifier) @crate_name)
        "#,
    );

    if let Ok(query) = extern_query {
        let idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "crate_name")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == idx) {
                if let Ok(name) = cap.node.utf8_text(source_bytes) {
                    crates.push(name.to_string());
                }
            }
        }
    }

    crates.sort();
    crates.dedup();
    crates
}

/// Extract Rust constant assignments for secret detection.
/// Returns (name, value, line) tuples.
pub fn extract_assignments(parser: &mut Parser, source: &str) -> Vec<(String, String, usize)> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut results = Vec::new();

    // Match const/static items with string values
    // Try const_item and static_item separately since alternation syntax may vary
    for pattern in &[
        r#"(const_item name: (identifier) @name value: (string_literal (string_content) @value))"#,
        r#"(static_item name: (identifier) @name value: (string_literal (string_content) @value))"#,
    ] {
        let query = Query::new(&tree.language(), pattern);

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
            let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

            while let Some(m) = matches.next() {
                let name_cap = m.captures.iter().find(|c| c.index as usize == name_idx);
                let value_cap = m.captures.iter().find(|c| c.index as usize == value_idx);
                let (Some(name_cap), Some(value_cap)) = (name_cap, value_cap) else {
                    continue;
                };

                let name = name_cap.node.utf8_text(source_bytes).unwrap_or("");
                let value = value_cap.node.utf8_text(source_bytes).unwrap_or("");
                let line = name_cap.node.start_position().row + 1;

                if value.len() >= 8 {
                    results.push((name.to_string(), value.to_string(), line));
                }
            }
        }
    }

    results
}

/// Walk a use_declaration node to find the root crate identifier.
/// Handles arbitrary nesting: `use serde::Serialize` → "serde",
/// `use std::collections::HashMap` → "std"
fn find_root_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }
        if child.kind() == "scoped_identifier" || child.kind() == "use_list" {
            // Recurse into scoped identifiers to find the leftmost identifier
            return find_root_identifier(&child, source);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rs(source: &str) -> Vec<AstFinding> {
        let mut parser = new_parser();
        analyze(&mut parser, source)
    }

    // --- P040: Command execution ---

    #[test]
    fn test_command_new_flagged() {
        let findings = parse_rs(
            r#"
fn run() {
    std::process::Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}
"#,
        );
        let p040: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P040")
            .collect();
        assert!(!p040.is_empty(), "Command::new should be flagged");
    }

    #[test]
    fn test_command_short_path() {
        let findings = parse_rs(
            r#"
use std::process::Command;
fn run() {
    Command::new("sh").output().unwrap();
}
"#,
        );
        let p040: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P040")
            .collect();
        assert!(
            !p040.is_empty(),
            "Command::new (short path) should be flagged"
        );
    }

    // --- P041: unsafe ---

    #[test]
    fn test_unsafe_block_flagged() {
        let findings = parse_rs(
            r#"
fn danger() {
    unsafe { std::ptr::read(addr) };
}
"#,
        );
        let p041: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P041")
            .collect();
        assert!(!p041.is_empty(), "unsafe block should be flagged");
        assert_eq!(p041[0].severity, Severity::Medium);
    }

    // --- P042: FFI ---

    #[test]
    fn test_extern_block_flagged() {
        let findings = parse_rs(
            r#"
extern "C" {
    fn evil_function(ptr: *mut u8);
}
"#,
        );
        let p042: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P042")
            .collect();
        assert!(!p042.is_empty(), "extern block should be flagged");
    }

    // --- P043: include macros ---

    #[test]
    fn test_include_bytes_flagged() {
        let findings = parse_rs(
            r#"
const DATA: &[u8] = include_bytes!("payload.bin");
"#,
        );
        let p043: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P043")
            .collect();
        assert!(!p043.is_empty(), "include_bytes! should be flagged");
    }

    #[test]
    fn test_include_str_flagged() {
        let findings = parse_rs(
            r#"
const SQL: &str = include_str!("setup.sql");
"#,
        );
        let p043: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P043")
            .collect();
        assert!(!p043.is_empty(), "include_str! should be flagged");
    }

    // --- Extraction ---

    #[test]
    fn test_extract_uses() {
        let mut parser = new_parser();
        let uses = extract_uses(
            &mut parser,
            r#"
use serde::Serialize;
use std::collections::HashMap;
use crate::config;
"#,
        );
        assert!(uses.contains(&"serde".to_string()));
        assert!(uses.contains(&"std".to_string()));
        assert!(!uses.contains(&"crate".to_string()));
    }

    #[test]
    fn test_extract_assignments() {
        let mut parser = new_parser();
        // gitleaks:allow — test fixture, not a real secret
        let assignments = extract_assignments(
            &mut parser,
            r#"
const API_KEY: &str = "sk-1234567890abcdefghij";
const VERSION: &str = "1.0";
"#,
        );
        // VERSION too short
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0, "API_KEY");
    }
}
