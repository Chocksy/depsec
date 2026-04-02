use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::checks::{Confidence, Severity};

use super::AstFinding;

/// Initialize a Ruby tree-sitter parser
pub fn new_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .expect("failed to set Ruby language");
    parser
}

/// Analyze Ruby source for security patterns
pub fn analyze(parser: &mut Parser, source: &str) -> Vec<AstFinding> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut findings = Vec::new();

    // P030: eval / instance_eval / class_eval / module_eval
    find_dynamic_eval(&tree, source_bytes, &mut findings);

    // P031: system / backticks / %x / IO.popen / exec
    find_shell_execution(&tree, source_bytes, &mut findings);

    // P032: send / public_send with variable args
    find_dynamic_dispatch(&tree, source_bytes, &mut findings);

    // P033: require with variable/interpolated args
    find_dynamic_require(&tree, source_bytes, &mut findings);

    // P034: open("|cmd") pipe execution
    find_pipe_open(&tree, source_bytes, &mut findings);

    findings
}

/// P030: eval / instance_eval / class_eval / module_eval
fn find_dynamic_eval(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Match bare eval(x) calls
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          method: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#match? @fn "^(eval|instance_eval|class_eval|module_eval)$"))
        "#,
    );

    if let Ok(query) = query {
        run_eval_query(&query, tree, source, findings);
    }

    // Also match receiver.instance_eval(x) style
    let method_query = Query::new(
        &tree.language(),
        r#"
        (call
          receiver: (_)
          method: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#match? @fn "^(instance_eval|class_eval|module_eval)$"))
        "#,
    );

    if let Ok(query) = method_query {
        run_eval_query(&query, tree, source, findings);
    }
}

fn run_eval_query(
    query: &Query,
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let fn_idx = query
        .capture_names()
        .iter()
        .position(|n| *n == "fn")
        .unwrap();
    let arg_idx = query
        .capture_names()
        .iter()
        .position(|n| *n == "arg")
        .unwrap();

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source);

    while let Some(m) = matches.next() {
        let fn_cap = m.captures.iter().find(|c| c.index as usize == fn_idx);
        let arg_cap = m.captures.iter().find(|c| c.index as usize == arg_idx);
        let (Some(fn_cap), Some(arg_cap)) = (fn_cap, arg_cap) else {
            continue;
        };

        let fn_name = fn_cap.node.utf8_text(source).unwrap_or("");
        let arg_kind = arg_cap.node.kind();
        let line = fn_cap.node.start_position().row + 1;

        let severity = if arg_kind == "string" {
            Severity::Medium
        } else {
            Severity::High
        };

        findings.push(AstFinding {
            rule_id: "DEPSEC-P030".into(),
            severity,
            confidence: Confidence::High,
            message: format!(
                "{}() with {} argument — dynamic code execution",
                fn_name,
                if arg_kind == "string" {
                    "static string"
                } else {
                    "variable"
                }
            ),
            line,
        });
    }
}

/// P031: system / backticks / %x / IO.popen / Kernel.exec
fn find_shell_execution(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Match bare system() / exec() calls
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          method: (identifier) @fn
          (#match? @fn "^(system|exec)$"))
        "#,
    );

    if let Ok(query) = query {
        let fn_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "fn")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == fn_idx) {
                let fn_name = cap.node.utf8_text(source).unwrap_or("");
                let line = cap.node.start_position().row + 1;

                findings.push(AstFinding {
                    rule_id: "DEPSEC-P031".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: format!("{}() — shell command execution", fn_name),
                    line,
                });
            }
        }
    }

    // Match IO.popen / Kernel.system / Kernel.exec / Open3.capture3
    let method_query = Query::new(
        &tree.language(),
        r#"
        (call
          receiver: (_) @recv
          method: (identifier) @fn
          (#match? @fn "^(system|exec|popen|spawn|capture2|capture2e|capture3)$"))
        "#,
    );

    if let Ok(query) = method_query {
        let fn_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "fn")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == fn_idx) {
                let fn_name = cap.node.utf8_text(source).unwrap_or("");
                let line = cap.node.start_position().row + 1;

                findings.push(AstFinding {
                    rule_id: "DEPSEC-P031".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: format!("{}() — shell command execution", fn_name),
                    line,
                });
            }
        }
    }

    // Match backtick execution: `cmd`
    let subshell_query = Query::new(&tree.language(), r#"(subshell) @shell"#);

    if let Ok(query) = subshell_query {
        let shell_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "shell")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == shell_idx) {
                let line = cap.node.start_position().row + 1;

                findings.push(AstFinding {
                    rule_id: "DEPSEC-P031".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: "Backtick/subshell execution — shell command execution".into(),
                    line,
                });
            }
        }
    }
}

/// P032: send / public_send with variable args (dynamic dispatch)
fn find_dynamic_dispatch(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          receiver: (_)
          method: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#match? @fn "^(send|public_send|__send__)$"))
        "#,
    );

    if let Ok(query) = query {
        let fn_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "fn")
            .unwrap();
        let arg_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "arg")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let fn_cap = m.captures.iter().find(|c| c.index as usize == fn_idx);
            let arg_cap = m.captures.iter().find(|c| c.index as usize == arg_idx);
            let (Some(fn_cap), Some(arg_cap)) = (fn_cap, arg_cap) else {
                continue;
            };

            let fn_name = fn_cap.node.utf8_text(source).unwrap_or("");
            let arg_kind = arg_cap.node.kind();
            let line = fn_cap.node.start_position().row + 1;

            // Static symbol arg (:method_name) is lower risk
            let severity = if arg_kind == "simple_symbol" {
                Severity::Low
            } else {
                Severity::High
            };

            findings.push(AstFinding {
                rule_id: "DEPSEC-P032".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "{}() with {} argument — dynamic method dispatch",
                    fn_name,
                    if arg_kind == "simple_symbol" {
                        "static symbol"
                    } else {
                        "variable"
                    }
                ),
                line,
            });
        }
    }
}

/// P033: require with variable/interpolated args (dynamic module loading)
fn find_dynamic_require(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          method: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#match? @fn "^(require|require_relative|load)$"))
        "#,
    );

    if let Ok(query) = query {
        let fn_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "fn")
            .unwrap();
        let arg_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "arg")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let fn_cap = m.captures.iter().find(|c| c.index as usize == fn_idx);
            let arg_cap = m.captures.iter().find(|c| c.index as usize == arg_idx);
            let (Some(fn_cap), Some(arg_cap)) = (fn_cap, arg_cap) else {
                continue;
            };

            let fn_name = fn_cap.node.utf8_text(source).unwrap_or("");
            let arg_kind = arg_cap.node.kind();
            let line = fn_cap.node.start_position().row + 1;

            // Only flag non-string-literal requires (dynamic loading)
            if arg_kind != "string" {
                findings.push(AstFinding {
                    rule_id: "DEPSEC-P033".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: format!(
                        "{}() with variable argument — dynamic module loading",
                        fn_name
                    ),
                    line,
                });
            }
        }
    }
}

/// P034: open("|cmd") — pipe execution via Ruby's Kernel#open
fn find_pipe_open(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Ruby's open("|cmd") spawns a shell. We match open() calls where the
    // first string argument starts with "|".
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          method: (identifier) @fn
          arguments: (argument_list
            (string (string_content) @arg))
          (#eq? @fn "open"))
        "#,
    );

    if let Ok(query) = query {
        let arg_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "arg")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(arg_cap) = m.captures.iter().find(|c| c.index as usize == arg_idx) {
                let arg_text = arg_cap.node.utf8_text(source).unwrap_or("");
                if arg_text.starts_with('|') {
                    let line = arg_cap.node.start_position().row + 1;
                    findings.push(AstFinding {
                        rule_id: "DEPSEC-P034".into(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        message: format!(
                            "open(\"|\") — pipe execution via Kernel#open: {}",
                            &arg_text[..arg_text.len().min(50)]
                        ),
                        line,
                    });
                }
            }
        }
    }
}

/// Extract Ruby require/require_relative for reachability analysis.
/// Returns a list of required gem/module names.
pub fn extract_requires(parser: &mut Parser, source: &str) -> Vec<String> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut requires = Vec::new();

    let query = Query::new(
        &tree.language(),
        r#"
        (call
          method: (identifier) @fn
          arguments: (argument_list (string (string_content) @module))
          (#match? @fn "^(require|require_relative)$"))
        "#,
    );

    if let Ok(query) = query {
        let module_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "module")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == module_idx) {
                if let Ok(name) = cap.node.utf8_text(source_bytes) {
                    // Take top-level module (before first /)
                    let top = name.split('/').next().unwrap_or(name);
                    // Skip relative requires
                    if !top.starts_with('.') {
                        requires.push(top.to_string());
                    }
                }
            }
        }
    }

    requires.sort();
    requires.dedup();
    requires
}

/// Extract Ruby constant assignments for secret detection.
/// Returns (name, value, line) tuples.
pub fn extract_assignments(parser: &mut Parser, source: &str) -> Vec<(String, String, usize)> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut results = Vec::new();

    // Match: CONSTANT = "value"
    let query = Query::new(
        &tree.language(),
        r#"
        (assignment
          left: (constant) @name
          right: (string (string_content) @value))
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

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rb(source: &str) -> Vec<AstFinding> {
        let mut parser = new_parser();
        analyze(&mut parser, source)
    }

    // --- P030: eval ---

    #[test]
    fn test_eval_variable_flagged() {
        let findings = parse_rb("eval(user_input)");
        let p030: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P030")
            .collect();
        assert!(!p030.is_empty(), "eval with variable should be flagged");
        assert_eq!(p030[0].severity, Severity::High);
    }

    #[test]
    fn test_eval_static_string_medium() {
        let findings = parse_rb(r#"eval("1 + 2")"#);
        let p030: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P030")
            .collect();
        assert!(!p030.is_empty(), "eval with string should be flagged");
        assert_eq!(p030[0].severity, Severity::Medium);
    }

    #[test]
    fn test_instance_eval_flagged() {
        let findings = parse_rb("obj.instance_eval(code)");
        let p030: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P030")
            .collect();
        assert!(!p030.is_empty(), "instance_eval should be flagged");
    }

    // --- P031: shell execution ---

    #[test]
    fn test_system_flagged() {
        let findings = parse_rb(r#"system("rm -rf /")"#);
        let p031: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P031")
            .collect();
        assert!(!p031.is_empty(), "system() should be flagged");
    }

    #[test]
    fn test_backtick_flagged() {
        let findings = parse_rb("`ls -la`");
        let p031: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P031")
            .collect();
        assert!(!p031.is_empty(), "backtick execution should be flagged");
    }

    #[test]
    fn test_io_popen_flagged() {
        let findings = parse_rb(r#"IO.popen("cmd")"#);
        let p031: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P031")
            .collect();
        assert!(!p031.is_empty(), "IO.popen should be flagged");
    }

    // --- P032: dynamic dispatch ---

    #[test]
    fn test_send_variable_flagged() {
        let findings = parse_rb("obj.send(method_name, arg1)");
        let p032: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P032")
            .collect();
        assert!(!p032.is_empty(), "send with variable should be flagged");
        assert_eq!(p032[0].severity, Severity::High);
    }

    #[test]
    fn test_send_symbol_low() {
        let findings = parse_rb("obj.send(:valid_method)");
        let p032: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P032")
            .collect();
        assert!(!p032.is_empty(), "send with symbol should be flagged");
        assert_eq!(p032[0].severity, Severity::Low);
    }

    // --- P033: dynamic require ---

    #[test]
    fn test_require_variable_flagged() {
        let findings = parse_rb("require(plugin_name)");
        let p033: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P033")
            .collect();
        assert!(!p033.is_empty(), "require with variable should be flagged");
    }

    #[test]
    fn test_require_string_not_flagged() {
        let findings = parse_rb(r#"require("json")"#);
        let p033: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P033")
            .collect();
        assert!(
            p033.is_empty(),
            "require with string literal should NOT be flagged"
        );
    }

    // --- Extraction ---

    #[test]
    fn test_extract_requires() {
        let mut parser = new_parser();
        let requires = extract_requires(
            &mut parser,
            r#"
require "json"
require "active_support/core_ext"
require_relative "./helper"
"#,
        );
        assert!(requires.contains(&"json".to_string()));
        assert!(requires.contains(&"active_support".to_string()));
        assert!(!requires.iter().any(|r| r.starts_with('.')));
    }

    #[test]
    fn test_extract_assignments() {
        let mut parser = new_parser();
        // gitleaks:allow — test fixture, not a real secret
        let assignments = extract_assignments(
            &mut parser,
            r#"
API_KEY = "sk-1234567890abcdefghijklmn"
VERSION = "1.0"
"#,
        );
        // VERSION too short (< 8 chars)
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0, "API_KEY");
    }
}
