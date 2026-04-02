use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::checks::{Confidence, Severity};

use super::AstFinding;

/// Initialize a Python tree-sitter parser
pub fn new_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to set Python language");
    parser
}

/// Analyze Python source for security patterns
pub fn analyze(parser: &mut Parser, source: &str) -> Vec<AstFinding> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut findings = Vec::new();

    // P020: eval() / exec() with arguments
    find_dangerous_builtins(&tree, source_bytes, &mut findings);

    // P021: subprocess with shell=True
    find_subprocess_shell(&tree, source_bytes, &mut findings);

    // P022: os.system() calls
    find_os_system(&tree, source_bytes, &mut findings);

    // P023: __import__() dynamic imports
    find_dynamic_import(&tree, source_bytes, &mut findings);

    // P024: pickle deserialization (arbitrary code execution)
    find_pickle_deserialize(&tree, source_bytes, &mut findings);

    findings
}

/// Extract variable assignments with string literal values for secret detection.
/// Returns (name, value, line) tuples.
pub fn extract_assignments(parser: &mut Parser, source: &str) -> Vec<(String, String, usize)> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut results = Vec::new();

    // Match: NAME = "value" or NAME = 'value'
    let query = Query::new(
        &tree.language(),
        r#"
        (assignment
          left: (identifier) @name
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

            // Only consider UPPER_CASE names (likely constants/config)
            if name.chars().all(|c| c.is_ascii_uppercase() || c == '_') && value.len() >= 8 {
                results.push((name.to_string(), value.to_string(), line));
            }
        }
    }

    // Also match dict-style assignments: config["KEY"] = "value"
    let dict_query = Query::new(
        &tree.language(),
        r#"
        (assignment
          left: (subscript
            value: (_)
            subscript: (string (string_content) @key))
          right: (string (string_content) @value))
        "#,
    );

    if let Ok(query) = dict_query {
        let key_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "key")
            .unwrap();
        let value_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "value")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

        while let Some(m) = matches.next() {
            let key_cap = m.captures.iter().find(|c| c.index as usize == key_idx);
            let value_cap = m.captures.iter().find(|c| c.index as usize == value_idx);
            let (Some(key_cap), Some(value_cap)) = (key_cap, value_cap) else {
                continue;
            };

            let key = key_cap.node.utf8_text(source_bytes).unwrap_or("");
            let value = value_cap.node.utf8_text(source_bytes).unwrap_or("");
            let line = key_cap.node.start_position().row + 1;

            if value.len() >= 8 {
                results.push((key.to_string(), value.to_string(), line));
            }
        }
    }

    results
}

/// P020: eval() / exec() with arguments
fn find_dangerous_builtins(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          function: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#match? @fn "^(eval|exec|compile)$"))
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

            let severity = if arg_kind == "string" {
                Severity::Medium // Static string eval
            } else {
                Severity::High // Variable/expression eval
            };

            findings.push(AstFinding {
                rule_id: "DEPSEC-P020".into(),
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
}

/// P021: subprocess with shell=True
fn find_subprocess_shell(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Match subprocess.Popen/call/run/check_output with shell=True
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @kwarg
              value: (true) @val))
          (#eq? @obj "subprocess")
          (#eq? @kwarg "shell"))
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
            let method_cap = m.captures.iter().find(|c| c.index as usize == method_idx);
            let Some(method_cap) = method_cap else {
                continue;
            };

            let method_name = method_cap.node.utf8_text(source).unwrap_or("");
            let line = method_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P021".into(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "subprocess.{method_name}() with shell=True — command injection risk"
                ),
                line,
            });
        }
    }
}

/// P022: os.system() calls
fn find_os_system(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
          (#eq? @obj "os")
          (#match? @method "^(system|popen)$"))
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
            let method_cap = m.captures.iter().find(|c| c.index as usize == method_idx);
            let Some(method_cap) = method_cap else {
                continue;
            };

            let method_name = method_cap.node.utf8_text(source).unwrap_or("");
            let line = method_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P022".into(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!("os.{method_name}() — shell command execution"),
                line,
            });
        }
    }
}

/// P023: __import__() dynamic imports
fn find_dynamic_import(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          function: (identifier) @fn
          arguments: (argument_list (_) @arg)
          (#eq? @fn "__import__"))
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

            let arg_kind = arg_cap.node.kind();
            let line = fn_cap.node.start_position().row + 1;

            let severity = if arg_kind == "string" {
                Severity::Medium // __import__("os") — suspicious but static
            } else {
                Severity::Critical // __import__(var) — dynamic, very suspicious
            };

            findings.push(AstFinding {
                rule_id: "DEPSEC-P023".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "__import__() with {} argument — dynamic module loading",
                    if arg_kind == "string" {
                        "static"
                    } else {
                        "variable"
                    }
                ),
                line,
            });
        }
    }
}

/// P024: pickle.loads / pickle.load / pickle.Unpickler — arbitrary code execution via deserialization
fn find_pickle_deserialize(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
          (#eq? @obj "pickle")
          (#match? @method "^(loads|load|Unpickler)$"))
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
            if let Some(method_cap) = m.captures.iter().find(|c| c.index as usize == method_idx) {
                let method_name = method_cap.node.utf8_text(source).unwrap_or("");
                let line = method_cap.node.start_position().row + 1;

                findings.push(AstFinding {
                    rule_id: "DEPSEC-P024".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    message: format!(
                        "pickle.{method_name}() — arbitrary code execution via deserialization"
                    ),
                    line,
                });
            }
        }
    }
}

/// Extract Python imports for reachability analysis.
/// Returns a list of imported module names.
pub fn extract_imports(parser: &mut Parser, source: &str) -> Vec<String> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut imports = Vec::new();

    // import X, import X.Y
    let import_query = Query::new(
        &tree.language(),
        r#"
        (import_statement
          name: (dotted_name) @module)
        "#,
    );

    if let Ok(query) = import_query {
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
                    // Take only the top-level module name (before first dot)
                    let top = name.split('.').next().unwrap_or(name);
                    imports.push(top.to_string());
                }
            }
        }
    }

    // from X import Y
    let from_query = Query::new(
        &tree.language(),
        r#"
        (import_from_statement
          module_name: (dotted_name) @module)
        "#,
    );

    if let Ok(query) = from_query {
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
                    let top = name.split('.').next().unwrap_or(name);
                    imports.push(top.to_string());
                }
            }
        }
    }

    imports.sort();
    imports.dedup();
    imports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_py(source: &str) -> Vec<AstFinding> {
        let mut parser = new_parser();
        analyze(&mut parser, source)
    }

    // --- P020: eval/exec ---

    #[test]
    fn test_eval_variable_flagged() {
        let findings = parse_py("result = eval(user_input)");
        let p020: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P020")
            .collect();
        assert_eq!(p020.len(), 1);
        assert_eq!(p020[0].severity, Severity::High);
    }

    #[test]
    fn test_exec_variable_flagged() {
        let findings = parse_py("exec(code_string)");
        let p020: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P020")
            .collect();
        assert_eq!(p020.len(), 1);
    }

    #[test]
    fn test_eval_static_string_medium() {
        let findings = parse_py(r#"result = eval("1 + 2")"#);
        let p020: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P020")
            .collect();
        assert_eq!(p020.len(), 1);
        assert_eq!(p020[0].severity, Severity::Medium);
    }

    // --- P021: subprocess shell=True ---

    #[test]
    fn test_subprocess_shell_true() {
        let findings = parse_py(r#"subprocess.Popen(cmd, shell=True)"#);
        let p021: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P021")
            .collect();
        assert_eq!(p021.len(), 1);
    }

    #[test]
    fn test_subprocess_call_shell_true() {
        let findings = parse_py(r#"subprocess.call(cmd, shell=True)"#);
        let p021: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P021")
            .collect();
        assert_eq!(p021.len(), 1);
    }

    // --- P022: os.system ---

    #[test]
    fn test_os_system_flagged() {
        let findings = parse_py(r#"os.system("rm -rf /")"#);
        let p022: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P022")
            .collect();
        assert_eq!(p022.len(), 1);
    }

    #[test]
    fn test_os_popen_flagged() {
        let findings = parse_py(r#"os.popen(cmd)"#);
        let p022: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P022")
            .collect();
        assert_eq!(p022.len(), 1);
    }

    // --- P023: __import__ ---

    #[test]
    fn test_dynamic_import_variable() {
        let findings = parse_py("mod = __import__(module_name)");
        let p023: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P023")
            .collect();
        assert_eq!(p023.len(), 1);
        assert_eq!(p023[0].severity, Severity::Critical);
    }

    #[test]
    fn test_static_import_medium() {
        let findings = parse_py(r#"mod = __import__("os")"#);
        let p023: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P023")
            .collect();
        assert_eq!(p023.len(), 1);
        assert_eq!(p023[0].severity, Severity::Medium);
    }

    // --- Assignment extraction ---

    #[test]
    fn test_extract_simple_assignment() {
        let mut parser = new_parser();
        let results = extract_assignments(
            &mut parser,
            r#"DATABASE_HOST = "postgres-main-replica-east.internal.example.com""#,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "DATABASE_HOST");
        assert_eq!(
            results[0].1,
            "postgres-main-replica-east.internal.example.com"
        );
    }

    #[test]
    fn test_extract_ignores_short_values() {
        let mut parser = new_parser();
        let results = extract_assignments(&mut parser, r#"X = "short""#);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_ignores_lowercase_names() {
        let mut parser = new_parser();
        let results = extract_assignments(&mut parser, r#"my_var = "this_is_not_a_constant_name""#);
        assert!(results.is_empty());
    }

    // --- Import extraction ---

    #[test]
    fn test_extract_import() {
        let mut parser = new_parser();
        let imports = extract_imports(&mut parser, "import os\nimport sys");
        assert!(imports.contains(&"os".to_string()));
        assert!(imports.contains(&"sys".to_string()));
    }

    #[test]
    fn test_extract_from_import() {
        let mut parser = new_parser();
        let imports = extract_imports(&mut parser, "from os.path import join");
        assert!(imports.contains(&"os".to_string()));
    }
}
