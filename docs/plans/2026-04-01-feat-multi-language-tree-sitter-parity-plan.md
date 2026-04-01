# Multi-Language Tree-Sitter Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring Ruby and Rust to full parity with JS/TS and Python across all tree-sitter-powered features: AST security analysis, secrets detection, reachability/import scanning, and preflight typosquat checking.

**Architecture:** Feature-at-a-time (Layer A → D). Each layer adds one capability across all languages before moving to the next. Two new tree-sitter grammar crates (`tree-sitter-ruby 0.23`, `tree-sitter-rust 0.24`) added upfront; all analyzers follow the existing `analyze() → Vec<AstFinding>` pattern established in `python.rs` and `javascript.rs`.

**Tech Stack:** Rust, tree-sitter 0.24, tree-sitter-ruby 0.23.1, tree-sitter-rust 0.24.2

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `Cargo.toml` | Modify | Add tree-sitter-ruby, tree-sitter-rust deps |
| `src/ast/ruby.rs` | Create | Ruby AST security rules P030-P033 |
| `src/ast/rust_lang.rs` | Create | Rust AST security rules P040-P043 |
| `src/ast/mod.rs` | Modify | Add Ruby/Rust to Lang enum, wire analyzers |
| `src/output.rs` | Modify | Add rule metadata for P030-P043 |
| `src/secrets_ast.rs` | Modify | Add Ruby secrets, upgrade Rust to tree-sitter |
| `src/reachability.rs` | Modify | Add Python/Ruby/Rust import scanning |
| `src/preflight.rs` | Modify | Add RubyGems top packages + wire into typosquat |

> Note: The Rust AST file is named `rust_lang.rs` (not `rust.rs`) to avoid conflict with the `rust` keyword.

---

## Layer A: AST Security Rules

### Task 1: Add tree-sitter dependencies

**Files:**
- Modify: `Cargo.toml:25-28`

- [ ] **Step 1: Add the two new grammar crates**

```toml
tree-sitter = "0.24"
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.23"
tree-sitter-ruby = "0.23"
tree-sitter-rust = "0.24"
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check`
Expected: compiles with no errors (warnings OK)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat: add tree-sitter-ruby and tree-sitter-rust dependencies"
```

---

### Task 2: Create Ruby AST security analyzer

**Files:**
- Create: `src/ast/ruby.rs`

This mirrors `src/ast/python.rs` exactly. Four rules:
- **P030**: `eval` / `instance_eval` / `class_eval` / `module_eval` — dynamic code execution
- **P031**: `system()` / `` ` `` backticks / `%x{}` / `IO.popen` / `Kernel.exec` — shell execution
- **P032**: `send()` / `public_send()` with variable args — dynamic dispatch
- **P033**: `require` with variable/interpolated args — dynamic module loading

- [ ] **Step 1: Write the test file structure and first test**

Create `src/ast/ruby.rs` with the module structure, parser init, and first test for P030:

```rust
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

    findings
}

/// P030: eval / instance_eval / class_eval / module_eval
fn find_dynamic_eval(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
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
                    if arg_kind == "string" { "static string" } else { "variable" }
                ),
                line,
            });
        }
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
                    if arg_kind == "string" { "static string" } else { "variable" }
                ),
                line,
            });
        }
    }
}

/// P031: system / backticks / %x / IO.popen / Kernel.exec
fn find_shell_execution(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
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

    // Match IO.popen / Kernel.system / Kernel.exec
    let method_query = Query::new(
        &tree.language(),
        r#"
        (call
          receiver: [(constant) (scope_resolution)]
          method: (identifier) @fn
          (#match? @fn "^(system|exec|popen|spawn)$"))
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

    // Match backtick execution: `cmd` and %x{cmd}
    let subshell_query = Query::new(
        &tree.language(),
        r#"(subshell) @shell"#,
    );

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
fn find_dynamic_dispatch(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    // Match obj.send(x) / obj.public_send(x)
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
                    if arg_kind == "simple_symbol" { "static symbol" } else { "variable" }
                ),
                line,
            });
        }
    }
}

/// P033: require with variable/interpolated args (dynamic module loading)
fn find_dynamic_require(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    // Match require(x) where x is NOT a string literal
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

/// Extract Ruby assignments for secret detection.
/// Returns (name, value, line) tuples for UPPER_CASE constant assignments.
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
        let p030: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P030").collect();
        assert!(!p030.is_empty(), "eval with variable should be flagged");
        assert_eq!(p030[0].severity, Severity::High);
    }

    #[test]
    fn test_eval_static_string_medium() {
        let findings = parse_rb(r#"eval("1 + 2")"#);
        let p030: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P030").collect();
        assert!(!p030.is_empty(), "eval with string should be flagged");
        assert_eq!(p030[0].severity, Severity::Medium);
    }

    #[test]
    fn test_instance_eval_flagged() {
        let findings = parse_rb("obj.instance_eval(code)");
        let p030: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P030").collect();
        assert!(!p030.is_empty(), "instance_eval should be flagged");
    }

    // --- P031: shell execution ---

    #[test]
    fn test_system_flagged() {
        let findings = parse_rb(r#"system("rm -rf /")"#);
        let p031: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P031").collect();
        assert!(!p031.is_empty(), "system() should be flagged");
    }

    #[test]
    fn test_backtick_flagged() {
        let findings = parse_rb("`ls -la`");
        let p031: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P031").collect();
        assert!(!p031.is_empty(), "backtick execution should be flagged");
    }

    // --- P032: dynamic dispatch ---

    #[test]
    fn test_send_variable_flagged() {
        let findings = parse_rb("obj.send(method_name, arg1)");
        let p032: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P032").collect();
        assert!(!p032.is_empty(), "send with variable should be flagged");
        assert_eq!(p032[0].severity, Severity::High);
    }

    #[test]
    fn test_send_symbol_low() {
        let findings = parse_rb("obj.send(:valid_method)");
        let p032: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P032").collect();
        assert!(!p032.is_empty(), "send with symbol should be flagged");
        assert_eq!(p032[0].severity, Severity::Low);
    }

    // --- P033: dynamic require ---

    #[test]
    fn test_require_variable_flagged() {
        let findings = parse_rb("require(plugin_name)");
        let p033: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P033").collect();
        assert!(!p033.is_empty(), "require with variable should be flagged");
    }

    #[test]
    fn test_require_string_not_flagged() {
        let findings = parse_rb(r#"require("json")"#);
        let p033: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P033").collect();
        assert!(p033.is_empty(), "require with string literal should NOT be flagged");
    }

    // --- Extraction ---

    #[test]
    fn test_extract_requires() {
        let mut parser = new_parser();
        let requires = extract_requires(&mut parser, r#"
require "json"
require "active_support/core_ext"
require_relative "./helper"
"#);
        assert!(requires.contains(&"json".to_string()));
        assert!(requires.contains(&"active_support".to_string()));
        assert!(!requires.iter().any(|r| r.starts_with('.')));
    }

    #[test]
    fn test_extract_assignments() {
        let mut parser = new_parser();
        let assignments = extract_assignments(&mut parser, r#"
API_KEY = "sk-1234567890abcdefghijklmn"
VERSION = "1.0"
"#);
        assert_eq!(assignments.len(), 1); // VERSION too short
        assert_eq!(assignments[0].0, "API_KEY");
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test ast::ruby -- --nocapture`
Expected: All tests pass. If any tree-sitter query fails to compile, check the grammar's node types using `tree-sitter parse` on a sample Ruby file and adjust the query accordingly.

> **Note on tree-sitter query debugging:** If a query fails, the node type names might differ. Common Ruby grammar differences:
> - `call` vs `method_call` — try both
> - `subshell` for backticks — verify with `tree-sitter parse`
> - `string_content` vs `string_fragment` — Ruby uses `string_content`
> - Constants in Ruby are `constant` nodes (capitalized identifiers)

- [ ] **Step 3: Commit**

```bash
git add src/ast/ruby.rs
git commit -m "feat: add Ruby AST security analyzer (P030-P033)"
```

---

### Task 3: Create Rust AST security analyzer

**Files:**
- Create: `src/ast/rust_lang.rs`

Four rules:
- **P040**: `Command::new()` / `process::Command` — process execution
- **P041**: `unsafe` blocks — memory safety bypass
- **P042**: `extern "C"` / FFI declarations — foreign function interface
- **P043**: `include_bytes!` / `include_str!` — compile-time file inclusion

- [ ] **Step 1: Create the analyzer**

```rust
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
fn find_command_execution(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    // Match Command::new("...") calls
    let query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (scoped_identifier
            name: (identifier) @method)
          arguments: (arguments (_) @arg)
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
                // Check if the scoped path contains "Command"
                let parent = cap.node.parent().unwrap();
                let full_path = parent.utf8_text(source).unwrap_or("");
                if full_path.contains("Command") {
                    let line = cap.node.start_position().row + 1;
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

/// P041: unsafe blocks
fn find_unsafe_blocks(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let query = Query::new(
        &tree.language(),
        r#"(unsafe_block) @unsafe"#,
    );

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
fn find_ffi_declarations(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    let query = Query::new(
        &tree.language(),
        r#"(extern_block) @ffi"#,
    );

    if let Ok(query) = query {
        let idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "ffi")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

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
                    message: format!(
                        "{}!() — embeds file contents at compile time",
                        macro_name
                    ),
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

    // Match: use crate_name::...
    let query = Query::new(
        &tree.language(),
        r#"
        (use_declaration
          argument: (scoped_identifier
            path: (identifier) @crate_name))
        "#,
    );

    if let Ok(query) = query {
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
                    // Skip self, crate, super references
                    if name != "self" && name != "crate" && name != "super" {
                        crates.push(name.to_string());
                    }
                }
            }
        }
    }

    // Match: use simple_identifier; (e.g., use serde;)
    let simple_query = Query::new(
        &tree.language(),
        r#"
        (use_declaration
          argument: (identifier) @crate_name)
        "#,
    );

    if let Ok(query) = simple_query {
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
                    if name != "self" && name != "crate" && name != "super" {
                        crates.push(name.to_string());
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

    // Match: const NAME: type = "value"; and static NAME: type = "value";
    let query = Query::new(
        &tree.language(),
        r#"
        [
          (const_item
            name: (identifier) @name
            value: (string_literal (string_content) @value))
          (static_item
            name: (identifier) @name
            value: (string_literal (string_content) @value))
        ]
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

    fn parse_rs(source: &str) -> Vec<AstFinding> {
        let mut parser = new_parser();
        analyze(&mut parser, source)
    }

    // --- P040: Command execution ---

    #[test]
    fn test_command_new_flagged() {
        let findings = parse_rs(r#"
fn run() {
    std::process::Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}
"#);
        let p040: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P040").collect();
        assert!(!p040.is_empty(), "Command::new should be flagged");
    }

    // --- P041: unsafe ---

    #[test]
    fn test_unsafe_block_flagged() {
        let findings = parse_rs(r#"
fn danger() {
    unsafe { std::ptr::read(addr) };
}
"#);
        let p041: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P041").collect();
        assert!(!p041.is_empty(), "unsafe block should be flagged");
        assert_eq!(p041[0].severity, Severity::Medium);
    }

    // --- P042: FFI ---

    #[test]
    fn test_extern_block_flagged() {
        let findings = parse_rs(r#"
extern "C" {
    fn evil_function(ptr: *mut u8);
}
"#);
        let p042: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P042").collect();
        assert!(!p042.is_empty(), "extern block should be flagged");
    }

    // --- P043: include macros ---

    #[test]
    fn test_include_bytes_flagged() {
        let findings = parse_rs(r#"
const DATA: &[u8] = include_bytes!("payload.bin");
"#);
        let p043: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P043").collect();
        assert!(!p043.is_empty(), "include_bytes! should be flagged");
    }

    #[test]
    fn test_include_str_flagged() {
        let findings = parse_rs(r#"
const SQL: &str = include_str!("setup.sql");
"#);
        let p043: Vec<_> = findings.iter().filter(|f| f.rule_id == "DEPSEC-P043").collect();
        assert!(!p043.is_empty(), "include_str! should be flagged");
    }

    // --- Extraction ---

    #[test]
    fn test_extract_uses() {
        let mut parser = new_parser();
        let uses = extract_uses(&mut parser, r#"
use serde::Serialize;
use std::collections::HashMap;
use crate::config;
"#);
        assert!(uses.contains(&"serde".to_string()));
        assert!(uses.contains(&"std".to_string()));
        assert!(!uses.contains(&"crate".to_string()));
    }

    #[test]
    fn test_extract_assignments() {
        let mut parser = new_parser();
        let assignments = extract_assignments(&mut parser, r#"
const API_KEY: &str = "sk-1234567890abcdefghij";
const VERSION: &str = "1.0";
"#);
        assert_eq!(assignments.len(), 1); // VERSION too short
        assert_eq!(assignments[0].0, "API_KEY");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test ast::rust_lang -- --nocapture`
Expected: All tests pass. Same tree-sitter query debugging notes as Task 2 apply.

> **Note on Rust grammar node types:** The tree-sitter-rust grammar uses:
> - `unsafe_block` for unsafe { ... }
> - `extern_block` or `foreign_mod` for extern "C" { ... } — check which
> - `macro_invocation` for macro calls
> - `call_expression` with `scoped_identifier` for `Foo::bar()` calls
> - `const_item` and `static_item` for constant declarations
> - `use_declaration` for use statements

- [ ] **Step 3: Commit**

```bash
git add src/ast/rust_lang.rs
git commit -m "feat: add Rust AST security analyzer (P040-P043)"
```

---

### Task 4: Wire Ruby and Rust into AST mod.rs

**Files:**
- Modify: `src/ast/mod.rs`

- [ ] **Step 1: Add module declarations and update Lang enum**

Add `pub mod ruby;` and `pub mod rust_lang;` at the top. Add `Ruby` and `Rust` variants to `Lang`. Add parsers to `AstAnalyzer`. Update `detect_language` and `analyze`.

The complete updated `src/ast/mod.rs`:

```rust
pub mod javascript;
pub mod python;
pub mod ruby;
pub mod rust_lang;

use std::path::Path;

use tree_sitter::Parser;

use crate::checks::{Confidence, Severity};

/// Languages we can parse with tree-sitter
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Lang {
    JavaScript,
    TypeScript,
    Python,
    Ruby,
    Rust,
}

/// A finding produced by AST analysis — higher confidence than regex
pub struct AstFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub line: usize, // 1-indexed
}

pub struct AstAnalyzer {
    js_parser: Parser,
    ts_parser: Parser,
    py_parser: Parser,
    rb_parser: Parser,
    rs_parser: Parser,
}

impl AstAnalyzer {
    pub fn new() -> Self {
        let mut js_parser = Parser::new();
        js_parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("failed to set JS language");

        let mut ts_parser = Parser::new();
        ts_parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to set TS language");

        let py_parser = python::new_parser();
        let rb_parser = ruby::new_parser();
        let rs_parser = rust_lang::new_parser();

        Self {
            js_parser,
            ts_parser,
            py_parser,
            rb_parser,
            rs_parser,
        }
    }

    /// Analyze a file for security patterns using AST.
    pub fn analyze(&mut self, path: &Path, source: &str) -> Vec<AstFinding> {
        match detect_language(path) {
            Some(Lang::JavaScript) => javascript::analyze(&mut self.js_parser, source),
            Some(Lang::TypeScript) => javascript::analyze(&mut self.ts_parser, source),
            Some(Lang::Python) => python::analyze(&mut self.py_parser, source),
            Some(Lang::Ruby) => ruby::analyze(&mut self.rb_parser, source),
            Some(Lang::Rust) => rust_lang::analyze(&mut self.rs_parser, source),
            None => vec![],
        }
    }

    /// Returns true if this file can be analyzed by the AST engine
    pub fn can_analyze(path: &Path) -> bool {
        detect_language(path).is_some()
    }
}

fn detect_language(path: &Path) -> Option<Lang> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    match ext {
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::JavaScript),
        "ts" | "mts" | "cts" | "tsx" => Some(Lang::TypeScript),
        "py" | "pyw" => Some(Lang::Python),
        "rb" | "rake" | "gemspec" => Some(Lang::Ruby),
        "rs" => Some(Lang::Rust),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language_js() {
        assert_eq!(detect_language(Path::new("file.js")), Some(Lang::JavaScript));
        assert_eq!(detect_language(Path::new("file.mjs")), Some(Lang::JavaScript));
        assert_eq!(detect_language(Path::new("file.cjs")), Some(Lang::JavaScript));
        assert_eq!(detect_language(Path::new("file.jsx")), Some(Lang::JavaScript));
    }

    #[test]
    fn test_detect_language_ts() {
        assert_eq!(detect_language(Path::new("file.ts")), Some(Lang::TypeScript));
        assert_eq!(detect_language(Path::new("file.tsx")), Some(Lang::TypeScript));
        assert_eq!(detect_language(Path::new("file.mts")), Some(Lang::TypeScript));
    }

    #[test]
    fn test_detect_language_python() {
        assert_eq!(detect_language(Path::new("file.py")), Some(Lang::Python));
        assert_eq!(detect_language(Path::new("file.pyw")), Some(Lang::Python));
    }

    #[test]
    fn test_detect_language_ruby() {
        assert_eq!(detect_language(Path::new("file.rb")), Some(Lang::Ruby));
        assert_eq!(detect_language(Path::new("file.rake")), Some(Lang::Ruby));
        assert_eq!(detect_language(Path::new("file.gemspec")), Some(Lang::Ruby));
    }

    #[test]
    fn test_detect_language_rust() {
        assert_eq!(detect_language(Path::new("file.rs")), Some(Lang::Rust));
    }

    #[test]
    fn test_detect_language_unknown() {
        assert_eq!(detect_language(Path::new("file.go")), None);
        assert_eq!(detect_language(Path::new("file")), None);
    }

    #[test]
    fn test_ast_analyzer_new() {
        let _analyzer = AstAnalyzer::new();
    }
}
```

- [ ] **Step 2: Run all AST tests**

Run: `cargo test ast:: -- --nocapture`
Expected: All tests pass (JS, Python, Ruby, Rust)

- [ ] **Step 3: Commit**

```bash
git add src/ast/mod.rs
git commit -m "feat: wire Ruby and Rust into AST analyzer pipeline"
```

---

### Task 5: Add rule metadata to output.rs

**Files:**
- Modify: `src/output.rs:14-37`

- [ ] **Step 1: Add P030-P043 entries to `rule_info()`**

Add after the P023 entry:

```rust
        // Ruby rules
        "DEPSEC-P030" => RuleInfo { name: "Ruby Dynamic Execution", narrative: "Calls eval(), instance_eval(), class_eval(), or module_eval() in Ruby. These execute arbitrary code strings at runtime. Common in metaprogramming but dangerous if input is user-controlled." },
        "DEPSEC-P031" => RuleInfo { name: "Ruby Shell Execution", narrative: "Executes shell commands via system(), backticks, %x{}, IO.popen, or Kernel.exec. These invoke a system shell and are vulnerable to command injection if arguments include user input." },
        "DEPSEC-P032" => RuleInfo { name: "Ruby Dynamic Dispatch", narrative: "Uses send() or public_send() to call methods by name at runtime. When the method name comes from user input, this can invoke arbitrary methods including private ones." },
        "DEPSEC-P033" => RuleInfo { name: "Ruby Dynamic Require", narrative: "Calls require() or load() with a variable argument instead of a string literal. This can be used to load attacker-controlled code at runtime." },
        // Rust rules
        "DEPSEC-P040" => RuleInfo { name: "Process Execution", narrative: "Uses std::process::Command to spawn external processes. If command arguments include user input, this enables command injection." },
        "DEPSEC-P041" => RuleInfo { name: "Unsafe Block", narrative: "Contains an unsafe block that bypasses Rust's memory safety guarantees. In dependency code, unsafe blocks are potential sources of memory corruption vulnerabilities." },
        "DEPSEC-P042" => RuleInfo { name: "FFI Declaration", narrative: "Declares foreign function interface (extern) bindings. FFI code operates outside Rust's safety model and can introduce undefined behavior." },
        "DEPSEC-P043" => RuleInfo { name: "Compile-Time File Inclusion", narrative: "Uses include_bytes!() or include_str!() to embed file contents at compile time. In dependency code, this could embed unexpected payloads." },
```

- [ ] **Step 2: Run tests**

Run: `cargo test output:: -- --nocapture`
Expected: existing tests still pass

- [ ] **Step 3: Commit**

```bash
git add src/output.rs
git commit -m "feat: add rule metadata for Ruby (P030-P033) and Rust (P040-P043)"
```

---

## Layer B: Secrets Detection

### Task 6: Add Ruby secrets detection

**Files:**
- Modify: `src/secrets_ast.rs:69-118`

- [ ] **Step 1: Add Ruby file handling in `scan_for_secrets`**

In the file loop (after the Python block at line ~113), add:

```rust
        // Ruby files: scan with tree-sitter AST for constant assignments
        if ext == "rb" {
            scan_ruby_ast(&content, &rel_path, &mut findings);
        }
```

- [ ] **Step 2: Add the `scan_ruby_ast` function**

Add after `scan_python_ast`:

```rust
/// Scan Ruby constant assignments for hardcoded secrets using tree-sitter AST
fn scan_ruby_ast(content: &str, file_path: &str, findings: &mut Vec<Finding>) {
    let mut parser = crate::ast::ruby::new_parser();
    let assignments = crate::ast::ruby::extract_assignments(&mut parser, content);

    for (name, value, line) in assignments {
        if let Some(src_line) = content.lines().nth(line.saturating_sub(1)) {
            if src_line.contains("depsec:allow") {
                continue;
            }
        }
        check_secret_candidate(&name, &value, file_path, line, findings);
    }
}
```

- [ ] **Step 3: Add test**

```rust
    #[test]
    fn test_ruby_constant_scanning() {
        let content = r#"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuv"
VERSION = "1.0.0"
TEST_SECRET = "fake-for-testing"
"#;
        // Write to temp file with .rb extension
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.rb");
        std::fs::write(&file, content).unwrap();

        let findings = scan_for_secrets(dir.path(), &[file]);
        assert!(
            findings.iter().any(|f| f.message.contains("API_KEY")),
            "Should detect API_KEY"
        );
        assert!(
            !findings.iter().any(|f| f.message.contains("VERSION")),
            "Should skip VERSION (not suspicious name)"
        );
        assert!(
            !findings.iter().any(|f| f.message.contains("TEST_SECRET")),
            "Should skip TEST_SECRET (has 'test' showstopper)"
        );
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test secrets_ast -- --nocapture`
Expected: all tests pass including the new Ruby test

- [ ] **Step 5: Commit**

```bash
git add src/secrets_ast.rs
git commit -m "feat: add Ruby secrets detection via tree-sitter AST"
```

---

### Task 7: Upgrade Rust secrets to tree-sitter

**Files:**
- Modify: `src/secrets_ast.rs`

Replace the regex-based `scan_rust_constants` with a tree-sitter-based `scan_rust_ast`.

- [ ] **Step 1: Replace scan_rust_constants with scan_rust_ast**

Replace the `scan_rust_constants` function and update its call site:

Change the call site (around line 107):
```rust
        // Rust files: scan with tree-sitter AST for const/static assignments
        if ext == "rs" {
            scan_rust_ast(&content, &rel_path, &mut findings);
        }
```

Replace the function:
```rust
/// Scan Rust const/static declarations for hardcoded secrets using tree-sitter AST
fn scan_rust_ast(content: &str, file_path: &str, findings: &mut Vec<Finding>) {
    let mut parser = crate::ast::rust_lang::new_parser();
    let assignments = crate::ast::rust_lang::extract_assignments(&mut parser, content);

    for (name, value, line) in assignments {
        if let Some(src_line) = content.lines().nth(line.saturating_sub(1)) {
            if src_line.contains("depsec:allow") {
                continue;
            }
        }
        check_secret_candidate(&name, &value, file_path, line, findings);
    }
}
```

- [ ] **Step 2: Update existing test to use new function name**

The existing `test_rust_const_scanning` and `test_depsec_allow_inline` tests call `scan_rust_constants` directly. Update them to either:
- Test through `scan_for_secrets` (preferred — matches Ruby test pattern), or
- Call `scan_rust_ast` directly

Update `test_rust_const_scanning`:
```rust
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
```

Update `test_depsec_allow_inline`:
```rust
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
```

Also update `test_rust_typed_secret_detected` in `src/checks/secrets.rs` if it directly calls `scan_rust_constants`.

- [ ] **Step 3: Remove the old `scan_rust_constants` function entirely**

Delete the function and the regex import if no longer used elsewhere.

- [ ] **Step 4: Run all secrets tests**

Run: `cargo test secrets -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/secrets_ast.rs
git commit -m "refactor: upgrade Rust secrets detection from regex to tree-sitter AST"
```

---

## Layer C: Reachability / Import Scanning

### Task 8: Extend reachability to scan Python, Ruby, and Rust files

**Files:**
- Modify: `src/reachability.rs`

Currently `scan_app_imports` only scans JS/TS files. Extend it to also scan `.py`, `.rb`, and `.rs` files using each language's tree-sitter-based import extraction.

- [ ] **Step 1: Add Python/Ruby/Rust extensions to SOURCE_EXTENSIONS**

```rust
/// File extensions to parse for imports
const SOURCE_EXTENSIONS_JS: &[&str] = &["js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"];
const SOURCE_EXTENSIONS_PY: &[&str] = &["py"];
const SOURCE_EXTENSIONS_RB: &[&str] = &["rb", "rake"];
const SOURCE_EXTENSIONS_RS: &[&str] = &["rs"];
```

- [ ] **Step 2: Add Python/Ruby/Rust parsers to `scan_app_imports`**

Inside `scan_app_imports`, after the JS/TS parsers, add:

```rust
    let mut py_parser = crate::ast::python::new_parser();
    let mut rb_parser = crate::ast::ruby::new_parser();
    let mut rs_parser = crate::ast::rust_lang::new_parser();
```

- [ ] **Step 3: Extend the file scanning loop**

In the loop body, after the JS/TS handling and the svelte/vue handling, add:

```rust
            else if SOURCE_EXTENSIONS_PY.contains(&ext) {
                let imports = crate::ast::python::extract_imports(&mut py_parser, &content);
                for module in imports {
                    packages.insert(module.clone());
                    locations
                        .entry(module)
                        .or_default()
                        .push((rel_path.clone(), 0));
                }
            } else if SOURCE_EXTENSIONS_RB.contains(&ext) {
                let requires = crate::ast::ruby::extract_requires(&mut rb_parser, &content);
                for module in requires {
                    packages.insert(module.clone());
                    locations
                        .entry(module)
                        .or_default()
                        .push((rel_path.clone(), 0));
                }
            } else if SOURCE_EXTENSIONS_RS.contains(&ext) {
                let uses = crate::ast::rust_lang::extract_uses(&mut rs_parser, &content);
                for crate_name in uses {
                    packages.insert(crate_name.clone());
                    locations
                        .entry(crate_name)
                        .or_default()
                        .push((rel_path.clone(), 0));
                }
            }
```

- [ ] **Step 4: Remove `#[cfg(test)]` from Python's `extract_imports`**

In `src/ast/python.rs`, change:
```rust
#[cfg(test)]
pub fn extract_imports(parser: &mut Parser, source: &str) -> Vec<String> {
```
to:
```rust
pub fn extract_imports(parser: &mut Parser, source: &str) -> Vec<String> {
```

- [ ] **Step 5: Update the `filter_entry` closure to include Python/Ruby/Rust skip dirs**

In the walkdir filter, add Python/Ruby/Rust-specific directories to skip:

```rust
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or("");
                name != "node_modules"
                    && name != ".svelte-kit"
                    && name != "dist"
                    && name != "build"
                    && name != "__pycache__"
                    && name != ".venv"
                    && name != "venv"
                    && name != "target"
                    && name != "vendor"
            })
```

- [ ] **Step 6: Add tests**

```rust
    #[test]
    fn test_scan_app_imports_python() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.py"),
            "import requests\nfrom flask import Flask\n",
        )
        .unwrap();

        let imports = scan_app_imports(dir.path());
        assert!(imports.packages.contains("requests"));
        assert!(imports.packages.contains("flask"));
    }

    #[test]
    fn test_scan_app_imports_ruby() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("lib");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("app.rb"),
            "require \"json\"\nrequire \"active_support/core_ext\"\n",
        )
        .unwrap();

        let imports = scan_app_imports(dir.path());
        assert!(imports.packages.contains("json"));
        assert!(imports.packages.contains("active_support"));
    }

    #[test]
    fn test_scan_app_imports_rust() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            "use serde::Serialize;\nuse tokio::runtime;\n",
        )
        .unwrap();

        let imports = scan_app_imports(dir.path());
        assert!(imports.packages.contains("serde"));
        assert!(imports.packages.contains("tokio"));
    }
```

- [ ] **Step 7: Run tests**

Run: `cargo test reachability -- --nocapture`
Expected: all tests pass

- [ ] **Step 8: Commit**

```bash
git add src/reachability.rs src/ast/python.rs
git commit -m "feat: extend reachability scanning to Python, Ruby, and Rust"
```

---

## Layer D: Preflight Typosquat

### Task 9: Add RubyGems top packages and wire into typosquat check

**Files:**
- Modify: `src/preflight.rs`

- [ ] **Step 1: Add RUBYGEMS_TOP_PACKAGES constant**

Add after CRATES_TOP_PACKAGES:

```rust
/// Top RubyGems packages
const RUBYGEMS_TOP_PACKAGES: &[&str] = &[
    "rails",
    "rake",
    "bundler",
    "rspec",
    "devise",
    "puma",
    "sidekiq",
    "nokogiri",
    "activerecord",
    "actionpack",
    "activesupport",
    "actionview",
    "actionmailer",
    "activemodel",
    "activejob",
    "activestorage",
    "actioncable",
    "actiontext",
    "pg",
    "mysql2",
    "sqlite3",
    "redis",
    "faraday",
    "rest-client",
    "httparty",
    "sinatra",
    "rack",
    "unicorn",
    "thin",
    "capistrano",
    "rspec-core",
    "rspec-expectations",
    "rspec-mocks",
    "minitest",
    "rubocop",
    "simplecov",
    "factory_bot",
    "faker",
    "dotenv",
    "figaro",
    "jwt",
    "bcrypt",
    "pundit",
    "cancancan",
    "omniauth",
    "doorkeeper",
    "kaminari",
    "pagy",
    "ransack",
    "jbuilder",
    "slim",
    "haml",
    "sassc",
    "uglifier",
    "webpacker",
    "turbo-rails",
    "stimulus-rails",
    "importmap-rails",
    "sprockets",
    "bootsnap",
    "tzinfo",
    "i18n",
    "thor",
    "concurrent-ruby",
    "mini_portile2",
    "ffi",
    "json",
    "bigdecimal",
    "drb",
    "net-smtp",
    "net-pop",
    "net-imap",
    "stripe",
    "aws-sdk",
    "aws-sdk-s3",
    "resque",
    "delayed_job",
    "whenever",
];
```

- [ ] **Step 2: Wire RubyGems into `check_typosquatting`**

Update the match in `check_typosquatting`:

```rust
    let popular = match pkg.ecosystem {
        parsers::Ecosystem::Npm => NPM_TOP_PACKAGES,
        parsers::Ecosystem::PyPI => PYPI_TOP_PACKAGES,
        parsers::Ecosystem::CratesIo => CRATES_TOP_PACKAGES,
        parsers::Ecosystem::RubyGems => RUBYGEMS_TOP_PACKAGES,
        _ => return,
    };
```

- [ ] **Step 3: Add test**

```rust
    #[test]
    fn test_rubygems_typosquat_detection() {
        let pkg = parsers::Package {
            name: "raills".into(),
            version: "7.0.0".into(),
            ecosystem: parsers::Ecosystem::RubyGems,
        };
        let mut findings = Vec::new();
        check_typosquatting(&pkg, &mut findings);
        assert!(
            !findings.is_empty(),
            "Should detect 'raills' as typosquat of 'rails'"
        );
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test preflight -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/preflight.rs
git commit -m "feat: add RubyGems top packages for typosquat detection"
```

---

## Final: Full test suite + fmt + clippy

### Task 10: Verify everything works together

- [ ] **Step 1: cargo fmt**

Run: `cargo fmt`

- [ ] **Step 2: cargo clippy**

Run: `cargo clippy -- -D warnings`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cargo test`
Expected: all tests pass

- [ ] **Step 4: Commit any formatting fixes**

```bash
git add -A
git commit -m "chore: fmt + clippy fixes for multi-language tree-sitter parity"
```

---

## Parity Summary (post-implementation)

| Feature | JS/TS | Python | Ruby | Rust |
|---|---|---|---|---|
| AST security rules | P001,P002,P008,P013,P014 | P020-P023 | P030-P033 | P040-P043 |
| Secrets (tree-sitter) | tree-sitter | tree-sitter | tree-sitter | tree-sitter |
| Reachability imports | tree-sitter | tree-sitter | tree-sitter | tree-sitter |
| Preflight typosquat | npm top pkgs | PyPI top pkgs | RubyGems top pkgs | crates.io top pkgs |
