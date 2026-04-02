use std::collections::HashSet;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::checks::{Confidence, Severity};

use super::AstFinding;

/// Dangerous modules whose exec/spawn calls should be flagged
const DANGEROUS_MODULES: &[&str] = &["child_process", "shelljs", "execa", "cross-spawn"];

/// Dangerous method names on those modules
const DANGEROUS_METHODS: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
];

/// Analyze JavaScript/TypeScript source for security patterns
pub fn analyze(parser: &mut Parser, source: &str) -> Vec<AstFinding> {
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let source_bytes = source.as_bytes();
    let mut findings = Vec::new();

    // Pass 1: Find dangerous module imports
    let dangerous_aliases = find_dangerous_imports(&tree, source_bytes);

    // Pass 2: Find exec/spawn calls on dangerous aliases
    if !dangerous_aliases.is_empty() {
        find_dangerous_calls(&tree, source_bytes, &dangerous_aliases, &mut findings);
    }

    // P008: Find new Function() with variable args
    find_dynamic_function(&tree, source_bytes, &mut findings);

    // P013: Find require() with non-literal arguments (dynamic require)
    find_dynamic_require(&tree, source_bytes, &mut findings);

    // P014: Find dense String.fromCharCode usage (deobfuscation routines)
    find_deobfuscation_patterns(&tree, source_bytes, &mut findings);

    // Detect Reflect.apply/construct with dangerous function arguments
    find_dangerous_reflect(&tree, source_bytes, &mut findings);

    findings
}

/// Pass 1: Scan for require('child_process') and import statements
fn find_dangerous_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut aliases = HashSet::new();

    // Query: const X = require('child_process')
    // Also: const { exec, spawn } = require('child_process')
    let require_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (identifier) @req_fn
          arguments: (arguments
            (string (string_fragment) @module))
          (#eq? @req_fn "require"))
        "#,
    );

    if let Ok(query) = require_query {
        let module_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "module")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            // Get the module name
            let module_cap = m.captures.iter().find(|c| c.index as usize == module_idx);
            if let Some(cap) = module_cap {
                let module_name = cap.node.utf8_text(source).unwrap_or("");
                if !DANGEROUS_MODULES.contains(&module_name) {
                    continue;
                }

                // Walk up to find the variable_declarator parent
                let call_node = m.captures[0].node.parent(); // call_expression
                if let Some(call) = call_node {
                    if let Some(declarator) = call.parent() {
                        if declarator.kind() == "variable_declarator" {
                            if let Some(name_node) = declarator.child_by_field_name("name") {
                                match name_node.kind() {
                                    "identifier" => {
                                        // const cp = require('child_process')
                                        if let Ok(name) = name_node.utf8_text(source) {
                                            aliases.insert(name.to_string());
                                        }
                                    }
                                    "object_pattern" => {
                                        // const { exec, spawn } = require('child_process')
                                        let mut child_cursor = name_node.walk();
                                        for child in name_node.children(&mut child_cursor) {
                                            if child.kind()
                                                == "shorthand_property_identifier_pattern"
                                            {
                                                if let Ok(name) = child.utf8_text(source) {
                                                    aliases.insert(name.to_string());
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Query: process.mainModule.require('child_process')
    // This is an alternative way to access require() that bypasses normal import tracking
    let mainmodule_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (member_expression
            object: (member_expression
              object: (identifier) @proc
              property: (property_identifier) @mm)
            property: (property_identifier) @req)
          arguments: (arguments
            (string (string_fragment) @module))
          (#eq? @proc "process")
          (#eq? @mm "mainModule")
          (#eq? @req "require"))
        "#,
    );

    if let Ok(query) = mainmodule_query {
        let module_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "module")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == module_idx) {
                let module_name = cap.node.utf8_text(source).unwrap_or("");
                if DANGEROUS_MODULES.contains(&module_name) {
                    // Walk up from the string_fragment → string → arguments → call_expression
                    // → variable_declarator to find the assigned name
                    let mut node = cap.node;
                    while let Some(parent) = node.parent() {
                        if parent.kind() == "variable_declarator" {
                            if let Some(name_node) = parent.child_by_field_name("name") {
                                if name_node.kind() == "identifier" {
                                    if let Ok(name) = name_node.utf8_text(source) {
                                        aliases.insert(name.to_string());
                                    }
                                }
                            }
                            break;
                        }
                        node = parent;
                    }
                }
            }
        }
    }

    // Query: import { exec } from 'child_process'
    // Also: import cp from 'child_process'
    let import_query = Query::new(
        &tree.language(),
        r#"
        (import_statement
          source: (string (string_fragment) @module))
        "#,
    );

    if let Ok(query) = import_query {
        let module_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "module")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let module_cap = m.captures.iter().find(|c| c.index as usize == module_idx);
            if let Some(cap) = module_cap {
                let module_name = cap.node.utf8_text(source).unwrap_or("");
                if !DANGEROUS_MODULES.contains(&module_name) {
                    continue;
                }

                // Walk up to import_statement and extract imported names
                let import_stmt = cap.node.parent().and_then(|p| p.parent()); // string -> import_statement
                if let Some(stmt) = import_stmt {
                    let mut stmt_cursor = stmt.walk();
                    for child in stmt.children(&mut stmt_cursor) {
                        if child.kind() == "import_clause" {
                            extract_import_names(&child, source, &mut aliases);
                        }
                    }
                }
            }
        }
    }

    aliases
}

/// Extract imported identifiers from an import clause
fn extract_import_names(clause: &tree_sitter::Node, source: &[u8], aliases: &mut HashSet<String>) {
    let mut cursor = clause.walk();
    for child in clause.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                // import cp from '...'
                if let Ok(name) = child.utf8_text(source) {
                    aliases.insert(name.to_string());
                }
            }
            "named_imports" => {
                // import { exec, spawn } from '...'
                let mut named_cursor = child.walk();
                for spec in child.children(&mut named_cursor) {
                    if spec.kind() == "import_specifier" {
                        // Use the local name (after 'as') if present, otherwise the imported name
                        let local = spec
                            .child_by_field_name("alias")
                            .or_else(|| spec.child_by_field_name("name"));
                        if let Some(name_node) = local {
                            if let Ok(name) = name_node.utf8_text(source) {
                                aliases.insert(name.to_string());
                            }
                        }
                    }
                }
            }
            "namespace_import" => {
                // import * as cp from '...'
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "identifier" {
                        if let Ok(name) = ns_child.utf8_text(source) {
                            aliases.insert(name.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Pass 2: Find exec/spawn calls on dangerous aliases
fn find_dangerous_calls(
    tree: &tree_sitter::Tree,
    source: &[u8],
    dangerous_aliases: &HashSet<String>,
    findings: &mut Vec<AstFinding>,
) {
    // Query: obj.method(args)
    let method_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
          arguments: (arguments) @args)
        "#,
    );

    if let Ok(query) = method_query {
        let obj_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "obj")
            .unwrap();
        let method_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "method")
            .unwrap();
        let args_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "args")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let obj_cap = m.captures.iter().find(|c| c.index as usize == obj_idx);
            let method_cap = m.captures.iter().find(|c| c.index as usize == method_idx);
            let args_cap = m.captures.iter().find(|c| c.index as usize == args_idx);
            let (Some(obj_cap), Some(method_cap), Some(args_cap)) = (obj_cap, method_cap, args_cap)
            else {
                continue;
            };

            let obj_text = obj_cap.node.utf8_text(source).unwrap_or("");
            let method_text = method_cap.node.utf8_text(source).unwrap_or("");

            if !dangerous_aliases.contains(obj_text) {
                continue;
            }
            if !DANGEROUS_METHODS.contains(&method_text) {
                continue;
            }

            let severity = classify_arg_severity(&args_cap.node, source);
            let line = obj_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P001".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "{obj_text}.{method_text}() with {} argument",
                    severity_arg_label(&severity)
                ),
                line,
            });
        }
    }

    // Query: direct call exec(args) — for destructured imports
    let direct_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (identifier) @func
          arguments: (arguments) @args)
        "#,
    );

    if let Ok(query) = direct_query {
        let func_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "func")
            .unwrap();
        let args_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "args")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let func_cap = m.captures.iter().find(|c| c.index as usize == func_idx);
            let args_cap = m.captures.iter().find(|c| c.index as usize == args_idx);
            let (Some(func_cap), Some(args_cap)) = (func_cap, args_cap) else {
                continue;
            };

            let func_text = func_cap.node.utf8_text(source).unwrap_or("");

            // For direct calls, only check alias membership — no DANGEROUS_METHODS filter.
            // If it came from a dangerous module (e.g., execa), any call is suspicious.
            if !dangerous_aliases.contains(func_text) {
                continue;
            }

            let severity = classify_arg_severity(&args_cap.node, source);
            let line = func_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P001".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "{func_text}() with {} argument (destructured import)",
                    severity_arg_label(&severity)
                ),
                line,
            });
        }
    }
}

/// Classify severity based on the first argument's type
fn classify_arg_severity(args_node: &tree_sitter::Node, _source: &[u8]) -> Severity {
    // Get the first argument (skip opening paren)
    let first_arg = args_node
        .children(&mut args_node.walk())
        .find(|c| c.kind() != "(" && c.kind() != ")" && c.kind() != ",");

    match first_arg {
        None => Severity::High, // No args — conservative
        Some(arg) => match arg.kind() {
            "string" | "string_fragment" => Severity::Medium, // Static string
            "template_string" => {
                // Check if it has interpolation
                let mut cursor = arg.walk();
                let has_substitution = arg
                    .children(&mut cursor)
                    .any(|c| c.kind() == "template_substitution");
                if has_substitution {
                    Severity::Critical // Template with interpolation
                } else {
                    Severity::Medium // Static template
                }
            }
            _ => Severity::High, // Variable or complex expression
        },
    }
}

fn severity_arg_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "interpolated template",
        Severity::High => "variable",
        Severity::Medium => "static string",
        Severity::Low => "unknown",
    }
}

/// P008: Find new Function() with variable args
/// Also detects: new global.Function(), new globalThis.Function(),
/// and const Fn = Function; new Fn() alias patterns.
fn find_dynamic_function(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Collect Function aliases: const Fn = Function; const F = globalThis.Function;
    let mut function_aliases: HashSet<String> = HashSet::new();
    function_aliases.insert("Function".into());

    let alias_query = Query::new(
        &tree.language(),
        r#"
        (variable_declarator
          name: (identifier) @alias
          value: (identifier) @val
          (#eq? @val "Function"))
        "#,
    );
    if let Ok(query) = alias_query {
        let alias_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "alias")
            .unwrap();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == alias_idx) {
                if let Ok(name) = cap.node.utf8_text(source) {
                    function_aliases.insert(name.to_string());
                }
            }
        }
    }

    // Query 1: new Function(args) — bare identifier
    let query = Query::new(
        &tree.language(),
        r#"
        (new_expression
          constructor: (identifier) @ctor
          arguments: (arguments) @args)
        "#,
    );

    if let Ok(query) = query {
        let args_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "args")
            .unwrap();
        let ctor_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "ctor")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let args_cap = m.captures.iter().find(|c| c.index as usize == args_idx);
            let ctor_cap = m.captures.iter().find(|c| c.index as usize == ctor_idx);
            let (Some(args_cap), Some(ctor_cap)) = (args_cap, ctor_cap) else {
                continue;
            };

            let ctor_text = ctor_cap.node.utf8_text(source).unwrap_or("");
            if !function_aliases.contains(ctor_text) {
                continue;
            }

            let severity = classify_arg_severity(&args_cap.node, source);
            let line = ctor_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P008".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "new {ctor_text}() with {} argument",
                    severity_arg_label(&severity)
                ),
                line,
            });
        }
    }

    // Query 2: new global.Function(args) / new globalThis.Function(args) — member_expression
    let member_query = Query::new(
        &tree.language(),
        r#"
        (new_expression
          constructor: (member_expression
            property: (property_identifier) @prop)
          arguments: (arguments) @args
          (#eq? @prop "Function"))
        "#,
    );

    if let Ok(query) = member_query {
        let prop_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "prop")
            .unwrap();
        let args_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "args")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let prop_cap = m.captures.iter().find(|c| c.index as usize == prop_idx);
            let args_cap = m.captures.iter().find(|c| c.index as usize == args_idx);
            let (Some(prop_cap), Some(args_cap)) = (prop_cap, args_cap) else {
                continue;
            };

            let severity = classify_arg_severity(&args_cap.node, source);
            let line = prop_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P008".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "new *.Function() with {} argument",
                    severity_arg_label(&severity)
                ),
                line,
            });
        }
    }
}

/// P013: Find require() calls with non-literal arguments (dynamic require)
/// Almost never legitimate in production dependencies — strong malware indicator.
fn find_dynamic_require(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    // Match all require() calls
    let query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (identifier) @fn
          arguments: (arguments . (_) @arg)
          (#eq? @fn "require"))
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

            // Skip string literals — those are normal require('module') calls
            if arg_kind == "string" || arg_kind == "string_fragment" {
                continue;
            }

            // Skip static template strings without interpolation
            if arg_kind == "template_string" {
                let mut child_cursor = arg_cap.node.walk();
                let has_substitution = arg_cap
                    .node
                    .children(&mut child_cursor)
                    .any(|c| c.kind() == "template_substitution");
                if !has_substitution {
                    continue;
                }
            }

            // Everything else is a dynamic require — flag it
            let (severity, arg_label) = match arg_kind {
                "call_expression" => (Severity::Critical, "function call"),
                "subscript_expression" | "member_expression" => {
                    (Severity::Critical, "computed expression")
                }
                "binary_expression" => (Severity::High, "concatenation"),
                "template_string" => (Severity::High, "interpolated template"),
                "identifier" => (Severity::High, "variable"),
                _ => (Severity::High, "dynamic expression"),
            };

            let line = fn_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P013".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "Dynamic require() with {arg_label} argument — module name computed at runtime"
                ),
                line,
            });
        }
    }

    // Detect (0, require)(name) — indirect require via comma/sequence expression
    // This is a common evasion technique: the comma operator returns the last value
    let indirect_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (parenthesized_expression
            (sequence_expression
              (_)
              (identifier) @fn))
          arguments: (arguments . (_) @arg)
          (#eq? @fn "require"))
        "#,
    );

    if let Ok(query) = indirect_query {
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

            // Any indirect require is suspicious regardless of argument type
            let severity = if arg_kind == "string" || arg_kind == "string_fragment" {
                Severity::High // Even static string through indirect require is suspicious
            } else {
                Severity::Critical
            };

            findings.push(AstFinding {
                rule_id: "DEPSEC-P013".into(),
                severity,
                confidence: Confidence::High,
                message: "Indirect (0, require)() call — evasion of static analysis".into(),
                line,
            });
        }
    }

    // Also detect dynamic import() — same logic as require()
    // In tree-sitter, import(x) is a call_expression with function: (import)
    let import_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (import) @fn
          arguments: (arguments . (_) @arg))
        "#,
    );

    if let Ok(query) = import_query {
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

            if arg_kind == "string" || arg_kind == "string_fragment" {
                continue;
            }

            if arg_kind == "template_string" {
                let mut child_cursor = arg_cap.node.walk();
                let has_substitution = arg_cap
                    .node
                    .children(&mut child_cursor)
                    .any(|c| c.kind() == "template_substitution");
                if !has_substitution {
                    continue;
                }
            }

            let (severity, arg_label) = match arg_kind {
                "call_expression" => (Severity::Critical, "function call"),
                "subscript_expression" | "member_expression" => {
                    (Severity::Critical, "computed expression")
                }
                "identifier" => (Severity::High, "variable"),
                _ => (Severity::High, "dynamic expression"),
            };

            let line = fn_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P013".into(),
                severity,
                confidence: Confidence::High,
                message: format!(
                    "Dynamic import() with {arg_label} argument — module name computed at runtime"
                ),
                line,
            });
        }
    }
}

/// P014 AST: Detect dense String.fromCharCode usage in function bodies (deobfuscation routines)
/// 3+ fromCharCode calls in the same function is a strong deobfuscation signal.
fn find_deobfuscation_patterns(
    tree: &tree_sitter::Tree,
    source: &[u8],
    findings: &mut Vec<AstFinding>,
) {
    // Find all String.fromCharCode calls
    let query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @prop)
          (#eq? @obj "String")
          (#eq? @prop "fromCharCode"))
        "#,
    );

    if let Ok(query) = query {
        let obj_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "obj")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches_iter = cursor.matches(&query, tree.root_node(), source);

        // Collect all fromCharCode call locations
        let mut locations: Vec<usize> = Vec::new();
        while let Some(m) = matches_iter.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == obj_idx) {
                locations.push(cap.node.start_position().row + 1);
            }
        }

        // If 3+ fromCharCode calls exist in the file, flag as deobfuscation routine
        if locations.len() >= 3 {
            let first_line = locations[0];
            findings.push(AstFinding {
                rule_id: "DEPSEC-P014".into(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "Dense String.fromCharCode usage ({} calls) — likely deobfuscation routine",
                    locations.len()
                ),
                line: first_line,
            });
        }
    }
}

/// Detect Reflect.apply(fn, ...) and Reflect.construct(fn, ...) where fn is dangerous
/// E.g., Reflect.apply(fs.readFileSync, fs, ['/home/user/.ssh/id_rsa'])
fn find_dangerous_reflect(tree: &tree_sitter::Tree, source: &[u8], findings: &mut Vec<AstFinding>) {
    let query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
          arguments: (arguments . (_) @first_arg)
          (#eq? @obj "Reflect")
          (#match? @method "^(apply|construct)$"))
        "#,
    );

    if let Ok(query) = query {
        let method_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "method")
            .unwrap();
        let arg_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "first_arg")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let method_cap = m.captures.iter().find(|c| c.index as usize == method_idx);
            let arg_cap = m.captures.iter().find(|c| c.index as usize == arg_idx);
            let (Some(method_cap), Some(arg_cap)) = (method_cap, arg_cap) else {
                continue;
            };

            // Check if the first argument references dangerous functions
            let arg_text = arg_cap.node.utf8_text(source).unwrap_or("");
            let is_dangerous = arg_text.contains("readFileSync")
                || arg_text.contains("readFile")
                || arg_text.contains("exec")
                || arg_text.contains("spawn")
                || arg_text.contains("writeFile");

            if !is_dangerous {
                continue;
            }

            let method_text = method_cap.node.utf8_text(source).unwrap_or("");
            let line = method_cap.node.start_position().row + 1;

            findings.push(AstFinding {
                rule_id: "DEPSEC-P001".into(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!("Reflect.{method_text}() with dangerous function: {arg_text}"),
                line,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(source: &str) -> Vec<AstFinding> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        analyze(&mut parser, source)
    }

    #[test]
    fn test_regex_exec_not_flagged() {
        let findings = parse_js(
            r#"
            const re = /pattern/;
            const result = re.exec("test string");
        "#,
        );
        assert!(findings.is_empty(), "regex.exec() should NOT be flagged");
    }

    #[test]
    fn test_child_process_exec_flagged() {
        let findings = parse_js(
            r#"
            const cp = require('child_process');
            cp.exec(userInput);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_exec_destructured_import() {
        let findings = parse_js(
            r#"
            const { exec, spawn } = require('child_process');
            exec(command);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
        assert!(findings[0].message.contains("destructured"));
    }

    #[test]
    fn test_exec_es_import() {
        let findings = parse_js(
            r#"
            import { exec } from 'child_process';
            exec(command);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
    }

    #[test]
    fn test_exec_static_string_medium() {
        let findings = parse_js(
            r#"
            const cp = require('child_process');
            cp.exec("ls -la");
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_exec_template_literal_critical() {
        let findings = parse_js(
            r#"
            const cp = require('child_process');
            cp.exec(`ls ${userInput}`);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_no_imports_no_findings() {
        let findings = parse_js(
            r#"
            const result = someObj.exec(data);
            db.exec("SELECT * FROM users");
            /regex/.exec("test");
        "#,
        );
        assert!(findings.is_empty(), "No dangerous imports → no findings");
    }

    #[test]
    fn test_shelljs_flagged() {
        let findings = parse_js(
            r#"
            const shell = require('shelljs');
            shell.exec(command);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
    }

    #[test]
    fn test_new_function_variable() {
        let findings = parse_js(
            r#"
            const fn = new Function(userCode);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P008");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn test_new_function_static() {
        let findings = parse_js(
            r#"
            const fn = new Function("return 1");
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_execa_flagged() {
        let findings = parse_js(
            r#"
            const execa = require('execa');
            execa(command);
        "#,
        );
        // execa is a dangerous module — direct calls should be flagged
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
        assert!(findings[0].message.contains("destructured import"));
    }

    #[test]
    fn test_multiple_findings_same_file() {
        let findings = parse_js(
            r#"
            const cp = require('child_process');
            cp.exec(cmd1);
            cp.spawn(cmd2);
            cp.execSync(cmd3);
        "#,
        );
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.rule_id == "DEPSEC-P001"));
    }

    #[test]
    fn test_namespace_import() {
        let findings = parse_js(
            r#"
            import * as cp from 'child_process';
            cp.exec(command);
        "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEPSEC-P001");
    }

    // --- P013: Dynamic Require tests ---

    #[test]
    fn test_dynamic_require_variable() {
        let findings = parse_js(
            r#"
            const x = decode(stq[0]);
            const mod = require(x);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert_eq!(p013[0].severity, Severity::High);
        assert_eq!(p013[0].confidence, Confidence::High);
    }

    #[test]
    fn test_dynamic_require_function_call() {
        let findings = parse_js(
            r#"
            const t = require(decode(stq[2], ord));
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert_eq!(p013[0].severity, Severity::Critical);
        assert!(p013[0].message.contains("function call"));
    }

    #[test]
    fn test_dynamic_require_subscript() {
        let findings = parse_js(
            r#"
            const m = require(modules[0]);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert_eq!(p013[0].severity, Severity::Critical);
    }

    #[test]
    fn test_dynamic_require_concatenation() {
        let findings = parse_js(
            r#"
            const m = require('./' + moduleName);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert_eq!(p013[0].severity, Severity::High);
        assert!(p013[0].message.contains("concatenation"));
    }

    #[test]
    fn test_dynamic_require_template_interpolation() {
        let findings = parse_js(
            r#"
            const m = require(`${prefix}/module`);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert_eq!(p013[0].severity, Severity::High);
    }

    #[test]
    fn test_static_require_not_flagged() {
        let findings = parse_js(
            r#"
            const fs = require('fs');
            const path = require("path");
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert!(p013.is_empty(), "Static require should NOT be flagged");
    }

    #[test]
    fn test_static_template_require_not_flagged() {
        let findings = parse_js(
            r#"
            const m = require(`fs`);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert!(
            p013.is_empty(),
            "Static template require should NOT be flagged"
        );
    }

    #[test]
    fn test_axios_payload_pattern() {
        // Mimics the actual axios attack pattern
        let findings = parse_js(
            r#"
            const stq = ["encoded1", "encoded2", "encoded3"];
            function _trans(x, r) {
                let S = Buffer.from(x, "base64").toString("utf8");
                return String.fromCharCode(S.charCodeAt(0) ^ 333);
            }
            const t = require(_trans(stq[0], "key"));
            const W = require(_trans(stq[1], "key"));
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(
            p013.len(),
            2,
            "Should flag both dynamic require() calls in axios-style payload"
        );
        assert!(p013.iter().all(|f| f.severity == Severity::Critical));
    }

    // --- P014: Deobfuscation Pattern tests ---

    #[test]
    fn test_dense_fromcharcode_flagged() {
        let findings = parse_js(
            r#"
            function decode(s) {
                var r = String.fromCharCode(s.charCodeAt(0) ^ 42);
                r += String.fromCharCode(s.charCodeAt(1) ^ 42);
                r += String.fromCharCode(s.charCodeAt(2) ^ 42);
                return r;
            }
        "#,
        );
        let p014: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P014")
            .collect();
        assert_eq!(p014.len(), 1);
        assert_eq!(p014[0].confidence, Confidence::High);
        assert!(p014[0].message.contains("3 calls"));
    }

    #[test]
    fn test_single_fromcharcode_not_flagged() {
        let findings = parse_js(
            r#"
            var ch = String.fromCharCode(65);
        "#,
        );
        let p014: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P014")
            .collect();
        assert!(p014.is_empty(), "Single fromCharCode should NOT be flagged");
    }

    // --- P013: Dynamic import() tests ---

    #[test]
    fn test_dynamic_import_variable() {
        let findings = parse_js(
            r#"
            const m = import(moduleName);
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1);
        assert!(p013[0].message.contains("import()"));
    }

    #[test]
    fn test_static_import_expression_not_flagged() {
        let findings = parse_js(
            r#"
            const m = import('lodash');
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert!(p013.is_empty(), "Static import() should NOT be flagged");
    }

    // --- E17: new global.Function() ---

    #[test]
    fn test_global_function_detected() {
        let findings = parse_js(
            r#"
            const code = "alert(1)";
            new global.Function(code)();
        "#,
        );
        let p008: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P008")
            .collect();
        assert_eq!(
            p008.len(),
            1,
            "new global.Function() should be detected as P008"
        );
    }

    // --- E18: const Fn = Function; new Fn() ---

    #[test]
    fn test_function_alias_detected() {
        let findings = parse_js(
            r#"
            const Fn = Function;
            const code = "alert(1)";
            new Fn(code)();
        "#,
        );
        let p008: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P008")
            .collect();
        assert_eq!(
            p008.len(),
            1,
            "const Fn = Function; new Fn() should be detected as P008"
        );
    }

    // --- E16: (0, require)(name) ---

    #[test]
    fn test_indirect_require_detected() {
        let findings = parse_js(
            r#"
            const cp = (0, require)('child_process');
            cp.exec('whoami');
        "#,
        );
        let p013: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P013")
            .collect();
        assert_eq!(p013.len(), 1, "(0, require)() should be detected as P013");
        assert!(p013[0].message.contains("Indirect"));
    }

    // --- E08: process.mainModule.require() ---

    #[test]
    fn test_mainmodule_require_detected() {
        let findings = parse_js(
            r#"
            const cp = process.mainModule.require('child_process');
            cp.exec('whoami');
        "#,
        );
        let p001: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-P001")
            .collect();
        assert_eq!(
            p001.len(),
            1,
            "process.mainModule.require('child_process') should track alias and detect exec"
        );
    }
}
