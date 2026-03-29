use std::collections::{HashMap, HashSet};
use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

/// Result of scanning the app's own source for package imports
pub struct AppImports {
    /// Set of package names directly imported by the app
    pub packages: HashSet<String>,
    /// Map of package name → [(file, line)] showing where it's imported
    #[allow(dead_code)]
    pub locations: HashMap<String, Vec<(String, usize)>>,
}

/// Directories to scan for app source code
const SOURCE_DIRS: &[&str] = &["src", "app", "lib", "packages", "apps"];

/// File extensions to parse for imports
const SOURCE_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"];

/// Scan the project's own source files to find which packages are imported.
/// This only scans YOUR code, not node_modules.
pub fn scan_app_imports(root: &Path) -> AppImports {
    let mut packages = HashSet::new();
    let mut locations: HashMap<String, Vec<(String, usize)>> = HashMap::new();

    let mut js_parser = Parser::new();
    js_parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("failed to set JS language");

    let mut ts_parser = Parser::new();
    ts_parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("failed to set TS language");

    // Also check devDependencies vs dependencies in package.json
    let _dev_deps = read_dev_dependencies(root); // Available for future use

    // Find all source files
    for source_dir in SOURCE_DIRS {
        let dir = root.join(source_dir);
        if !dir.exists() {
            continue;
        }

        for entry in walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or("");
                name != "node_modules" && name != ".svelte-kit" && name != "dist" && name != "build"
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let rel_path = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            if SOURCE_EXTENSIONS.contains(&ext) {
                // Parse with tree-sitter
                let parser = if ext == "ts" || ext == "mts" || ext == "cts" || ext == "tsx" {
                    &mut ts_parser
                } else {
                    &mut js_parser
                };

                extract_imports_ts(parser, &content, &rel_path, &mut packages, &mut locations);
            } else if ext == "svelte" || ext == "vue" {
                // Extract <script> block and parse as JS/TS
                if let Some(script_content) = extract_script_block(&content) {
                    let script_has_ts =
                        content.contains("lang=\"ts\"") || content.contains("lang='ts'");
                    let parser = if script_has_ts {
                        &mut ts_parser
                    } else {
                        &mut js_parser
                    };
                    extract_imports_ts(
                        parser,
                        &script_content,
                        &rel_path,
                        &mut packages,
                        &mut locations,
                    );
                }
            }
        }
    }

    // Also scan root-level config files (svelte.config.js, vite.config.ts, etc.)
    for config_file in &[
        "svelte.config.js",
        "vite.config.ts",
        "vite.config.js",
        "next.config.js",
        "next.config.ts",
        "tailwind.config.js",
        "tailwind.config.ts",
        "vitest.config.ts",
    ] {
        let path = root.join(config_file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let is_ts = config_file.ends_with(".ts");
            let parser = if is_ts {
                &mut ts_parser
            } else {
                &mut js_parser
            };
            // Config file imports are build-time, but we include them for completeness
            extract_imports_ts(parser, &content, config_file, &mut packages, &mut locations);
        }
    }

    AppImports {
        packages,
        locations,
    }
}

/// Extract package imports from JS/TS using tree-sitter
fn extract_imports_ts(
    parser: &mut Parser,
    content: &str,
    file_path: &str,
    packages: &mut HashSet<String>,
    locations: &mut HashMap<String, Vec<(String, usize)>>,
) {
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return,
    };

    let source = content.as_bytes();

    // Query for ES imports: import X from 'package'
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
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == module_idx) {
                let module = cap.node.utf8_text(source).unwrap_or("");
                if let Some(pkg) = extract_package_from_module(module) {
                    let line = cap.node.start_position().row + 1;
                    packages.insert(pkg.clone());
                    locations
                        .entry(pkg)
                        .or_default()
                        .push((file_path.to_string(), line));
                }
            }
        }
    }

    // Query for CommonJS requires: const X = require('package')
    let require_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (identifier) @fn
          arguments: (arguments (string (string_fragment) @module))
          (#eq? @fn "require"))
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
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == module_idx) {
                let module = cap.node.utf8_text(source).unwrap_or("");
                if let Some(pkg) = extract_package_from_module(module) {
                    let line = cap.node.start_position().row + 1;
                    packages.insert(pkg.clone());
                    locations
                        .entry(pkg)
                        .or_default()
                        .push((file_path.to_string(), line));
                }
            }
        }
    }

    // Query for dynamic imports: import('package')
    let dynamic_query = Query::new(
        &tree.language(),
        r#"
        (call_expression
          function: (import)
          arguments: (arguments (string (string_fragment) @module)))
        "#,
    );

    if let Ok(query) = dynamic_query {
        let module_idx = query
            .capture_names()
            .iter()
            .position(|n| *n == "module")
            .unwrap();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index as usize == module_idx) {
                let module = cap.node.utf8_text(source).unwrap_or("");
                if let Some(pkg) = extract_package_from_module(module) {
                    let line = cap.node.start_position().row + 1;
                    packages.insert(pkg.clone());
                    locations
                        .entry(pkg)
                        .or_default()
                        .push((file_path.to_string(), line));
                }
            }
        }
    }
}

/// Convert a module specifier to a package name.
/// "lodash" → "lodash"
/// "@scope/pkg" → "@scope/pkg"
/// "@scope/pkg/sub/path" → "@scope/pkg"
/// "./relative" → None (local import)
/// "fs" → "fs" (builtin, but we include it)
fn extract_package_from_module(module: &str) -> Option<String> {
    if module.starts_with('.') || module.starts_with('/') {
        return None; // Relative or absolute path
    }
    if module.starts_with('$') {
        return None; // SvelteKit alias ($lib, $app, etc.)
    }

    let parts: Vec<&str> = module.split('/').collect();
    if parts[0].starts_with('@') && parts.len() >= 2 {
        Some(format!("{}/{}", parts[0], parts[1]))
    } else {
        Some(parts[0].to_string())
    }
}

/// Extract the content of <script> tags from Svelte/Vue files
fn extract_script_block(content: &str) -> Option<String> {
    let mut scripts = String::new();

    let mut remaining = content;
    while let Some(start) = remaining.find("<script") {
        let after_tag = &remaining[start..];
        if let Some(close_bracket) = after_tag.find('>') {
            let script_start = start + close_bracket + 1;
            if let Some(end) = remaining[script_start..].find("</script>") {
                scripts.push_str(&remaining[script_start..script_start + end]);
                scripts.push('\n');
                remaining = &remaining[script_start + end + 9..];
                continue;
            }
        }
        break;
    }

    if scripts.is_empty() {
        None
    } else {
        Some(scripts)
    }
}

/// Read devDependencies from package.json
fn read_dev_dependencies(root: &Path) -> HashSet<String> {
    let pkg_json = root.join("package.json");
    let mut dev_deps = HashSet::new();

    if let Ok(content) = std::fs::read_to_string(&pkg_json) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(deps) = parsed["devDependencies"].as_object() {
                for key in deps.keys() {
                    dev_deps.insert(key.clone());
                }
            }
        }
    }

    dev_deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_from_module() {
        assert_eq!(extract_package_from_module("lodash"), Some("lodash".into()));
        assert_eq!(
            extract_package_from_module("@scope/pkg"),
            Some("@scope/pkg".into())
        );
        assert_eq!(
            extract_package_from_module("@scope/pkg/sub/path"),
            Some("@scope/pkg".into())
        );
        assert_eq!(extract_package_from_module("./relative"), None);
        assert_eq!(extract_package_from_module("../parent"), None);
        assert_eq!(extract_package_from_module("$lib/utils"), None);
    }

    #[test]
    fn test_extract_script_block() {
        let svelte = r#"
<script lang="ts">
  import { onMount } from 'svelte';
  import { db } from '$lib/db';
</script>

<h1>Hello</h1>

<script context="module">
  import { load } from '@sveltejs/kit';
</script>
"#;
        let scripts = extract_script_block(svelte).unwrap();
        assert!(scripts.contains("import { onMount }"));
        assert!(scripts.contains("import { load }"));
    }

    #[test]
    fn test_extract_script_block_no_script() {
        let html = "<h1>Hello</h1>";
        assert!(extract_script_block(html).is_none());
    }

    #[test]
    fn test_extract_imports_from_js() {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();

        let mut packages = HashSet::new();
        let mut locations = HashMap::new();

        let code = r#"
import { createClient } from '@supabase/supabase-js';
import lodash from 'lodash';
const fs = require('fs');
import('./dynamic-package');
import './relative-file';
"#;

        extract_imports_ts(&mut parser, code, "test.js", &mut packages, &mut locations);

        assert!(packages.contains("@supabase/supabase-js"));
        assert!(packages.contains("lodash"));
        assert!(packages.contains("fs"));
        assert!(!packages.contains("./relative-file"));
        // 3 confirmed: supabase, lodash, fs. Dynamic import may not be captured.
        assert!(packages.len() >= 3);
    }

    #[test]
    fn test_scan_app_imports_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let imports = scan_app_imports(dir.path());
        assert!(imports.packages.is_empty());
    }
}
