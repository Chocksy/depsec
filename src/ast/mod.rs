pub mod javascript;

use std::path::Path;

use tree_sitter::Parser;

use crate::checks::{Confidence, Severity};

/// Languages we can parse with tree-sitter
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Lang {
    JavaScript,
    TypeScript,
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

        Self {
            js_parser,
            ts_parser,
        }
    }

    /// Analyze a file for security patterns using AST.
    /// Returns findings for rules P001, P002, P008 with High confidence.
    pub fn analyze(&mut self, path: &Path, source: &str) -> Vec<AstFinding> {
        match detect_language(path) {
            Some(Lang::JavaScript) => javascript::analyze(&mut self.js_parser, source),
            Some(Lang::TypeScript) => javascript::analyze(&mut self.ts_parser, source),
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language_js() {
        assert_eq!(
            detect_language(Path::new("file.js")),
            Some(Lang::JavaScript)
        );
        assert_eq!(
            detect_language(Path::new("file.mjs")),
            Some(Lang::JavaScript)
        );
        assert_eq!(
            detect_language(Path::new("file.cjs")),
            Some(Lang::JavaScript)
        );
        assert_eq!(
            detect_language(Path::new("file.jsx")),
            Some(Lang::JavaScript)
        );
    }

    #[test]
    fn test_detect_language_ts() {
        assert_eq!(
            detect_language(Path::new("file.ts")),
            Some(Lang::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("file.tsx")),
            Some(Lang::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("file.mts")),
            Some(Lang::TypeScript)
        );
    }

    #[test]
    fn test_detect_language_unknown() {
        assert_eq!(detect_language(Path::new("file.py")), None);
        assert_eq!(detect_language(Path::new("file.rs")), None);
        assert_eq!(detect_language(Path::new("file.rb")), None);
        assert_eq!(detect_language(Path::new("file")), None);
    }

    #[test]
    fn test_ast_analyzer_new() {
        // Should not panic
        let _analyzer = AstAnalyzer::new();
    }
}
