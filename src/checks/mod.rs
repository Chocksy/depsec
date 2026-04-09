pub mod capabilities;
pub mod deps;
pub mod hygiene;
pub mod patterns;
pub mod secrets;
pub mod workflows;

use std::path::Path;

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    #[allow(dead_code)]
    pub fn deduction_multiplier(&self) -> f64 {
        match self {
            Severity::Critical => 3.0,
            Severity::High => 2.0,
            Severity::Medium => 1.0,
            Severity::Low => 0.3,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Whether this finding's package is imported by the app at runtime
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    pub auto_fixable: bool,
}

impl Finding {
    /// Create a new Finding with required fields. Optional fields default to None/false.
    pub fn new(rule_id: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            confidence: None,
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
            package: None,
            reachable: None,
            auto_fixable: false,
        }
    }

    pub fn with_file(mut self, file: impl Into<String>, line: usize) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self
    }

    pub fn with_file_only(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    /// Human-readable label for grouping: package name, or a meaningful fallback
    /// derived from the rule category or file path. Never returns "unknown".
    pub fn display_label(&self) -> String {
        if let Some(ref pkg) = self.package {
            return pkg.clone();
        }
        // Derive from rule_id prefix
        match self.rule_id.as_str() {
            r if r.starts_with("DEPSEC-W") => {
                // Workflow findings: use the workflow file name
                if let Some(ref file) = self.file {
                    return format!("workflow:{}", file.rsplit('/').next().unwrap_or(file));
                }
                "workflows".into()
            }
            r if r.starts_with("DEPSEC-S") => "secrets".into(),
            r if r.starts_with("DEPSEC-H") => "hygiene".into(),
            r if r.starts_with("DEPSEC-V") => "dependencies".into(),
            r if r.starts_with("DEPSEC-CAP") => "capabilities".into(),
            _ => {
                // Last resort: use file path
                if let Some(ref file) = self.file {
                    file.clone()
                } else {
                    "project".into()
                }
            }
        }
    }

    pub fn with_package(mut self, package: Option<String>) -> Self {
        self.package = package;
        self
    }

    #[cfg(test)]
    pub fn with_package_name(mut self, package: impl Into<String>) -> Self {
        self.package = Some(package.into());
        self
    }

    pub fn auto_fixable(mut self) -> Self {
        self.auto_fixable = true;
        self
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    pub category: String,
    pub findings: Vec<Finding>,
    pub score: f64,
    pub max_score: f64,
    pub pass_messages: Vec<String>,
}

impl CheckResult {
    pub fn new(
        category: impl Into<String>,
        findings: Vec<Finding>,
        max_score: f64,
        pass_messages: Vec<String>,
    ) -> Self {
        let score = crate::scoring::compute_category_score(max_score, &findings);
        Self {
            category: category.into(),
            findings,
            score,
            max_score,
            pass_messages,
        }
    }
}

pub struct ScanContext<'a> {
    pub root: &'a Path,
    pub config: &'a Config,
}

pub trait Check {
    fn name(&self) -> &str;
    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult>;
}
