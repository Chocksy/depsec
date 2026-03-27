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
    pub fn deduction_multiplier(&self) -> f64 {
        match self {
            Severity::Critical => 3.0,
            Severity::High => 2.0,
            Severity::Medium => 1.0,
            Severity::Low => 0.5,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    pub auto_fixable: bool,
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
