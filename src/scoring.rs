use crate::checks::CheckResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Grade::A => write!(f, "A"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::F => write!(f, "F"),
        }
    }
}

impl Grade {
    pub fn color_code(&self) -> &str {
        match self {
            Grade::A => "brightgreen",
            Grade::B => "green",
            Grade::C => "yellow",
            Grade::D => "orange",
            Grade::F => "red",
        }
    }
}

pub fn compute_grade(score: f64) -> Grade {
    if score >= 90.0 {
        Grade::A
    } else if score >= 75.0 {
        Grade::B
    } else if score >= 60.0 {
        Grade::C
    } else if score >= 40.0 {
        Grade::D
    } else {
        Grade::F
    }
}

pub fn compute_total_score(results: &[CheckResult]) -> f64 {
    let total_max: f64 = results.iter().map(|r| r.max_score).sum();
    if total_max == 0.0 {
        return 100.0;
    }
    let total_score: f64 = results.iter().map(|r| r.score).sum();
    (total_score / total_max * 100.0).round()
}

pub fn compute_category_score(max_points: f64, findings: &[crate::checks::Finding]) -> f64 {
    use crate::checks::Severity;

    if findings.is_empty() {
        return max_points;
    }

    let num_checks = findings.len() as f64;
    let base_deduction = max_points / (num_checks + 1.0);

    let has_high_or_critical = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High));

    // Sort findings by severity (Critical first) for deterministic scoring.
    // Without sorting, diminishing returns would vary based on finding order.
    let mut sorted: Vec<&crate::checks::Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Explicit loop (not .map()) for clarity — mutable counters track diminishing returns
    let mut medium_count = 0u32;
    let mut low_count = 0u32;
    let mut total_deduction = 0.0f64;

    for f in &sorted {
        let severity_mult = match f.severity {
            Severity::Critical => 3.0,
            Severity::High => 2.0,
            Severity::Medium => {
                medium_count += 1;
                // 1st medium = 1.0, 10th = 0.5, 20th = 0.33, etc.
                1.0 / (1.0 + (medium_count.saturating_sub(1) as f64 * 0.1))
            }
            Severity::Low => {
                low_count += 1;
                // Low starts lower and diminishes faster
                0.3 / (1.0 + (low_count.saturating_sub(1) as f64 * 0.15))
            }
        };

        // Build-only findings have heavily reduced impact
        let reachability_mult = match f.reachable {
            Some(false) => 0.1, // Build-only: minimal impact
            _ => 1.0,           // Runtime or unknown: standard impact
        };

        total_deduction += base_deduction * severity_mult * reachability_mult;
    }

    let raw_score = (max_points - total_deduction).max(0.0);

    // Floor: if no critical/high findings, score can't drop below 30% of max.
    // This prevents 68 medium advisories from tanking to 0%.
    let floor = if has_high_or_critical {
        0.0
    } else {
        max_points * 0.3
    };

    raw_score.max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Finding, Severity};

    #[test]
    fn test_grade_thresholds() {
        assert_eq!(compute_grade(100.0), Grade::A);
        assert_eq!(compute_grade(90.0), Grade::A);
        assert_eq!(compute_grade(89.9), Grade::B);
        assert_eq!(compute_grade(75.0), Grade::B);
        assert_eq!(compute_grade(74.9), Grade::C);
        assert_eq!(compute_grade(60.0), Grade::C);
        assert_eq!(compute_grade(59.9), Grade::D);
        assert_eq!(compute_grade(40.0), Grade::D);
        assert_eq!(compute_grade(39.9), Grade::F);
        assert_eq!(compute_grade(0.0), Grade::F);
    }

    #[test]
    fn test_total_score_no_results() {
        let results: Vec<CheckResult> = vec![];
        assert_eq!(compute_total_score(&results), 100.0);
    }

    #[test]
    fn test_total_score_perfect() {
        let results = vec![
            CheckResult {
                category: "workflows".into(),
                findings: vec![],
                score: 25.0,
                max_score: 25.0,
                pass_messages: vec![],
            },
            CheckResult {
                category: "secrets".into(),
                findings: vec![],
                score: 25.0,
                max_score: 25.0,
                pass_messages: vec![],
            },
        ];
        assert_eq!(compute_total_score(&results), 100.0);
    }

    #[test]
    fn test_category_score_no_findings() {
        assert_eq!(compute_category_score(25.0, &[]), 25.0);
    }

    #[test]
    fn test_category_score_with_findings() {
        let findings = vec![Finding::new("TEST-001", Severity::High, "test")];
        let score = compute_category_score(25.0, &findings);
        assert!(score < 25.0);
        assert!(score >= 0.0);
    }

    #[test]
    fn test_grade_display() {
        assert_eq!(Grade::A.to_string(), "A");
        assert_eq!(Grade::B.to_string(), "B");
        assert_eq!(Grade::C.to_string(), "C");
        assert_eq!(Grade::D.to_string(), "D");
        assert_eq!(Grade::F.to_string(), "F");
    }

    #[test]
    fn test_grade_color_code() {
        assert_eq!(Grade::A.color_code(), "brightgreen");
        assert_eq!(Grade::B.color_code(), "green");
        assert_eq!(Grade::C.color_code(), "yellow");
        assert_eq!(Grade::D.color_code(), "orange");
        assert_eq!(Grade::F.color_code(), "red");
    }

    #[test]
    fn test_category_score_build_only_reduced() {
        // Build-only finding should have less impact
        let mut finding = Finding::new("TEST-001", Severity::High, "test");
        finding.reachable = Some(false);
        let build_score = compute_category_score(25.0, &[finding]);

        let runtime_finding = Finding::new("TEST-001", Severity::High, "test");
        let runtime_score = compute_category_score(25.0, &[runtime_finding]);

        // Build-only should lose fewer points
        assert!(build_score > runtime_score);
    }

    #[test]
    fn test_category_score_multiple_severities() {
        let findings = vec![
            Finding::new("T1", Severity::Critical, "crit"),
            Finding::new("T2", Severity::Low, "low"),
        ];
        let score = compute_category_score(25.0, &findings);
        assert!(score >= 0.0);
        assert!(score < 25.0);
    }

    #[test]
    fn test_severity_deduction_multiplier() {
        assert_eq!(Severity::Critical.deduction_multiplier(), 3.0);
        assert_eq!(Severity::High.deduction_multiplier(), 2.0);
        assert_eq!(Severity::Medium.deduction_multiplier(), 1.0);
        assert_eq!(Severity::Low.deduction_multiplier(), 0.3);
    }

    #[test]
    fn test_total_score_partial() {
        let results = vec![CheckResult::new(
            "test",
            vec![Finding::new("T1", Severity::Low, "minor issue")],
            25.0,
            vec![],
        )];
        let score = compute_total_score(&results);
        assert!(score < 100.0);
        assert!(score > 0.0);
    }
}
