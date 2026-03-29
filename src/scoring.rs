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
    if findings.is_empty() {
        return max_points;
    }

    let num_checks = findings.len() as f64;
    let base_deduction = max_points / (num_checks + 1.0);

    let total_deduction: f64 = findings
        .iter()
        .map(|f| base_deduction * f.severity.deduction_multiplier())
        .sum();

    (max_points - total_deduction).max(0.0)
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
        let findings = vec![Finding {
            rule_id: "TEST-001".into(),
            severity: Severity::High,
            message: "test".into(),
            file: None,
            line: None,
            suggestion: None,
            confidence: None,
            package: None,
            auto_fixable: false,
        }];
        let score = compute_category_score(25.0, &findings);
        assert!(score < 25.0);
        assert!(score >= 0.0);
    }
}
