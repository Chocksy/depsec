use crate::checks::{CheckResult, Severity};
use crate::scoring::{compute_grade, compute_total_score, Grade};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanReport {
    pub version: String,
    pub project_name: String,
    pub results: Vec<CheckResult>,
    pub total_score: f64,
    pub grade: Grade,
}

impl ScanReport {
    pub fn new(project_name: String, results: Vec<CheckResult>) -> Self {
        let total_score = compute_total_score(&results);
        let grade = compute_grade(total_score);
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            project_name,
            results,
            total_score,
            grade,
        }
    }
}

pub fn render_human(report: &ScanReport, use_color: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "depsec v{} — Supply Chain Security Scanner\n\n",
        report.version
    ));
    out.push_str(&format!("Project: {}\n", report.project_name));
    out.push_str(&format!(
        "Grade: {} ({:.1}/10)\n",
        format_grade(&report.grade, use_color),
        report.total_score / 10.0,
    ));

    for result in &report.results {
        out.push('\n');
        out.push_str(&format!("[{}]\n", capitalize(&result.category)));

        for msg in &result.pass_messages {
            out.push_str(&format!(
                "  {} {}\n",
                if use_color {
                    "\x1b[32m✓\x1b[0m"
                } else {
                    "✓"
                },
                msg
            ));
        }

        for finding in &result.findings {
            let icon = match finding.severity {
                Severity::Critical | Severity::High => {
                    if use_color {
                        "\x1b[31m✗\x1b[0m"
                    } else {
                        "✗"
                    }
                }
                Severity::Medium | Severity::Low => {
                    if use_color {
                        "\x1b[33m⚠\x1b[0m"
                    } else {
                        "⚠"
                    }
                }
            };

            let location = match (&finding.file, finding.line) {
                (Some(f), Some(l)) => format!(" ({f}:{l})"),
                (Some(f), None) => format!(" ({f})"),
                _ => String::new(),
            };

            out.push_str(&format!("  {} {}{}\n", icon, finding.message, location));

            if let Some(suggestion) = &finding.suggestion {
                out.push_str(&format!("    → {suggestion}\n"));
            }
        }
    }

    let fixable_count = report
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.auto_fixable)
        .count();

    if fixable_count > 0 {
        out.push_str(&format!(
            "\nRun 'depsec fix' to auto-fix {} issue{}.\n",
            fixable_count,
            if fixable_count == 1 { "" } else { "s" }
        ));
    }

    // ASCII scorecard
    out.push('\n');
    out.push_str(&render_ascii_scorecard(report, use_color));

    out
}

pub fn render_json(report: &ScanReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn format_grade(grade: &Grade, use_color: bool) -> String {
    if !use_color {
        return grade.to_string();
    }
    let color = match grade {
        Grade::A => "\x1b[32m",
        Grade::B => "\x1b[32m",
        Grade::C => "\x1b[33m",
        Grade::D => "\x1b[33m",
        Grade::F => "\x1b[31m",
    };
    format!("{color}{grade}\x1b[0m")
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn render_ascii_scorecard(report: &ScanReport, use_color: bool) -> String {
    let bar_width = 20;
    let box_width = 52;
    let border = "─".repeat(box_width);

    let (green, yellow, red, dim, bold, reset) = if use_color {
        (
            "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[90m", "\x1b[1m", "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "")
    };

    let grade_color = match report.grade {
        Grade::A | Grade::B => green,
        Grade::C | Grade::D => yellow,
        Grade::F => red,
    };

    let mut out = String::new();

    // Top border
    out.push_str(&format!("{dim}┌{border}┐{reset}\n"));

    // Title + score
    let score_str = format!("{:.1}/10", report.total_score / 10.0);
    let title = "DEPSEC SCORECARD";
    let padding = box_width - title.len() - score_str.len() - 6;
    out.push_str(&format!(
        "{dim}│{reset} {bold}{title}{reset}{: <pad$}{grade_color}{bold}{score}{reset} {grade_color}{grade}{reset} {dim}│{reset}\n",
        "",
        pad = padding,
        title = title,
        score = score_str,
        grade = report.grade,
    ));

    // Separator
    out.push_str(&format!("{dim}├{border}┤{reset}\n"));

    // Category rows
    for result in &report.results {
        let pct = if result.max_score > 0.0 {
            (result.score / result.max_score * 100.0).round() as u32
        } else {
            100
        };

        let filled = (pct as usize * bar_width) / 100;
        let empty = bar_width - filled;
        let bar_color = if pct >= 90 {
            green
        } else if pct >= 60 {
            yellow
        } else {
            red
        };

        let bar = format!(
            "{bar_color}{}{dim}{}{reset}",
            "█".repeat(filled),
            "░".repeat(empty),
        );

        let name = capitalize(&result.category);
        let status = if result.findings.is_empty() {
            format!("{green}✓{reset}")
        } else {
            format!("{red}{}{reset}", result.findings.len())
        };

        out.push_str(&format!(
            "{dim}│{reset} {name:<12} {bar} {pct:>3}% {status:>3} {dim}│{reset}\n",
        ));
    }

    // Bottom border
    out.push_str(&format!("{dim}└{border}┘{reset}\n"));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_report_new() {
        let report = ScanReport::new("test-project".into(), vec![]);
        assert_eq!(report.grade, Grade::A);
        assert_eq!(report.total_score, 100.0);
        assert_eq!(report.project_name, "test-project");
    }

    #[test]
    fn test_render_human_empty() {
        let report = ScanReport::new("test-project".into(), vec![]);
        let output = render_human(&report, false);
        assert!(output.contains("test-project"));
        assert!(output.contains("Grade: A"));
    }

    #[test]
    fn test_render_json_valid() {
        let report = ScanReport::new("test-project".into(), vec![]);
        let json = render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["grade"], "A");
        assert_eq!(parsed["project_name"], "test-project");
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("workflows"), "Workflows");
        assert_eq!(capitalize("deps"), "Deps");
        assert_eq!(capitalize(""), "");
    }
}
