use std::collections::{BTreeMap, HashSet};

use crate::checks::{CheckResult, Confidence, Finding, Severity};
use crate::scoring::{compute_grade, compute_total_score, Grade};
use crate::Persona;

/// Rule metadata for the glossary and inline display
struct RuleInfo {
    name: &'static str,
    narrative: &'static str,
}

fn rule_info(rule_id: &str) -> Option<RuleInfo> {
    Some(match rule_id {
        "DEPSEC-P001" => RuleInfo { name: "Shell Execution", narrative: "Calls child_process.exec/spawn with variable arguments. If user-controlled, enables Remote Code Execution. Common in build tools where it's expected." },
        "DEPSEC-P002" => RuleInfo { name: "Encoded Execution", narrative: "Decodes base64/atob data and passes it to eval, exec, or Function. This is the #1 obfuscation pattern in npm malware. Legitimate uses are rare." },
        "DEPSEC-P003" => RuleInfo { name: "Raw IP Network Call", narrative: "Makes HTTP requests to a hardcoded IP address. Malware uses raw IPs to avoid DNS blocking. Could also be local dev/testing." },
        "DEPSEC-P004" => RuleInfo { name: "Credential Harvesting", narrative: "Reads files from ~/.ssh, ~/.aws, ~/.env, or ~/.gnupg. No legitimate package needs your credentials." },
        "DEPSEC-P005" => RuleInfo { name: "Steganographic Payload", narrative: "Reads binary files (.wav, .png, .ico) and extracts bytes. Known malware technique: hide payloads in media files." },
        "DEPSEC-P006" => RuleInfo { name: "Install Script Download", narrative: "Install script makes network calls. These run automatically during npm install with full system access." },
        "DEPSEC-P007" => RuleInfo { name: "Encoded Payload", narrative: "High-entropy string (>4.5 bits/char). Could be base64 data, crypto keys, or obfuscated code. Also common in compression tables." },
        "DEPSEC-P008" => RuleInfo { name: "Dynamic Code Construction", narrative: "Uses new Function() to create code from strings. Standard for template engines (ejs, pug). Dangerous if input is user-controlled." },
        "DEPSEC-P009" => RuleInfo { name: "Python Startup Injection", narrative: "A .pth file with executable code. Python .pth files run on every interpreter startup — a powerful malware persistence mechanism." },
        "DEPSEC-P010" => RuleInfo { name: "Cloud Credential Probing", narrative: "Accesses cloud instance metadata (169.254.169.254). IMDS provides IAM credentials. Could steal cloud credentials." },
        "DEPSEC-P011" => RuleInfo { name: "Environment Exfiltration", narrative: "Serializes process.env to JSON. Environment variables often contain API keys and secrets." },
        "DEPSEC-P012" => RuleInfo { name: "Suspicious Install Hook", narrative: "package.json install script contains suspicious commands. Install hooks run with full system access." },
        _ => return None,
    })
}

/// Get a short rule label like "P001: Shell Execution"
fn rule_label(rule_id: &str) -> String {
    let short = rule_id.strip_prefix("DEPSEC-").unwrap_or(rule_id);
    match rule_info(rule_id) {
        Some(info) => format!("{}: {}", short, info.name),
        None => short.to_string(),
    }
}

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

/// Check if a finding is visible under the given persona filter
pub fn finding_visible(finding: &Finding, persona: Persona) -> bool {
    finding_passes_persona(finding, persona)
}

fn finding_passes_persona(finding: &Finding, persona: Persona) -> bool {
    let min_confidence = match persona {
        Persona::Regular => Confidence::High,
        Persona::Pedantic => Confidence::Medium,
        Persona::Auditor => Confidence::Low,
    };

    match finding.confidence {
        // Findings without confidence (non-pattern checks) always pass
        None => true,
        Some(conf) => conf >= min_confidence,
    }
}

pub fn render_human(
    report: &ScanReport,
    use_color: bool,
    persona: Persona,
    verbose: bool,
) -> String {
    let mut out = String::new();

    // Recompute score with persona-filtered findings for a fair grade
    let filtered_results: Vec<CheckResult> = report
        .results
        .iter()
        .map(|r| {
            let filtered_findings: Vec<Finding> = r
                .findings
                .iter()
                .filter(|f| verbose || finding_passes_persona(f, persona))
                .cloned()
                .collect();
            CheckResult::new(
                r.category.clone(),
                filtered_findings,
                r.max_score,
                r.pass_messages.clone(),
            )
        })
        .collect();
    let filtered_score = compute_total_score(&filtered_results);
    let filtered_grade = compute_grade(filtered_score);

    out.push_str(&format!(
        "depsec v{} — Supply Chain Security Scanner\n\n",
        report.version
    ));
    out.push_str(&format!("Project: {}\n", report.project_name));
    out.push_str(&format!(
        "Grade: {} ({:.1}/10)\n",
        format_grade(&filtered_grade, use_color),
        filtered_score / 10.0,
    ));

    let dim = if use_color { "\x1b[90m" } else { "" };
    let reset = if use_color { "\x1b[0m" } else { "" };

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

        let mut hidden_count = 0usize;

        // Separate visible from hidden findings
        let visible: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|f| {
                if verbose || finding_passes_persona(f, persona) {
                    true
                } else {
                    hidden_count += 1;
                    false
                }
            })
            .collect();

        // Check if this category has package-able findings for aggregation
        let has_packages = visible.iter().any(|f| f.package.is_some());

        if !verbose && has_packages {
            // Aggregate mode: group by package
            let mut by_package: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
            let mut no_package: Vec<&Finding> = Vec::new();

            for f in &visible {
                match &f.package {
                    Some(pkg) => by_package.entry(pkg.clone()).or_default().push(f),
                    None => no_package.push(f),
                }
            }

            // Render non-packaged findings individually (workflows, hygiene, etc.)
            for finding in &no_package {
                render_finding(&mut out, finding, use_color);
            }

            // Render packaged findings aggregated
            for (pkg, findings) in &by_package {
                let count = findings.len();
                let max_severity = findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Low);
                let max_confidence = findings
                    .iter()
                    .filter_map(|f| f.confidence)
                    .max()
                    .unwrap_or(Confidence::Low);

                let icon = match max_severity {
                    Severity::Critical | Severity::High => {
                        if use_color {
                            "\x1b[31m✗\x1b[0m"
                        } else {
                            "✗"
                        }
                    }
                    _ => {
                        if use_color {
                            "\x1b[33m⚠\x1b[0m"
                        } else {
                            "⚠"
                        }
                    }
                };

                // Collect unique rule labels (e.g., "P001: Shell Execution")
                let mut rules: Vec<String> = findings
                    .iter()
                    .map(|f| f.rule_id.as_str())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .map(rule_label)
                    .collect();
                rules.sort();

                let conf_label = format!("{max_confidence:?}").to_lowercase();
                out.push_str(&format!(
                    "  {icon} {pkg} — {count} finding{s} ({rules}, confidence: {conf_label})\n",
                    s = if count == 1 { "" } else { "s" },
                    rules = rules.join(", "),
                ));

                // Show top 3 locations
                let top_locations: Vec<String> = findings
                    .iter()
                    .take(3)
                    .filter_map(|f| {
                        f.file.as_ref().map(|file| match f.line {
                            Some(l) => format!("{file}:{l}"),
                            None => file.clone(),
                        })
                    })
                    .collect();
                if !top_locations.is_empty() {
                    let more = if count > 3 {
                        format!(" +{} more", count - 3)
                    } else {
                        String::new()
                    };
                    out.push_str(&format!(
                        "    {dim}Top: {}{more}{reset}\n",
                        top_locations.join(", "),
                    ));
                }

                if let Some(suggestion) = &findings[0].suggestion {
                    out.push_str(&format!("    → {suggestion}\n"));
                }
            }
        } else {
            // Verbose mode or no packages: render individually
            for finding in &visible {
                render_finding(&mut out, finding, use_color);
            }
        }

        if hidden_count > 0 {
            let persona_hint = match persona {
                Persona::Regular => "--persona pedantic",
                Persona::Pedantic => "--persona auditor",
                Persona::Auditor => "--verbose",
            };
            out.push_str(&format!(
                "  {dim}+{hidden_count} hidden findings (use {persona_hint} to see){reset}\n"
            ));
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

    // ASCII scorecard — use filtered results for fair display
    let filtered_report = ScanReport {
        version: report.version.clone(),
        project_name: report.project_name.clone(),
        results: filtered_results,
        total_score: filtered_score,
        grade: filtered_grade,
    };
    out.push('\n');
    out.push_str(&render_ascii_scorecard(&filtered_report, use_color));

    // Rule glossary — only rules that triggered in this scan
    let glossary = render_rule_glossary(report, use_color);
    if !glossary.is_empty() {
        out.push('\n');
        out.push_str(&glossary);
    }

    out
}

fn render_rule_glossary(report: &ScanReport, use_color: bool) -> String {
    let dim = if use_color { "\x1b[90m" } else { "" };
    let bold = if use_color { "\x1b[1m" } else { "" };
    let reset = if use_color { "\x1b[0m" } else { "" };

    // Collect unique P-rule IDs that triggered
    let triggered_ids: HashSet<String> = report
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.rule_id.starts_with("DEPSEC-P"))
        .map(|f| f.rule_id.clone())
        .collect();

    let mut triggered: Vec<(String, RuleInfo)> = triggered_ids
        .into_iter()
        .filter_map(|id| rule_info(&id).map(|info| (id, info)))
        .collect();
    triggered.sort_by(|a, b| a.0.cmp(&b.0));

    if triggered.is_empty() {
        return String::new();
    }

    let mut out = format!("{bold}[Rule Guide]{reset}\n");

    for (rule_id, info) in triggered.iter() {
        let short = rule_id.strip_prefix("DEPSEC-").unwrap_or(rule_id);
        out.push_str(&format!("  {bold}{short}{reset}  {}\n", info.name));
        // Wrap narrative to ~72 chars with indent
        for line in wrap_text(info.narrative, 70) {
            out.push_str(&format!("  {dim}    {line}{reset}\n"));
        }
        out.push('\n');
    }

    out
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() > width {
            lines.push(current);
            current = word.to_string();
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub fn render_json(report: &ScanReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn render_finding(out: &mut String, finding: &Finding, use_color: bool) {
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
        let output = render_human(&report, false, Persona::Auditor, false);
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
