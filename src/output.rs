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
        "DEPSEC-P013" => RuleInfo { name: "Dynamic Require", narrative: "Calls require() with a variable, function call, or computed expression instead of a string literal. This hides the actual module being loaded, defeating static analysis. The #1 evasion technique in npm malware." },
        "DEPSEC-P014" => RuleInfo { name: "String Deobfuscation", narrative: "Uses String.fromCharCode combined with XOR or bitwise operations to decode hidden strings at runtime. This is the primary obfuscation technique in npm malware like the axios/plain-crypto-js attack." },
        "DEPSEC-P015" => RuleInfo { name: "Anti-Forensic File Operations", narrative: "Deletes its own source file or replaces package.json after execution to destroy evidence. The axios/plain-crypto-js attack deleted setup.js and renamed package.md to package.json to appear clean after infection." },
        "DEPSEC-P017" => RuleInfo { name: "Code Obfuscation", narrative: "Uses patterns common in JavaScript obfuscators: hex-prefixed function names (_0x...), while(!![]) infinite loops, or dynamic global property access via Buffer.from." },
        "DEPSEC-P018" => RuleInfo { name: "Typosquat Install Hook", narrative: "Typosquatted package name combined with install-time execution. Low download count packages with postinstall hooks that run shell commands." },
        "DEPSEC-P019" => RuleInfo { name: "Shadowed Builtin", narrative: "Overrides a Node.js builtin module name with a local file. This can trick require() into loading attacker-controlled code instead of the real builtin." },
        "DEPSEC-P020" => RuleInfo { name: "Python Dynamic Execution", narrative: "Calls eval(), exec(), or compile() in Python. These execute arbitrary code at runtime. If the argument comes from user input or external data, this enables Remote Code Execution." },
        "DEPSEC-P021" => RuleInfo { name: "Subprocess Shell Injection", narrative: "Uses subprocess.Popen/call/run with shell=True. When combined with user-controlled input, this allows command injection via shell metacharacters." },
        "DEPSEC-P022" => RuleInfo { name: "OS Command Execution", narrative: "Calls os.system() or os.popen() which execute commands through the system shell. These are deprecated in favor of subprocess and are more vulnerable to injection." },
        "DEPSEC-P023" => RuleInfo { name: "Dynamic Module Import", narrative: "Uses __import__() to dynamically load a module at runtime. When the module name is computed from variables, this can be used to load attacker-controlled code." },
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
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
            repo_url: None,
            results,
            total_score,
            grade,
        }
    }

    pub fn with_repo_url(mut self, root: &std::path::Path) -> Self {
        self.repo_url = crate::utils::detect_repo_url(root);
        self
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

        // Special collapsed rendering for deps category
        if result.category == "deps" && !result.findings.is_empty() && !verbose {
            render_deps_summary(&mut out, &result.findings, use_color, dim, reset);
            continue;
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
            // Aggregate mode: group by package, split by reachability
            let mut runtime_pkgs: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
            let mut build_pkgs: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
            let mut no_package: Vec<&Finding> = Vec::new();

            for f in &visible {
                match &f.package {
                    Some(pkg) => {
                        if f.reachable == Some(true) {
                            runtime_pkgs.entry(pkg.clone()).or_default().push(f);
                        } else {
                            build_pkgs.entry(pkg.clone()).or_default().push(f);
                        }
                    }
                    None => no_package.push(f),
                }
            }

            // Render non-packaged findings individually
            for finding in &no_package {
                render_finding(&mut out, finding, use_color);
            }

            let red = if use_color { "\x1b[31m" } else { "" };
            let green = if use_color { "\x1b[32m" } else { "" };

            // Runtime findings — prominent
            if !runtime_pkgs.is_empty() {
                let runtime_count: usize = runtime_pkgs.values().map(|v| v.len()).sum();
                out.push_str(&format!(
                    "\n  {red}ACTION REQUIRED{reset} — {count} finding{s} in {pkg_count} package{ps} your app imports:\n\n",
                    count = runtime_count,
                    s = if runtime_count == 1 { "" } else { "s" },
                    pkg_count = runtime_pkgs.len(),
                    ps = if runtime_pkgs.len() == 1 { "" } else { "s" },
                ));

                for (pkg, findings) in &runtime_pkgs {
                    render_package_aggregate(&mut out, pkg, findings, use_color, dim, reset);
                }
            }

            // Build-only findings — collapsed
            if !build_pkgs.is_empty() {
                let build_count: usize = build_pkgs.values().map(|v| v.len()).sum();
                let pkg_names: Vec<&str> = build_pkgs.keys().map(|s| s.as_str()).collect();

                out.push_str(&format!(
                    "\n  {green}BUILD TOOLS{reset} — {count} finding{s} in {pkg_count} package{ps} not imported by your app:\n",
                    count = build_count,
                    s = if build_count == 1 { "" } else { "s" },
                    pkg_count = build_pkgs.len(),
                    ps = if build_pkgs.len() == 1 { "" } else { "s" },
                ));

                // Show just package names, collapsed
                let display_names: Vec<&str> = pkg_names.iter().take(8).copied().collect();
                let more = if pkg_names.len() > 8 {
                    format!(", +{} more", pkg_names.len() - 8)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "    {dim}{}{more}{reset}\n",
                    display_names.join(", "),
                ));
                out.push_str(&format!(
                    "    {dim}These run during build/dev only, not in production (use --verbose for details){reset}\n",
                ));
            }

            // If neither runtime nor build had findings, show pass
            if runtime_pkgs.is_empty() && build_pkgs.is_empty() && no_package.is_empty() {
                out.push_str(&format!("  {green}✓{reset} No suspicious patterns found\n",));
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
        repo_url: report.repo_url.clone(),
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

fn render_deps_summary(
    out: &mut String,
    findings: &[Finding],
    use_color: bool,
    dim: &str,
    reset: &str,
) {
    let total = findings.len();
    let malware = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("DEPSEC-MAL"))
        .count();
    let cves = total - malware;

    let icon = if findings.iter().any(|f| {
        f.severity == Severity::Critical
            || f.severity == Severity::High
            || f.rule_id.starts_with("DEPSEC-MAL")
    }) {
        if use_color {
            "\x1b[31m✗\x1b[0m"
        } else {
            "✗"
        }
    } else if use_color {
        "\x1b[33m⚠\x1b[0m"
    } else {
        "⚠"
    };

    if malware > 0 {
        let red = if use_color { "\x1b[31m" } else { "" };
        out.push_str(&format!(
            "  {icon} {red}MALWARE: {malware} malicious package{s} — REMOVE IMMEDIATELY{reset}\n",
            s = if malware == 1 { "" } else { "s" },
        ));
    }

    // Group by package for collapsed view
    let mut by_package: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        let pkg = f
            .package
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        by_package.entry(pkg).or_default().push(f);
    }

    let unique_pkgs = by_package.len();
    out.push_str(&format!(
        "  {icon} {cves} known vulnerabilit{ies} across {unique_pkgs} package{ps}\n",
        ies = if cves == 1 { "y" } else { "ies" },
        ps = if unique_pkgs == 1 { "" } else { "s" },
    ));

    // Show top packages by severity (max 8, then collapse)
    let mut sorted_pkgs: Vec<(&String, &Vec<&Finding>)> = by_package.iter().collect();
    sorted_pkgs.sort_by(|a, b| {
        let max_a = a.1.iter().map(|f| f.severity).max().unwrap_or(Severity::Low);
        let max_b = b.1.iter().map(|f| f.severity).max().unwrap_or(Severity::Low);
        max_b.cmp(&max_a).then(b.1.len().cmp(&a.1.len()))
    });

    let show_count = sorted_pkgs.len().min(8);
    for (pkg, pkg_findings) in sorted_pkgs.iter().take(show_count) {
        let count = pkg_findings.len();
        let max_sev = pkg_findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Low);
        let sev_label = match max_sev {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        };
        out.push_str(&format!(
            "    {dim}{pkg} — {count} {sev_label}{reset}\n",
        ));
    }

    if sorted_pkgs.len() > show_count {
        out.push_str(&format!(
            "    {dim}+{} more packages{reset}\n",
            sorted_pkgs.len() - show_count,
        ));
    }

    out.push_str(&format!(
        "    → Run {dim}npm audit fix{reset} or {dim}cargo audit{reset} to resolve\n"
    ));
    out.push_str(&format!(
        "    {dim}Use --verbose for full advisory list{reset}\n"
    ));
}

fn render_package_aggregate(
    out: &mut String,
    pkg: &str,
    findings: &[&Finding],
    use_color: bool,
    dim: &str,
    reset: &str,
) {
    let count = findings.len();
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Low);

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

    let mut rules: Vec<String> = findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(rule_label)
        .collect();
    rules.sort();

    out.push_str(&format!(
        "  {icon} {pkg} — {count} finding{s} ({rules})\n",
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
    crate::utils::capitalize(s)
}

/// Count visible terminal columns, ignoring ANSI escape sequences.
fn visual_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            len += 1;
        }
    }
    len
}

fn render_ascii_scorecard(report: &ScanReport, use_color: bool) -> String {
    let bar_width = 20;
    let inner_width = 46; // chars between the two │ borders
    let border = "─".repeat(inner_width);

    let (cyan, green, yellow, red, dim, bold, reset) = if use_color {
        (
            "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[90m", "\x1b[1m", "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    let grade_color = match report.grade {
        Grade::A | Grade::B => cyan,
        Grade::C | Grade::D => yellow,
        Grade::F => red,
    };

    let bar_color_for = |pct: u32| -> &str {
        if pct >= 90 {
            cyan
        } else if pct >= 60 {
            yellow
        } else {
            red
        }
    };

    // Helper: wrap inner content in a box row, right-padding to inner_width
    let box_row = |content: &str| -> String {
        let vis = visual_len(content);
        let pad = inner_width.saturating_sub(vis);
        format!("{dim}│{reset}{content}{}{dim}│{reset}\n", " ".repeat(pad))
    };

    let mut out = String::new();

    // ── Top border ──
    out.push_str(&format!("{dim}┌{border}┐{reset}\n"));

    // ── Title row: " DEPSEC SCORECARD          7.8/10 B " ──
    let score_str = format!("{:.1}/10", report.total_score / 10.0);
    let grade_str = format!("{}", report.grade);
    let title = "DEPSEC SCORECARD";
    let left = format!(" {bold}{title}{reset}");
    let right = format!("{grade_color}{bold}{score_str}{reset} {grade_color}{grade_str}{reset} ");
    let left_vis = 1 + title.len(); // space + title
    let right_vis = score_str.len() + 1 + grade_str.len() + 1; // score + space + grade + space
    let gap = inner_width.saturating_sub(left_vis + right_vis);
    out.push_str(&box_row(&format!("{left}{}{right}", " ".repeat(gap))));

    // ── Separator ──
    out.push_str(&format!("{dim}├{border}┤{reset}\n"));

    // ── Category rows ──
    for result in &report.results {
        let pct = if result.max_score > 0.0 {
            (result.score / result.max_score * 100.0).round() as u32
        } else {
            100
        };

        let filled = (pct as usize * bar_width) / 100;
        let empty = bar_width - filled;
        let bc = bar_color_for(pct);

        let bar = format!(
            "{bc}{}{dim}{}{reset}",
            "█".repeat(filled),
            "░".repeat(empty),
        );

        let name = capitalize(&result.category);
        let name_pad = 12usize.saturating_sub(name.len());

        let status = if result.findings.is_empty() {
            format!("{green}✓{reset}")
        } else {
            format!("{red}{}{reset}", result.findings.len())
        };

        // Build row content with known visual widths
        let content = format!(" {name}{} {bar} {pct:>3}% {status} ", " ".repeat(name_pad),);
        out.push_str(&box_row(&content));
    }

    // ── Bottom border ──
    out.push_str(&format!("{dim}└{border}┘{reset}\n"));

    // ── Grading scale ──
    out.push_str(&format!(
        "\n{dim}Grading scale:{reset}  {cyan}A{reset} 90-100  {cyan}B{reset} 75-89  {yellow}C{reset} 60-74  {yellow}D{reset} 40-59  {red}F{reset} 0-39\n",
    ));

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

    #[test]
    fn test_rule_info_known() {
        let info = rule_info("DEPSEC-P001").unwrap();
        assert_eq!(info.name, "Shell Execution");
        assert!(!info.narrative.is_empty());
    }

    #[test]
    fn test_rule_info_unknown() {
        assert!(rule_info("UNKNOWN-RULE").is_none());
    }

    #[test]
    fn test_rule_label_known() {
        let label = rule_label("DEPSEC-P001");
        assert_eq!(label, "P001: Shell Execution");
    }

    #[test]
    fn test_rule_label_unknown() {
        let label = rule_label("DEPSEC-X999");
        assert_eq!(label, "X999");
    }

    #[test]
    fn test_finding_passes_persona_no_confidence() {
        let finding = Finding::new("DEPSEC-W001", Severity::High, "test");
        // No confidence → always visible
        assert!(finding_passes_persona(&finding, Persona::Regular));
        assert!(finding_passes_persona(&finding, Persona::Pedantic));
        assert!(finding_passes_persona(&finding, Persona::Auditor));
    }

    #[test]
    fn test_finding_passes_persona_high_confidence() {
        let finding =
            Finding::new("DEPSEC-P001", Severity::High, "test").with_confidence(Confidence::High);
        assert!(finding_passes_persona(&finding, Persona::Regular));
        assert!(finding_passes_persona(&finding, Persona::Pedantic));
        assert!(finding_passes_persona(&finding, Persona::Auditor));
    }

    #[test]
    fn test_finding_passes_persona_low_confidence() {
        let finding =
            Finding::new("DEPSEC-P001", Severity::High, "test").with_confidence(Confidence::Low);
        assert!(!finding_passes_persona(&finding, Persona::Regular));
        assert!(!finding_passes_persona(&finding, Persona::Pedantic));
        assert!(finding_passes_persona(&finding, Persona::Auditor));
    }

    #[test]
    fn test_finding_passes_persona_medium_confidence() {
        let finding =
            Finding::new("DEPSEC-P001", Severity::High, "test").with_confidence(Confidence::Medium);
        assert!(!finding_passes_persona(&finding, Persona::Regular));
        assert!(finding_passes_persona(&finding, Persona::Pedantic));
        assert!(finding_passes_persona(&finding, Persona::Auditor));
    }

    #[test]
    fn test_render_human_with_findings() {
        let findings = vec![Finding::new("DEPSEC-P001", Severity::High, "exec() call")
            .with_file("node_modules/evil/index.js", 5)
            .with_confidence(Confidence::High)
            .with_package_name("evil")];
        let results = vec![
            CheckResult::new("patterns", findings, 25.0, vec![]),
            CheckResult::new("workflows", vec![], 25.0, vec!["All pinned".into()]),
        ];
        let report = ScanReport::new("test-app".into(), results);
        let output = render_human(&report, false, Persona::Regular, false);
        assert!(output.contains("test-app"));
        // Finding is rendered with rule label (P001: Shell Execution), not raw message
        assert!(output.contains("Shell Execution") || output.contains("P001"));
        assert!(output.contains("All pinned"));
    }

    #[test]
    fn test_render_human_verbose_shows_low_confidence() {
        let findings = vec![
            Finding::new("DEPSEC-P001", Severity::High, "low conf finding")
                .with_confidence(Confidence::Low),
        ];
        let results = vec![CheckResult::new("patterns", findings, 25.0, vec![])];
        let report = ScanReport::new("test".into(), results);

        // Regular persona, no verbose — low confidence should be hidden
        let _output_regular = render_human(&report, false, Persona::Regular, false);
        // Verbose — should show all
        let output_verbose = render_human(&report, false, Persona::Regular, true);

        // The verbose output should include the finding; regular may not render it in findings section
        assert!(output_verbose.contains("low conf finding"));
    }

    #[test]
    fn test_finding_visible_api() {
        let high = Finding::new("X", Severity::High, "t").with_confidence(Confidence::High);
        let low = Finding::new("X", Severity::High, "t").with_confidence(Confidence::Low);
        assert!(finding_visible(&high, Persona::Regular));
        assert!(!finding_visible(&low, Persona::Regular));
        assert!(finding_visible(&low, Persona::Auditor));
    }

    #[test]
    fn test_scorecard_alignment_no_color() {
        let results = vec![
            CheckResult::new("patterns", vec![], 25.0, vec![]),
            CheckResult::new("workflows", vec![], 25.0, vec![]),
            CheckResult::new("secrets", vec![], 25.0, vec![]),
        ];
        let report = ScanReport::new("test".into(), results);
        let scorecard = render_ascii_scorecard(&report, false);

        // Every line inside the box must start with │ and end with │,
        // and all lines must be the same visual width.
        let box_lines: Vec<&str> = scorecard
            .lines()
            .filter(|l| {
                l.starts_with('┌') || l.starts_with('│') || l.starts_with('├') || l.starts_with('└')
            })
            .collect();

        assert!(box_lines.len() >= 5, "Expected at least 5 box lines");

        let widths: Vec<usize> = box_lines.iter().map(|l| l.chars().count()).collect();
        let first = widths[0];
        for (i, w) in widths.iter().enumerate() {
            assert_eq!(
                *w, first,
                "Line {i} width {w} != expected {first}: {:?}",
                box_lines[i]
            );
        }
    }

    #[test]
    fn test_scorecard_alignment_with_color() {
        let findings =
            vec![Finding::new("DEPSEC-P001", Severity::High, "test")
                .with_confidence(Confidence::High)];
        let results = vec![
            CheckResult::new("patterns", findings, 25.0, vec![]),
            CheckResult::new("workflows", vec![], 25.0, vec![]),
            CheckResult::new("capabilities", vec![], 25.0, vec![]),
        ];
        let report = ScanReport::new("test".into(), results);
        let scorecard = render_ascii_scorecard(&report, true);

        // Strip ANSI codes and verify all box lines have the same visual width
        let box_lines: Vec<&str> = scorecard
            .lines()
            .filter(|l| {
                let stripped: String = l.chars().filter(|c| !c.is_ascii_control()).collect();
                stripped.contains('┌')
                    || stripped.contains('│')
                    || stripped.contains('├')
                    || stripped.contains('└')
            })
            .collect();

        let vis_widths: Vec<usize> = box_lines.iter().map(|l| visual_len(l)).collect();
        let first = vis_widths[0];
        for (i, w) in vis_widths.iter().enumerate() {
            assert_eq!(
                *w, first,
                "Colored line {i} visual width {w} != expected {first}"
            );
        }
    }

    #[test]
    fn test_visual_len_strips_ansi() {
        assert_eq!(visual_len("hello"), 5);
        assert_eq!(visual_len("\x1b[32mhello\x1b[0m"), 5);
        assert_eq!(visual_len("\x1b[1m\x1b[36mAB\x1b[0m"), 2);
        assert_eq!(visual_len(""), 0);
    }
}
