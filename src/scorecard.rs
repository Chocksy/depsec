use crate::output::ScanReport;
use crate::scoring::Grade;

/// Category descriptions for the SVG scorecard
fn category_subtitle(name: &str) -> &'static str {
    match name.to_lowercase().as_str() {
        "workflows" => "Action pins, permissions, injection guards",
        "deps" => "OSV advisories, lockfile, known malware",
        "patterns" => "Malicious code patterns, obfuscation, exfil",
        "secrets" => "Hardcoded keys, tokens, credentials",
        "hygiene" => "SECURITY.md, .gitignore, branch protection",
        "capabilities" => "Dangerous capability combinations",
        _ => "",
    }
}

/// Generate an SVG scorecard image from scan results
pub fn generate_svg(report: &ScanReport) -> String {
    let grade_color = match report.grade {
        Grade::A => "#73daca",
        Grade::B => "#9ece6a",
        Grade::C => "#e0af68",
        Grade::D => "#ff9e64",
        Grade::F => "#f7768e",
    };

    let score_display = format!("{:.1}", report.total_score / 10.0);
    let font = "SF Mono, Menlo, Consolas, monospace";

    // ── Dimensions ──
    let width = 800;
    let padding = 32;
    let right_edge = width - padding;
    let bar_x = 200;
    let bar_max_w = 340;
    let pct_x = 560;
    let status_x = right_edge - 8; // right-aligned with padding from edge

    // Build category rows
    let categories: Vec<(String, u32, usize, String)> = report
        .results
        .iter()
        .map(|r| {
            let pct = if r.max_score > 0.0 {
                (r.score / r.max_score * 100.0).round() as u32
            } else {
                100
            };
            let name = capitalize(&r.category);
            let sub = category_subtitle(&r.category).to_string();
            (name, pct, r.findings.len(), sub)
        })
        .collect();

    let row_height = 44;
    let table_start_y = 160;
    let header_row_h = 28;

    let mut rows = String::new();
    for (i, (name, pct, findings, subtitle)) in categories.iter().enumerate() {
        let y = table_start_y + header_row_h + i * row_height;
        let text_y = y + 18;
        let sub_y = y + 32;
        let bar_y = y + 10;
        let bar_w = (*pct as f64 / 100.0 * bar_max_w as f64).round() as u32;

        let bar_fill = if *pct >= 90 {
            "url(#barCyan)"
        } else if *pct >= 75 {
            "url(#barGreen)"
        } else if *pct >= 60 {
            "#e0af68"
        } else {
            "#f7768e"
        };

        let status = if *findings > 0 {
            format!(
                "<text x=\"{status_x}\" y=\"{text_y}\" font-size=\"12\" fill=\"#f7768e\" \
                 font-family=\"{font}\" text-anchor=\"end\" font-weight=\"600\">{findings} issue{s}</text>",
                s = if *findings == 1 { "" } else { "s" },
            )
        } else {
            format!(
                "<text x=\"{status_x}\" y=\"{text_y}\" font-size=\"12\" fill=\"#73daca\" \
                 font-family=\"{font}\" text-anchor=\"end\">&#x2713; clean</text>",
            )
        };

        // Row separator
        if i > 0 {
            rows.push_str(&format!(
                "\n    <line x1=\"{padding}\" y1=\"{y}\" x2=\"{right_edge}\" y2=\"{y}\" stroke=\"#24283b\" stroke-width=\"1\"/>",
            ));
        }

        rows.push_str(&format!(
            "\n    <text x=\"{padding}\" y=\"{text_y}\" font-size=\"13\" fill=\"#c0caf5\" \
             font-family=\"{font}\" font-weight=\"600\">{name}</text>\
             \n    <text x=\"{padding}\" y=\"{sub_y}\" font-size=\"9\" fill=\"#414868\" \
             font-family=\"{font}\">{subtitle}</text>\
             \n    <rect x=\"{bar_x}\" y=\"{bar_y}\" width=\"{bar_max_w}\" height=\"8\" rx=\"4\" fill=\"#24283b\"/>\
             \n    <rect x=\"{bar_x}\" y=\"{bar_y}\" width=\"{bar_w}\" height=\"8\" rx=\"4\" fill=\"{bar_fill}\"/>\
             \n    <text x=\"{pct_x}\" y=\"{text_y}\" font-size=\"12\" fill=\"#a9b1d6\" \
             font-family=\"{font}\" font-weight=\"600\">{pct}%</text>\
             \n    {status}",
        ));
    }

    let total_height = table_start_y + header_row_h + categories.len() * row_height + 48;
    let footer_y = total_height - 32;
    let footer_text_y = total_height - 14;

    let mut svg = String::new();

    // ── SVG root ──
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{h}\" viewBox=\"0 0 {width} {h}\">\n",
        h = total_height,
    ));

    // ── Defs: gradients ──
    svg.push_str("  <defs>\n");
    svg.push_str("    <linearGradient id=\"barCyan\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"0\">\n");
    svg.push_str("      <stop offset=\"0%\" stop-color=\"#73daca\"/>\n");
    svg.push_str("      <stop offset=\"100%\" stop-color=\"#7dcfff\"/>\n");
    svg.push_str("    </linearGradient>\n");
    svg.push_str("    <linearGradient id=\"barGreen\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"0\">\n");
    svg.push_str("      <stop offset=\"0%\" stop-color=\"#9ece6a\"/>\n");
    svg.push_str("      <stop offset=\"100%\" stop-color=\"#73daca\"/>\n");
    svg.push_str("    </linearGradient>\n");
    svg.push_str("  </defs>\n");

    // ── Terminal window background ──
    svg.push_str(&format!(
        "  <rect width=\"{width}\" height=\"{h}\" rx=\"10\" fill=\"#1a1b26\"/>\n",
        h = total_height,
    ));

    // ── Title bar ──
    svg.push_str(&format!(
        "  <rect width=\"{width}\" height=\"36\" rx=\"10\" fill=\"#16161e\"/>\n",
    ));
    svg.push_str(&format!(
        "  <rect x=\"0\" y=\"26\" width=\"{width}\" height=\"10\" fill=\"#16161e\"/>\n",
    ));
    svg.push_str("  <circle cx=\"20\" cy=\"18\" r=\"6\" fill=\"#ff5f57\"/>\n");
    svg.push_str("  <circle cx=\"40\" cy=\"18\" r=\"6\" fill=\"#febc2e\"/>\n");
    svg.push_str("  <circle cx=\"60\" cy=\"18\" r=\"6\" fill=\"#28c840\"/>\n");
    svg.push_str(&format!(
        "  <text x=\"{mid}\" y=\"22\" font-size=\"12\" fill=\"#565f89\" font-family=\"{font}\" text-anchor=\"middle\">depsec scorecard</text>\n",
        mid = width / 2,
    ));

    // ── Header section ──
    svg.push_str(&format!(
        "  <text x=\"{padding}\" y=\"68\" font-size=\"10\" fill=\"#565f89\" font-family=\"{font}\" letter-spacing=\"3\">SUPPLY CHAIN SECURITY</text>\n",
    ));

    // Score: large grade letter + numeric
    svg.push_str(&format!(
        "  <text x=\"{padding}\" y=\"112\" font-size=\"42\" fill=\"{gc}\" font-family=\"{font}\" font-weight=\"700\">{grade}</text>\n",
        gc = grade_color,
        grade = report.grade,
    ));
    let score_x = padding + 48;
    svg.push_str(&format!(
        "  <text x=\"{score_x}\" y=\"100\" font-size=\"28\" fill=\"#c0caf5\" font-family=\"{font}\" font-weight=\"700\">{score}</text>\n",
        score = score_display,
    ));
    let slash_x = score_x + 80;
    svg.push_str(&format!(
        "  <text x=\"{slash_x}\" y=\"100\" font-size=\"14\" fill=\"#565f89\" font-family=\"{font}\">/10</text>\n",
    ));

    // Project info — right side of header
    let info_x = width / 2 + 60;
    let repo_display = report.repo_url.as_deref().unwrap_or(&report.project_name);
    svg.push_str(&format!(
        "  <text x=\"{info_x}\" y=\"75\" font-size=\"15\" fill=\"#c0caf5\" font-family=\"{font}\" font-weight=\"600\">{repo_display}</text>\n",
    ));
    svg.push_str(&format!(
        "  <text x=\"{info_x}\" y=\"95\" font-size=\"11\" fill=\"#565f89\" font-family=\"{font}\">v{version} &#183; Supply Chain Security Scanner</text>\n",
        version = report.version,
    ));
    svg.push_str(&format!(
        "  <text x=\"{info_x}\" y=\"115\" font-size=\"10\" fill=\"#414868\" font-family=\"{font}\">depsec.dev</text>\n",
    ));

    // ── Divider ──
    svg.push_str(&format!(
        "  <line x1=\"{padding}\" y1=\"135\" x2=\"{right_edge}\" y2=\"135\" stroke=\"#24283b\" stroke-width=\"1\"/>\n",
    ));

    // ── Table header ──
    let th_y = table_start_y;
    svg.push_str(&format!(
        "  <rect x=\"{padding}\" y=\"{th_y}\" width=\"{tw}\" height=\"{header_row_h}\" rx=\"4\" fill=\"#16161e\"/>\n",
        tw = width - 2 * padding,
    ));
    let th_text_y = th_y + 18;
    svg.push_str(&format!(
        "  <text x=\"{padding_inner}\" y=\"{th_text_y}\" font-size=\"10\" fill=\"#565f89\" font-family=\"{font}\" letter-spacing=\"1\">CHECK</text>\n",
        padding_inner = padding + 8,
    ));
    svg.push_str(&format!(
        "  <text x=\"{bar_x}\" y=\"{th_text_y}\" font-size=\"10\" fill=\"#565f89\" font-family=\"{font}\" letter-spacing=\"1\">PROGRESS</text>\n",
    ));
    svg.push_str(&format!(
        "  <text x=\"{pct_x}\" y=\"{th_text_y}\" font-size=\"10\" fill=\"#565f89\" font-family=\"{font}\" letter-spacing=\"1\">SCORE</text>\n",
    ));
    svg.push_str(&format!(
        "  <text x=\"{status_x}\" y=\"{th_text_y}\" font-size=\"10\" fill=\"#565f89\" font-family=\"{font}\" letter-spacing=\"1\" text-anchor=\"end\">STATUS</text>\n",
    ));

    // ── Category rows ──
    svg.push_str(&rows);
    svg.push('\n');

    // ── Footer ──
    svg.push_str(&format!(
        "  <line x1=\"{padding}\" y1=\"{footer_y}\" x2=\"{right_edge}\" y2=\"{footer_y}\" stroke=\"#24283b\" stroke-width=\"1\"/>\n",
    ));
    svg.push_str(&format!(
        "  <text x=\"{padding}\" y=\"{footer_text_y}\" font-size=\"10\" fill=\"#414868\" font-family=\"{font}\">depsec.dev</text>\n",
    ));
    svg.push_str(&format!(
        "  <text x=\"{right_edge}\" y=\"{footer_text_y}\" font-size=\"10\" fill=\"#414868\" font-family=\"{font}\" text-anchor=\"end\">Own your supply chain</text>\n",
    ));

    svg.push_str("</svg>");
    svg
}

fn capitalize(s: &str) -> String {
    crate::utils::capitalize(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_svg_empty_report() {
        let report = ScanReport::new("test-project".into(), vec![]);
        let svg = generate_svg(&report);
        assert!(svg.contains("SUPPLY CHAIN SECURITY"));
        assert!(svg.contains("test-project"));
        assert!(svg.contains("depsec.dev"));
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        // Width should be 800
        assert!(svg.contains("width=\"800\""));
    }

    #[test]
    fn test_generate_svg_with_results() {
        use crate::checks::{CheckResult, Finding, Severity};

        let findings = vec![Finding::new("TEST-001", Severity::High, "test")];
        let results = vec![
            CheckResult::new("workflows", vec![], 25.0, vec![]),
            CheckResult::new("deps", findings, 20.0, vec![]),
            CheckResult::new("capabilities", vec![], 10.0, vec![]),
        ];
        let report = ScanReport::new("my-app".into(), results);
        let svg = generate_svg(&report);
        assert!(svg.contains("Workflows"));
        assert!(svg.contains("Deps"));
        assert!(svg.contains("Capabilities"));
        assert!(svg.contains("100%"));
        assert!(svg.contains("1 issue"));
        assert!(svg.contains("clean"));
    }

    #[test]
    fn test_svg_category_subtitles() {
        assert!(!category_subtitle("workflows").is_empty());
        assert!(!category_subtitle("deps").is_empty());
        assert!(!category_subtitle("patterns").is_empty());
        assert!(!category_subtitle("secrets").is_empty());
        assert!(!category_subtitle("hygiene").is_empty());
        assert!(!category_subtitle("capabilities").is_empty());
    }
}
