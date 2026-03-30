use crate::output::ScanReport;
use crate::scoring::Grade;

/// Generate an SVG scorecard image from scan results
pub fn generate_svg(report: &ScanReport) -> String {
    let grade_color = match report.grade {
        Grade::A => "#22c55e",
        Grade::B => "#84cc16",
        Grade::C => "#eab308",
        Grade::D => "#f97316",
        Grade::F => "#ef4444",
    };

    let score_display = format!("{:.1}", report.total_score / 10.0);
    let font = "system-ui, -apple-system, sans-serif";

    // Build category rows
    let mut rows = String::new();
    let categories: Vec<(String, u32, usize)> = report
        .results
        .iter()
        .map(|r| {
            let pct = if r.max_score > 0.0 {
                (r.score / r.max_score * 100.0).round() as u32
            } else {
                100
            };
            (capitalize(&r.category), pct, r.findings.len())
        })
        .collect();

    let row_height = 32;
    let start_y = 120;

    for (i, (name, pct, findings)) in categories.iter().enumerate() {
        let y = start_y + i * row_height;
        let label_y = y + 16;
        let bar_y = y + 6;
        let bar_width = (*pct as f64 * 1.8).round() as u32;
        let bar_color = if *pct >= 90 {
            "#22c55e"
        } else if *pct >= 75 {
            "#84cc16"
        } else if *pct >= 60 {
            "#eab308"
        } else {
            "#ef4444"
        };

        let status = if *findings > 0 {
            let s = if *findings == 1 { "" } else { "s" };
            format!(
                "<text x=\"440\" y=\"{}\" font-size=\"11\" fill=\"#94a3b8\" text-anchor=\"end\">{} finding{}</text>",
                label_y, findings, s
            )
        } else {
            format!(
                "<text x=\"440\" y=\"{}\" font-size=\"11\" fill=\"#4ade80\" text-anchor=\"end\">&#x2713; clean</text>",
                label_y
            )
        };

        rows.push_str(&format!(
            "\n    <text x=\"20\" y=\"{ly}\" font-size=\"13\" fill=\"#e2e8f0\" font-weight=\"500\">{name}</text>\
            \n    <rect x=\"160\" y=\"{by}\" width=\"180\" height=\"12\" rx=\"6\" fill=\"#1e293b\"/>\
            \n    <rect x=\"160\" y=\"{by}\" width=\"{bw}\" height=\"12\" rx=\"6\" fill=\"{bc}\"/>\
            \n    <text x=\"350\" y=\"{ly}\" font-size=\"12\" fill=\"#cbd5e1\" font-weight=\"600\">{pct}%</text>\
            \n    {status}",
            ly = label_y,
            by = bar_y,
            name = name,
            bw = bar_width,
            bc = bar_color,
            pct = pct,
            status = status,
        ));
    }

    let total_height = start_y + categories.len() * row_height + 50;
    let footer_y = total_height - 35;
    let footer_text_y = total_height - 18;

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"480\" height=\"{h}\" viewBox=\"0 0 480 {h}\">\n",
        h = total_height
    ));

    // Background
    svg.push_str("  <defs>\n");
    svg.push_str("    <linearGradient id=\"bg\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\">\n");
    svg.push_str("      <stop offset=\"0%\" stop-color=\"#0f172a\"/>\n");
    svg.push_str("      <stop offset=\"100%\" stop-color=\"#1e293b\"/>\n");
    svg.push_str("    </linearGradient>\n");
    svg.push_str("  </defs>\n");
    svg.push_str(&format!(
        "  <rect width=\"480\" height=\"{h}\" rx=\"16\" fill=\"url(#bg)\"/>\n",
        h = total_height
    ));
    svg.push_str(&format!(
        "  <rect width=\"480\" height=\"{h}\" rx=\"16\" fill=\"none\" stroke=\"#334155\" stroke-width=\"1\"/>\n",
        h = total_height
    ));

    // Header
    svg.push_str(&format!(
        "  <text x=\"20\" y=\"35\" font-size=\"14\" fill=\"#94a3b8\" font-family=\"{font}\" font-weight=\"400\">DEPSEC SCORECARD</text>\n"
    ));
    svg.push_str(&format!(
        "  <text x=\"20\" y=\"80\" font-size=\"48\" fill=\"{gc}\" font-family=\"{font}\" font-weight=\"700\">{score}</text>\n",
        gc = grade_color,
        score = score_display,
    ));
    svg.push_str(&format!(
        "  <text x=\"115\" y=\"65\" font-size=\"16\" fill=\"#64748b\" font-family=\"{font}\">/10</text>\n"
    ));
    svg.push_str(&format!(
        "  <text x=\"115\" y=\"82\" font-size=\"14\" fill=\"{gc}\" font-family=\"{font}\" font-weight=\"600\">Grade {grade}</text>\n",
        gc = grade_color,
        grade = report.grade,
    ));

    // Project info
    svg.push_str(&format!(
        "  <text x=\"260\" y=\"55\" font-size=\"13\" fill=\"#94a3b8\" font-family=\"{font}\">{project}</text>\n",
        project = report.project_name,
    ));
    svg.push_str(&format!(
        "  <text x=\"260\" y=\"75\" font-size=\"11\" fill=\"#64748b\" font-family=\"{font}\">v{version} &#183; Supply Chain Security</text>\n",
        version = report.version,
    ));

    // Divider
    svg.push_str("  <line x1=\"20\" y1=\"100\" x2=\"460\" y2=\"100\" stroke=\"#334155\" stroke-width=\"1\"/>\n");

    // Rows
    svg.push_str(&rows);
    svg.push('\n');

    // Footer
    svg.push_str(&format!(
        "  <line x1=\"20\" y1=\"{fy}\" x2=\"460\" y2=\"{fy}\" stroke=\"#334155\" stroke-width=\"1\"/>\n",
        fy = footer_y,
    ));
    svg.push_str(&format!(
        "  <text x=\"20\" y=\"{fty}\" font-size=\"10\" fill=\"#475569\" font-family=\"{font}\">github.com/chocksy/depsec</text>\n",
        fty = footer_text_y,
    ));
    svg.push_str(&format!(
        "  <text x=\"460\" y=\"{fty}\" font-size=\"10\" fill=\"#475569\" font-family=\"{font}\" text-anchor=\"end\">Own your security</text>\n",
        fty = footer_text_y,
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
        assert!(svg.contains("DEPSEC SCORECARD"));
        assert!(svg.contains("test-project"));
        assert!(svg.contains("Grade A"));
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
    }

    #[test]
    fn test_generate_svg_with_results() {
        use crate::checks::{CheckResult, Finding, Severity};

        let findings = vec![Finding {
            rule_id: "TEST-001".into(),
            severity: Severity::High,
            message: "test".into(),
            file: None,
            line: None,
            suggestion: None,
            confidence: None,
            package: None,
            reachable: None,
            auto_fixable: false,
        }];
        let results = vec![
            CheckResult::new("workflows", vec![], 25.0, vec![]),
            CheckResult::new("deps", findings, 20.0, vec![]),
        ];
        let report = ScanReport::new("my-app".into(), results);
        let svg = generate_svg(&report);
        assert!(svg.contains("Workflows"));
        assert!(svg.contains("Deps"));
        assert!(svg.contains("100%"));
        assert!(svg.contains("1 finding"));
    }
}
