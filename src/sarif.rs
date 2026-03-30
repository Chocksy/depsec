use crate::checks::Severity;
use crate::output::ScanReport;

/// Generate SARIF 2.1.0 JSON from a scan report
pub fn render_sarif(report: &ScanReport) -> anyhow::Result<String> {
    let mut rules = Vec::new();
    let mut results = Vec::new();
    let mut rule_ids_seen = std::collections::HashSet::new();

    for check_result in &report.results {
        for finding in &check_result.findings {
            // Add rule definition (deduplicated)
            if rule_ids_seen.insert(finding.rule_id.clone()) {
                rules.push(serde_json::json!({
                    "id": finding.rule_id,
                    "shortDescription": {
                        "text": finding.message.chars().take(100).collect::<String>()
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(&finding.severity)
                    }
                }));
            }

            // Add result
            let mut result = serde_json::json!({
                "ruleId": finding.rule_id,
                "level": severity_to_sarif_level(&finding.severity),
                "message": {
                    "text": finding.message
                }
            });

            // Add location if available
            if let Some(ref file) = finding.file {
                let mut region = serde_json::Map::new();
                if let Some(line) = finding.line {
                    region.insert("startLine".into(), serde_json::json!(line));
                }

                result["locations"] = serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file
                        },
                        "region": region
                    }
                }]);
            }

            // Add fix suggestion
            if let Some(ref suggestion) = finding.suggestion {
                result["fixes"] = serde_json::json!([{
                    "description": {
                        "text": suggestion
                    }
                }]);
            }

            results.push(result);
        }
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "depsec",
                    "version": report.version,
                    "informationUri": "https://github.com/chocksy/depsec",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_empty_report() {
        let report = ScanReport::new("test".into(), vec![]);
        let sarif = render_sarif(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "depsec");
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_sarif_with_findings() {
        use crate::checks::{CheckResult, Finding};

        let findings = vec![
            Finding::new("DEPSEC-W001", Severity::High, "Unpinned action")
                .with_file(".github/workflows/ci.yml", 10)
                .with_suggestion("Pin to SHA")
                .auto_fixable(),
        ];

        let results = vec![CheckResult::new("workflows", findings, 25.0, vec![])];
        let report = ScanReport::new("test".into(), results);
        let sarif = render_sarif(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "DEPSEC-W001");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".github/workflows/ci.yml"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            10
        );
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
    }
}
