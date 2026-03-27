use anyhow::Context;

use crate::checks::{Check, CheckResult, Finding, ScanContext, Severity};
use crate::parsers::{self, Package};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_BATCH_SIZE: usize = 1000;
const OSV_TIMEOUT_SECS: u64 = 30;

pub struct DepsCheck;

impl Check for DepsCheck {
    fn name(&self) -> &str {
        "deps"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("deps") as f64;

        // Parse all lockfiles
        let lockfile_results = parsers::parse_all_lockfiles(ctx.root, 3);

        if lockfile_results.is_empty() {
            return Ok(CheckResult::new(
                "deps",
                vec![],
                max_score,
                vec!["No lockfiles found".into()],
            ));
        }

        let mut all_packages: Vec<Package> = Vec::new();
        let mut lockfile_names: Vec<String> = Vec::new();

        for (name, pkgs) in &lockfile_results {
            lockfile_names.push(name.clone());
            all_packages.extend(pkgs.iter().cloned());
        }

        // Deduplicate
        let packages = parsers::deduplicate(all_packages);
        let package_count = packages.len();

        // Check lockfile committed (not in .gitignore)
        let mut findings = Vec::new();
        check_lockfile_committed(ctx, &lockfile_names, &mut findings);

        // Query OSV for vulnerabilities
        let mut pass_messages = vec![format!(
            "Lockfile{} found: {}",
            if lockfile_names.len() > 1 { "s" } else { "" },
            lockfile_names.join(", ")
        )];

        match query_osv_batch(&packages) {
            Ok(vulns) => {
                if vulns.is_empty() {
                    pass_messages.push(format!(
                        "0 known vulnerabilities ({package_count} packages checked via OSV)"
                    ));
                } else {
                    for vuln in vulns {
                        findings.push(vuln);
                    }
                }
            }
            Err(e) => {
                // OSV API failure is a hard error
                anyhow::bail!("OSV API query failed: {e}");
            }
        }

        Ok(CheckResult::new("deps", findings, max_score, pass_messages))
    }
}

fn check_lockfile_committed(ctx: &ScanContext, lockfiles: &[String], findings: &mut Vec<Finding>) {
    // Check if lockfiles are gitignored
    for lockfile in lockfiles {
        let output = std::process::Command::new("git")
            .args(["check-ignore", "-q", lockfile])
            .current_dir(ctx.root)
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                // File IS ignored by git
                findings.push(Finding {
                    rule_id: "DEPSEC-D001".into(),
                    severity: Severity::High,
                    message: format!("Lockfile {lockfile} is gitignored — should be committed"),
                    file: Some(lockfile.clone()),
                    line: None,
                    suggestion: Some("Remove lockfile from .gitignore and commit it".into()),
                    auto_fixable: false,
                });
            }
        }
    }
}

#[derive(serde::Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(serde::Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(serde::Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

fn query_osv_batch(packages: &[Package]) -> anyhow::Result<Vec<Finding>> {
    if packages.is_empty() {
        return Ok(vec![]);
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(OSV_TIMEOUT_SECS))
        .timeout_write(std::time::Duration::from_secs(OSV_TIMEOUT_SECS))
        .user_agent("depsec")
        .build();

    let mut all_findings = Vec::new();

    // Process in batches
    for chunk in packages.chunks(OSV_BATCH_SIZE) {
        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|p| OsvQuery {
                version: p.version.clone(),
                package: OsvPackage {
                    name: p.name.clone(),
                    ecosystem: p.ecosystem.osv_name().to_string(),
                },
            })
            .collect();

        let batch = OsvBatchQuery { queries };

        let resp = agent
            .post(OSV_BATCH_URL)
            .send_json(serde_json::to_value(&batch)?)
            .context("OSV API request failed")?;

        let body: serde_json::Value = resp.into_json().context("Failed to parse OSV response")?;

        if let Some(results) = body.get("results").and_then(|r| r.as_array()) {
            for (i, result) in results.iter().enumerate() {
                let pkg = &chunk[i];

                if let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        let id = vuln["id"].as_str().unwrap_or("UNKNOWN");
                        let summary = vuln["summary"].as_str().unwrap_or("No summary available");
                        let is_malware = id.starts_with("MAL-");

                        let severity = if is_malware {
                            Severity::Critical
                        } else {
                            determine_severity(vuln)
                        };

                        let rule_id = if is_malware {
                            format!("DEPSEC-MAL:{id}")
                        } else {
                            format!("DEPSEC-V:{id}")
                        };

                        let message = if is_malware {
                            format!(
                                "KNOWN MALICIOUS PACKAGE: {} {} — {summary}",
                                pkg.name, pkg.version
                            )
                        } else {
                            format!("{}: {} {} — {summary}", severity, pkg.name, pkg.version)
                        };

                        let suggestion = if is_malware {
                            format!(
                                "REMOVE {} IMMEDIATELY — this package is confirmed malware",
                                pkg.name
                            )
                        } else if let Some(fix) = extract_fix_version(vuln, &pkg.ecosystem) {
                            format!("Upgrade {} to >= {fix}", pkg.name)
                        } else {
                            format!("Review advisory {id} for remediation steps")
                        };

                        all_findings.push(Finding {
                            rule_id,
                            severity,
                            message,
                            file: None,
                            line: None,
                            suggestion: Some(suggestion),
                            auto_fixable: false,
                        });
                    }
                }
            }
        }
    }

    Ok(all_findings)
}

fn determine_severity(vuln: &serde_json::Value) -> Severity {
    // Try CVSS score from database_specific or severity array
    if let Some(severity_arr) = vuln.get("severity").and_then(|s| s.as_array()) {
        for sev in severity_arr {
            if let Some(score_str) = sev.get("score").and_then(|s| s.as_str()) {
                // CVSS vector string — extract base score
                if let Some(score) = extract_cvss_score(score_str) {
                    return cvss_to_severity(score);
                }
            }
        }
    }

    // Fallback: check ecosystem severity from database_specific
    if let Some(db) = vuln.get("database_specific") {
        if let Some(sev) = db.get("severity").and_then(|s| s.as_str()) {
            return match sev.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MODERATE" | "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Medium,
            };
        }
    }

    // Default
    Severity::Medium
}

fn extract_cvss_score(vector: &str) -> Option<f64> {
    // Try bare float first
    if let Ok(score) = vector.parse::<f64>() {
        return Some(score);
    }

    // Parse CVSS:3.x vector string — extract base score from metrics
    // The score isn't embedded in the vector string itself, so we approximate
    // from the impact metrics: AV (Attack Vector), AC (Attack Complexity),
    // PR (Privileges Required), UI (User Interaction), S (Scope),
    // C (Confidentiality), I (Integrity), A (Availability)
    if vector.starts_with("CVSS:") {
        let mut score = 5.0; // baseline

        if vector.contains("AV:N") {
            score += 1.5; // Network attack vector
        }
        if vector.contains("AC:L") {
            score += 0.5; // Low complexity
        }
        if vector.contains("PR:N") {
            score += 0.5; // No privileges needed
        }
        if vector.contains("C:H") {
            score += 1.0; // High confidentiality impact
        }
        if vector.contains("I:H") {
            score += 0.5; // High integrity impact
        }
        if vector.contains("A:H") {
            score += 0.5; // High availability impact
        }

        return Some(if score > 10.0 { 10.0 } else { score });
    }

    None
}

fn cvss_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn extract_fix_version(
    vuln: &serde_json::Value,
    _ecosystem: &parsers::Ecosystem,
) -> Option<String> {
    // Try to find a fixed version from the "affected" array
    if let Some(affected) = vuln.get("affected").and_then(|a| a.as_array()) {
        for entry in affected {
            if let Some(ranges) = entry.get("ranges").and_then(|r| r.as_array()) {
                for range in ranges {
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        for event in events {
                            if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                                return Some(fixed.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(cvss_to_severity(9.5), Severity::Critical);
        assert_eq!(cvss_to_severity(9.0), Severity::Critical);
        assert_eq!(cvss_to_severity(7.0), Severity::High);
        assert_eq!(cvss_to_severity(8.9), Severity::High);
        assert_eq!(cvss_to_severity(4.0), Severity::Medium);
        assert_eq!(cvss_to_severity(3.9), Severity::Low);
    }

    #[test]
    fn test_determine_severity_default() {
        let vuln = serde_json::json!({});
        assert_eq!(determine_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn test_determine_severity_from_database() {
        let vuln = serde_json::json!({
            "database_specific": {
                "severity": "HIGH"
            }
        });
        assert_eq!(determine_severity(&vuln), Severity::High);
    }

    #[test]
    fn test_extract_fix_version() {
        let vuln = serde_json::json!({
            "affected": [{
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.0.1"}
                    ]
                }]
            }]
        });
        let fix = extract_fix_version(&vuln, &parsers::Ecosystem::Npm);
        assert_eq!(fix, Some("2.0.1".to_string()));
    }
}
