use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::checks::Finding;
use crate::config::TriageConfig;
use crate::llm::TokenUsage;
use crate::triage_cache;
use crate::triage_prefilter::{self, Choice, DecisionApi};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub classification: Classification,
    pub confidence: f64,
    pub reasoning: String,
    pub recommendation: String,
    /// Which stage produced the verdict
    #[serde(default)]
    pub stage: Stage,
    /// API cost in USD for this finding (all stages combined)
    #[serde(default)]
    pub cost_usd: f64,
    /// Wall-clock API latency in milliseconds (all stages combined)
    #[serde(default)]
    pub latency_ms: u64,
}

/// The stage that decided a finding.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Scanner-verified, no model needed
    Deterministic,
    /// Cleared by the cheap d1 prefilter
    Prefilter,
    /// Decided by the full LLM
    #[default]
    Llm,
    /// Served from the local triage cache
    Cache,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Stage::Deterministic => "deterministic",
            Stage::Prefilter => "prefilter",
            Stage::Llm => "llm",
            Stage::Cache => "cache",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Classification {
    #[serde(rename = "TP")]
    TruePositive,
    #[serde(rename = "FP")]
    FalsePositive,
    #[serde(rename = "NI")]
    NeedsInvestigation,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Classification::TruePositive => write!(f, "TRUE POSITIVE"),
            Classification::FalsePositive => write!(f, "FALSE POSITIVE"),
            Classification::NeedsInvestigation => write!(f, "NEEDS INVESTIGATION"),
        }
    }
}

/// Dry run: show what would be sent to d1 without making API calls
pub fn dry_run_findings(findings: &[Finding], root: &Path, config: &TriageConfig) {
    let mut total_chars = 0usize;
    let mut n = 0usize;
    for finding in findings.iter() {
        if n >= config.max_findings {
            break;
        }
        if is_deterministic_true_positive(finding)
            || triage_prefilter::is_protected(finding, &config.prefilter_always_llm)
        {
            continue;
        }
        let Some(state) =
            triage_prefilter::build_state(finding, root, config.prefilter_snippet_lines)
        else {
            continue;
        };
        n += 1;
        total_chars += state.len();
        eprintln!(
            "--- {} {} ({} chars) ---",
            finding.display_label(),
            finding.rule_id,
            state.len()
        );
    }
    let est_tokens = total_chars / 4;
    eprintln!(
        "Total: {n} findings to d1, ~{est_tokens} input tokens, ~${:.5} estimated",
        est_tokens as f64 / 1_000_000.0 * triage_prefilter::D1_ULTRA_INPUT_PER_M
    );
}

/// Run triage on a set of findings using the LLM
/// Findings that are always TRUE POSITIVE by definition — no LLM judgment needed.
/// These are deterministic: the scanner already verified the condition with certainty.
fn is_deterministic_true_positive(finding: &Finding) -> bool {
    let rid = finding.rule_id.as_str();
    // Workflow issues: action not pinned, permissions missing — binary check, always real
    rid.starts_with("DEPSEC-W")
        // Known vulnerabilities from advisory databases — always real
        || rid.starts_with("DEPSEC-V")
        // Hygiene issues: lockfile missing, outdated — always real
        || rid.starts_with("DEPSEC-H")
}

/// Auto-resolve a deterministic finding without calling the LLM.
fn auto_resolve(finding: &Finding) -> TriageResult {
    let category = if finding.rule_id.starts_with("DEPSEC-W") {
        "workflow security"
    } else if finding.rule_id.starts_with("DEPSEC-V") {
        "known vulnerability"
    } else {
        "project hygiene"
    };
    TriageResult {
        classification: Classification::TruePositive,
        confidence: 1.0,
        reasoning: format!("Deterministic {category} finding — no LLM review needed"),
        recommendation: finding
            .suggestion
            .clone()
            .unwrap_or_else(|| "Review and fix".into()),
        stage: Stage::Deterministic,
        cost_usd: 0.0,
        latency_ms: 0,
    }
}

/// d1-only triage (no expensive LLM tier).
///
/// - Deterministic findings are auto-resolved as before.
/// - Protected rule families (malware, typosquat, advisories, secrets, install
///   scripts, ...) are never sent to d1 and never suppressed: they are reported
///   as NEEDS INVESTIGATION for a human.
/// - Everything else gets one d1 Choice. Only FP at P >= prefilter_fp_threshold
///   (default 0.95) is marked FALSE POSITIVE. A TP answer is reported as TP;
///   FP below the bar, UNSURE and API errors are NEEDS INVESTIGATION.
pub fn triage_findings_d1(
    findings: &[Finding],
    root: &Path,
    d1: &dyn DecisionApi,
    config: &TriageConfig,
) -> Vec<(usize, TriageResult, TokenUsage)> {
    let mut results = Vec::new();
    let mut considered = 0usize;
    for (idx, finding) in findings.iter().enumerate() {
        if is_deterministic_true_positive(finding) {
            results.push((idx, auto_resolve(finding), TokenUsage::default()));
            continue;
        }
        if considered >= config.max_findings {
            break;
        }
        considered += 1;
        if triage_prefilter::is_protected(finding, &config.prefilter_always_llm) {
            results.push((
                idx,
                needs_review(
                    finding,
                    0.0,
                    0.0,
                    0,
                    "Protected rule family: never auto-triaged, review manually",
                ),
                TokenUsage::default(),
            ));
            continue;
        }
        if let Some(mut cached) = triage_cache::get_cached(finding, root, config.cache_ttl_days) {
            cached.stage = Stage::Cache;
            cached.cost_usd = 0.0;
            cached.latency_ms = 0;
            results.push((idx, cached, TokenUsage::default()));
            continue;
        }
        let Some(state) =
            triage_prefilter::build_state(finding, root, config.prefilter_snippet_lines)
        else {
            continue;
        };
        let start = std::time::Instant::now();
        let result = match d1.decide(&state) {
            Ok(d) => {
                let ms = start.elapsed().as_millis() as u64;
                let classification = if d.clears(config.prefilter_fp_threshold) {
                    Classification::FalsePositive
                } else if d.choice == Choice::TruePositive {
                    Classification::TruePositive
                } else {
                    Classification::NeedsInvestigation
                };
                TriageResult {
                    classification,
                    confidence: d.confidence,
                    reasoning: format!(
                        "{} answered {:?} at {:.1}% (FP bar {:.0}%)",
                        d1.model(),
                        d.choice,
                        d.confidence * 100.0,
                        config.prefilter_fp_threshold * 100.0
                    ),
                    recommendation: match classification {
                        Classification::FalsePositive => "Likely false positive".into(),
                        _ => "Review this finding".into(),
                    },
                    stage: Stage::Prefilter,
                    cost_usd: d.cost_usd,
                    latency_ms: ms,
                }
            }
            Err(e) => {
                eprintln!("  d1 failed for {}: {e}", finding.rule_id);
                needs_review(
                    finding,
                    0.0,
                    0.0,
                    start.elapsed().as_millis() as u64,
                    "d1 call failed",
                )
            }
        };
        let _ = triage_cache::set_cached(finding, root, &result);
        results.push((idx, result, TokenUsage::default()));
    }
    results
}

fn needs_review(_f: &Finding, confidence: f64, cost: f64, ms: u64, why: &str) -> TriageResult {
    TriageResult {
        classification: Classification::NeedsInvestigation,
        confidence,
        reasoning: why.into(),
        recommendation: "Review this finding".into(),
        stage: Stage::Deterministic,
        cost_usd: cost,
        latency_ms: ms,
    }
}

/// Render triage results for human output
pub fn render_triage_results(
    findings: &[Finding],
    results: &[(usize, TriageResult, TokenUsage)],
    use_color: bool,
) -> String {
    let mut out = String::new();

    let (green, yellow, red, dim, bold, reset) = if use_color {
        (
            "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[90m", "\x1b[1m", "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "")
    };

    out.push_str(&format!("\n{bold}[LLM Triage Results]{reset}\n"));

    let mut total_tokens = 0u32;
    let mut tp_count = 0;
    let mut fp_count = 0;
    let mut ni_count = 0;

    for (idx, result, usage) in results {
        let finding = &findings[*idx];
        total_tokens += usage.total_tokens;

        let (icon, label) = match result.classification {
            Classification::TruePositive => {
                tp_count += 1;
                (
                    format!("{red}✗{reset}"),
                    format!("{red}TRUE POSITIVE{reset}"),
                )
            }
            Classification::FalsePositive => {
                fp_count += 1;
                (
                    format!("{green}✓{reset}"),
                    format!("{green}FALSE POSITIVE{reset}"),
                )
            }
            Classification::NeedsInvestigation => {
                ni_count += 1;
                (
                    format!("{yellow}~{reset}"),
                    format!("{yellow}NEEDS INVESTIGATION{reset}"),
                )
            }
        };

        let location = match (&finding.file, finding.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f.clone(),
            _ => "?".into(),
        };

        let conf_label = if result.confidence >= 0.8 {
            format!("{:.0}%", result.confidence * 100.0)
        } else {
            format!("{dim}{:.0}%{reset}", result.confidence * 100.0)
        };

        out.push_str(&format!(
            "  {icon} {label} ({conf_label}) {dim}[{}]{reset}: {} — {}\n",
            result.stage,
            finding.package.as_deref().unwrap_or("?"),
            finding.rule_id,
        ));
        out.push_str(&format!(
            "    {dim}{location} · ${:.5} · {}ms{reset}\n",
            result.cost_usd, result.latency_ms
        ));
        out.push_str(&format!("    → {}\n", result.recommendation));
    }

    out.push_str(&format!(
        "\n  {dim}Summary: {tp_count} true positive, {fp_count} false positive, {ni_count} needs investigation{reset}\n"
    ));

    let count_stage = |s: Stage| results.iter().filter(|(_, r, _)| r.stage == s).count();
    out.push_str(&format!(
        "  {dim}Stages: {} deterministic, {} prefilter, {} llm, {} cache{reset}\n",
        count_stage(Stage::Deterministic),
        count_stage(Stage::Prefilter),
        count_stage(Stage::Llm),
        count_stage(Stage::Cache),
    ));

    let total_cost: f64 = results.iter().map(|(_, r, _)| r.cost_usd).sum();
    out.push_str(&format!(
        "  {dim}API cost: ~${total_cost:.4} ({total_tokens} LLM tokens){reset}\n"
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Confidence, Finding, Severity};
    use crate::llm::TokenUsage;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_classification_display() {
        assert_eq!(Classification::TruePositive.to_string(), "TRUE POSITIVE");
        assert_eq!(Classification::FalsePositive.to_string(), "FALSE POSITIVE");
        assert_eq!(
            Classification::NeedsInvestigation.to_string(),
            "NEEDS INVESTIGATION"
        );
    }

    #[test]
    fn test_classification_serde_roundtrip() {
        let tp: Classification = serde_json::from_str("\"TP\"").unwrap();
        assert_eq!(tp, Classification::TruePositive);

        let fp: Classification = serde_json::from_str("\"FP\"").unwrap();
        assert_eq!(fp, Classification::FalsePositive);

        let ni: Classification = serde_json::from_str("\"NI\"").unwrap();
        assert_eq!(ni, Classification::NeedsInvestigation);
    }

    #[test]
    fn test_render_triage_results_no_color() {
        let findings = vec![Finding::new("DEPSEC-P001", Severity::High, "exec() call")
            .with_file("node_modules/evil/index.js", 5)
            .with_package_name("evil")];
        let results = vec![(
            0,
            TriageResult {
                classification: Classification::TruePositive,
                confidence: 0.95,
                reasoning: "Dangerous exec".into(),
                recommendation: "Remove package".into(),
                stage: Stage::Llm,
                cost_usd: 0.0,
                latency_ms: 0,
            },
            TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 50,
                total_tokens: 150,
            },
        )];

        let output = render_triage_results(&findings, &results, false);
        assert!(output.contains("TRUE POSITIVE"));
        assert!(output.contains("evil"));
        assert!(output.contains("Remove package"));
        assert!(output.contains("1 true positive"));
    }

    #[test]
    fn test_render_triage_results_mixed() {
        let findings = vec![
            Finding::new("DEPSEC-P001", Severity::High, "exec").with_package_name("bad-pkg"),
            Finding::new("DEPSEC-P001", Severity::High, "exec").with_package_name("safe-pkg"),
        ];
        let results = vec![
            (
                0,
                TriageResult {
                    classification: Classification::TruePositive,
                    confidence: 0.9,
                    reasoning: "bad".into(),
                    recommendation: "remove".into(),
                    stage: Stage::Llm,
                    cost_usd: 0.0,
                    latency_ms: 0,
                },
                TokenUsage::default(),
            ),
            (
                1,
                TriageResult {
                    classification: Classification::FalsePositive,
                    confidence: 0.85,
                    reasoning: "ok".into(),
                    recommendation: "ignore".into(),
                    stage: Stage::Llm,
                    cost_usd: 0.0,
                    latency_ms: 0,
                },
                TokenUsage::default(),
            ),
        ];

        let output = render_triage_results(&findings, &results, false);
        assert!(output.contains("1 true positive"));
        assert!(output.contains("1 false positive"));
    }

    // --- Prefilter tests ---
    use crate::triage_prefilter::{Choice, Decision, MockDecisionApi};

    fn d1(choice: Choice, confidence: f64) -> MockDecisionApi {
        let mut m = MockDecisionApi::new();
        m.expect_model().return_const("liquid/d1-ultra".to_string());
        m.expect_decide().times(1).returning(move |_| {
            Ok(Decision {
                choice,
                confidence,
                cost_usd: 0.00001,
            })
        });
        m
    }

    fn tmp_finding(dir: &TempDir, rule: &str) -> Finding {
        // Unique content per test so the shared triage cache never hits.
        let nonce = dir.path().display().to_string();
        fs::write(
            dir.path().join("index.js"),
            format!("// {nonce}\nexec(cmd);\nconst b = 2;\n"),
        )
        .unwrap();
        let mut f = Finding::new(rule, Severity::High, "exec");
        f.file = Some("index.js".into());
        f.line = Some(2);
        f
    }

    #[test]
    fn d1_confident_fp_is_false_positive() {
        let dir = TempDir::new().unwrap();
        let f = tmp_finding(&dir, "DEPSEC-P001");
        let r = triage_findings_d1(
            &[f],
            dir.path(),
            &d1(Choice::FalsePositive, 0.97),
            &TriageConfig::default(),
        );
        assert_eq!(r[0].1.classification, Classification::FalsePositive);
        assert_eq!(r[0].1.stage, Stage::Prefilter);
    }

    #[test]
    fn d1_below_bar_fp_and_unsure_need_investigation() {
        for (c, p) in [(Choice::FalsePositive, 0.94), (Choice::Unsure, 0.99)] {
            let dir = TempDir::new().unwrap();
            let f = tmp_finding(&dir, "DEPSEC-P001");
            let r = triage_findings_d1(&[f], dir.path(), &d1(c, p), &TriageConfig::default());
            assert_eq!(r[0].1.classification, Classification::NeedsInvestigation);
        }
    }

    #[test]
    fn d1_tp_is_true_positive() {
        let dir = TempDir::new().unwrap();
        let f = tmp_finding(&dir, "DEPSEC-P001");
        let r = triage_findings_d1(
            &[f],
            dir.path(),
            &d1(Choice::TruePositive, 0.8),
            &TriageConfig::default(),
        );
        assert_eq!(r[0].1.classification, Classification::TruePositive);
    }

    #[test]
    fn protected_findings_never_reach_d1() {
        let dir = TempDir::new().unwrap();
        let f = tmp_finding(&dir, "DEPSEC-MAL001");
        let mut m = MockDecisionApi::new();
        m.expect_decide().never();
        m.expect_model().return_const("liquid/d1-ultra".to_string());
        let r = triage_findings_d1(&[f], dir.path(), &m, &TriageConfig::default());
        assert_eq!(r[0].1.classification, Classification::NeedsInvestigation);
    }

    #[test]
    fn deterministic_findings_record_stage() {
        let finding = Finding::new("DEPSEC-W001", Severity::High, "unpinned");
        let dir = TempDir::new().unwrap();
        let mut m = MockDecisionApi::new();
        m.expect_decide().never();
        let results = triage_findings_d1(&[finding], dir.path(), &m, &TriageConfig::default());
        assert_eq!(results[0].1.stage, Stage::Deterministic);
        assert_eq!(results[0].1.cost_usd, 0.0);
    }
    #[test]
    fn render_shows_stage_and_cost() {
        let findings = vec![Finding::new("DEPSEC-P001", Severity::High, "exec")
            .with_file("node_modules/a/index.js", 5)
            .with_package_name("a")];
        let results = vec![(
            0,
            TriageResult {
                classification: Classification::FalsePositive,
                confidence: 0.98,
                reasoning: "r".into(),
                recommendation: "ignore".into(),
                stage: Stage::Prefilter,
                cost_usd: 0.00002,
                latency_ms: 150,
            },
            TokenUsage::default(),
        )];
        let out = render_triage_results(&findings, &results, false);
        assert!(out.contains("[prefilter]"));
        assert!(out.contains("150ms"));
        assert!(out.contains("1 prefilter"));
    }

    #[test]
    fn old_cache_entries_without_stage_still_parse() {
        let r: TriageResult = serde_json::from_str(
            r#"{"classification":"FP","confidence":0.9,"reasoning":"x","recommendation":"y"}"#,
        )
        .unwrap();
        assert_eq!(r.stage, Stage::Llm);
        assert_eq!(r.cost_usd, 0.0);
    }
}
