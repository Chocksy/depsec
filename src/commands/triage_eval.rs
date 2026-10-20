//! `depsec triage-eval`: run d1 on a labelled corpus and report precision,
//! recall and safety against the label. Paid (d1 only), bypasses the cache.
//! Secret findings (DEPSEC-S*) are never sent. Stops at DEPSEC_EVAL_BUDGET USD.

use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use crate::checks::Finding;
use crate::triage_prefilter::{self, Choice, D1Client, DecisionApi};
use crate::{config, output, scanner, Persona};

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Label {
    /// Corpus is real malware: every finding counts as a true positive.
    Tp,
    /// Corpus is benign packages: every finding counts as a false positive.
    Fp,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalRow {
    pub rule_id: String,
    pub package: String,
    pub location: String,
    pub protected: bool,
    pub label: Label,
    pub d1_choice: Option<Choice>,
    pub d1_confidence: f64,
    pub d1_cost_usd: f64,
    pub d1_latency_ms: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct EvalSummary {
    pub findings: usize,
    pub answered: usize,
    pub errors: usize,
    /// Answered and matching the label (TP->TP, FP->FP)
    pub correct: usize,
    /// Would be auto-suppressed (FP at >= threshold, not protected)
    pub suppressed: usize,
    pub suppressed_correct: usize,
    /// Malware (label TP) findings d1 marked FP at >= threshold. Must be 0.
    pub malware_marked_fp: usize,
    /// Of benign (label FP) findings, share auto-suppressed (recall of the FP filter)
    pub fp_recall: f64,
    /// Of auto-suppressed findings, share truly benign (precision of the FP filter)
    pub fp_precision: f64,
    /// Of malware findings, share d1 called TP
    pub tp_recall: f64,
    pub cost_usd: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
}

pub fn summarize(rows: &[EvalRow], threshold: f64) -> EvalSummary {
    let mut s = EvalSummary {
        findings: rows.len(),
        ..Default::default()
    };
    let (mut benign, mut malware, mut mal_tp) = (0usize, 0usize, 0usize);
    let mut lat: Vec<u64> = vec![];
    for r in rows {
        s.cost_usd += r.d1_cost_usd;
        let Some(c) = r.d1_choice else {
            s.errors += 1;
            continue;
        };
        s.answered += 1;
        lat.push(r.d1_latency_ms);
        let confident_fp = c == Choice::FalsePositive && r.d1_confidence >= threshold;
        match r.label {
            Label::Tp => {
                malware += 1;
                if c == Choice::TruePositive {
                    mal_tp += 1;
                    s.correct += 1;
                }
                if confident_fp {
                    s.malware_marked_fp += 1;
                }
            }
            Label::Fp => {
                benign += 1;
                if c == Choice::FalsePositive {
                    s.correct += 1;
                }
            }
        }
        if confident_fp && !r.protected {
            s.suppressed += 1;
            if r.label == Label::Fp {
                s.suppressed_correct += 1;
            }
        }
    }
    let ratio = |a: usize, b: usize| if b == 0 { 0.0 } else { a as f64 / b as f64 };
    s.fp_recall = ratio(s.suppressed_correct, benign);
    s.fp_precision = ratio(s.suppressed_correct, s.suppressed);
    s.tp_recall = ratio(mal_tp, malware);
    lat.sort_unstable();
    if !lat.is_empty() {
        s.p50_latency_ms = lat[lat.len() / 2];
        s.p95_latency_ms = lat[(lat.len() * 95 / 100).min(lat.len() - 1)];
    }
    s
}

/// Ship bar: zero malware auto-suppressed (protected or not).
pub fn passes(s: &EvalSummary) -> bool {
    s.malware_marked_fp == 0 && s.answered > 0
}

pub fn run(root: &Path, limit: usize, label: Label, out: Option<&Path>) -> ExitCode {
    let cfg = config::load_config(root);
    let Some(d1) = D1Client::from_config(&cfg.triage) else {
        crate::llm::print_setup_instructions();
        return ExitCode::from(2);
    };
    let report = match scanner::run_scan(root, &cfg, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(2);
        }
    };
    let findings: Vec<Finding> = report
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| output::finding_visible(f, Persona::Auditor))
        .filter(|f| {
            let rid = f.rule_id.as_str();
            !(rid.starts_with("DEPSEC-W")
                || rid.starts_with("DEPSEC-V")
                || rid.starts_with("DEPSEC-H")
                || rid.starts_with("DEPSEC-S"))
        })
        .filter(|f| f.file.is_some() && f.line.is_some())
        .cloned()
        .collect();
    // Even sample across the whole finding list instead of the first N.
    let stride = (findings.len() / limit.max(1)).max(1);
    let findings: Vec<Finding> = findings.into_iter().step_by(stride).take(limit).collect();
    let budget: f64 = std::env::var("DEPSEC_EVAL_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.95);

    eprintln!(
        "Evaluating {} findings with {} (label {:?}, budget ${budget})...",
        findings.len(),
        d1.model(),
        label
    );
    let mut rows = Vec::with_capacity(findings.len());
    let mut spent = 0.0f64;
    for f in &findings {
        let mut row = EvalRow {
            rule_id: f.rule_id.clone(),
            package: f.display_label(),
            location: format!(
                "{}:{}",
                f.file.clone().unwrap_or_default(),
                f.line.unwrap_or(0)
            ),
            protected: triage_prefilter::is_protected(f, &cfg.triage.prefilter_always_llm),
            label,
            d1_choice: None,
            d1_confidence: 0.0,
            d1_cost_usd: 0.0,
            d1_latency_ms: 0,
        };
        if let Some(state) =
            triage_prefilter::build_state(f, root, cfg.triage.prefilter_snippet_lines)
        {
            let t = std::time::Instant::now();
            match d1.decide(&state) {
                Ok(d) => {
                    row.d1_latency_ms = t.elapsed().as_millis() as u64;
                    row.d1_choice = Some(d.choice);
                    row.d1_confidence = d.confidence;
                    row.d1_cost_usd = d.cost_usd;
                }
                Err(e) => eprintln!("  d1 failed on {}: {e}", row.rule_id),
            }
        }
        spent += row.d1_cost_usd;
        rows.push(row);
        if spent >= budget {
            eprintln!("Budget ${budget} reached (spent ${spent:.5}); stopping.");
            break;
        }
    }
    let summary = summarize(&rows, cfg.triage.prefilter_fp_threshold);
    println!("{}", render_summary(&summary));
    if let Some(path) = out {
        let body = serde_json::json!({ "summary": summary, "rows": rows });
        if let Err(e) = std::fs::write(
            path,
            serde_json::to_string_pretty(&body).unwrap_or_default(),
        ) {
            eprintln!("Error writing {}: {e}", path.display());
            return ExitCode::from(2);
        }
        eprintln!("Wrote {}", path.display());
    }
    if passes(&summary) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub fn render_summary(s: &EvalSummary) -> String {
    format!(
        "d1 triage eval\n\
         findings: {} (answered {}, errors {})\n\
         label agreement: {}/{}\n\
         auto-suppressed: {} (truly benign {})  FP precision {:.1}%  FP recall {:.1}%\n\
         malware marked FP at bar: {}  (must be 0)\n\
         malware TP recall: {:.1}%\n\
         cost: ${:.5}  latency p50 {} ms p95 {} ms\n\
         verdict: {}",
        s.findings,
        s.answered,
        s.errors,
        s.correct,
        s.answered,
        s.suppressed,
        s.suppressed_correct,
        s.fp_precision * 100.0,
        s.fp_recall * 100.0,
        s.malware_marked_fp,
        s.tp_recall * 100.0,
        s.cost_usd,
        s.p50_latency_ms,
        s.p95_latency_ms,
        if passes(s) { "PASS" } else { "FAIL" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(label: Label, protected: bool, d1: Option<(Choice, f64)>) -> EvalRow {
        EvalRow {
            rule_id: "DEPSEC-P001".into(),
            package: "p".into(),
            location: "f:1".into(),
            protected,
            label,
            d1_choice: d1.map(|d| d.0),
            d1_confidence: d1.map(|d| d.1).unwrap_or(0.0),
            d1_cost_usd: 0.00001,
            d1_latency_ms: 100,
        }
    }

    #[test]
    fn metrics_against_labels() {
        let rows = vec![
            row(Label::Fp, false, Some((Choice::FalsePositive, 0.99))),
            row(Label::Fp, false, Some((Choice::FalsePositive, 0.80))),
            row(Label::Fp, false, Some((Choice::TruePositive, 0.70))),
            row(Label::Tp, false, Some((Choice::TruePositive, 0.90))),
            row(Label::Tp, false, Some((Choice::Unsure, 0.50))),
            row(Label::Tp, false, None),
        ];
        let s = summarize(&rows, 0.95);
        assert_eq!(s.answered, 5);
        assert_eq!(s.errors, 1);
        assert_eq!(s.suppressed, 1);
        assert!((s.fp_precision - 1.0).abs() < 1e-9);
        assert!((s.fp_recall - 1.0 / 3.0).abs() < 1e-9);
        assert!((s.tp_recall - 0.5).abs() < 1e-9);
        assert_eq!(s.malware_marked_fp, 0);
        assert!(passes(&s));
    }

    #[test]
    fn any_malware_marked_fp_fails() {
        let rows = vec![row(Label::Tp, true, Some((Choice::FalsePositive, 0.97)))];
        let s = summarize(&rows, 0.95);
        assert_eq!(s.malware_marked_fp, 1);
        assert_eq!(s.suppressed, 0, "protected findings are never suppressed");
        assert!(!passes(&s));
        assert!(render_summary(&s).contains("FAIL"));
    }
}
