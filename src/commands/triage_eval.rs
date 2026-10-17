//! `depsec triage-eval`: run the d1 prefilter and the full LLM on the same
//! findings and report agreement, cost, and safety. Paid: calls both APIs,
//! bypasses the triage cache. See docs/triage-prefilter.md for the pass bar.

use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use crate::checks::Finding;
use crate::llm::{ChatMessage, LlmApi, LlmClient};
use crate::triage::Classification;
use crate::triage_prefilter::{self, Choice, D1Client, DecisionApi};
use crate::{config, output, scanner, triage, Persona};

#[derive(Debug, Clone, Serialize)]
pub struct EvalRow {
    pub rule_id: String,
    pub package: String,
    pub location: String,
    pub protected: bool,
    pub d1_choice: Option<Choice>,
    pub d1_confidence: f64,
    pub d1_cost_usd: f64,
    pub d1_latency_ms: u64,
    pub llm_classification: Option<Classification>,
    pub llm_confidence: f64,
    pub llm_cost_usd: f64,
    pub llm_latency_ms: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct EvalSummary {
    pub findings: usize,
    pub both_answered: usize,
    /// d1 would auto-clear as FP (confident, not protected)
    pub prefilter_cleared: usize,
    /// ...and the LLM also said FP
    pub prefilter_cleared_llm_agrees: usize,
    /// Fraction of auto-cleared findings the LLM also called FP. Pass bar: >= 0.90
    pub agreement_on_cleared: f64,
    /// 3-way agreement on all answered findings (TP=TP, FP=FP, UNSURE=NI)
    pub raw_agreement: f64,
    /// Findings that would still go to the LLM in production
    pub sent_to_llm: usize,
    /// Protected (malware/supply-chain/secret) findings d1 marked FP confidently. Must be 0.
    pub protected_marked_fp: usize,
    /// Non-protected findings d1 cleared where the LLM said TP. Must be 0 to ship.
    pub cleared_but_llm_tp: usize,
    pub d1_cost_usd: f64,
    pub llm_cost_usd: f64,
    pub d1_p50_latency_ms: u64,
    pub llm_p50_latency_ms: u64,
}

pub fn summarize(rows: &[EvalRow], threshold: f64) -> EvalSummary {
    let mut s = EvalSummary {
        findings: rows.len(),
        ..Default::default()
    };
    let mut raw_agree = 0usize;
    for r in rows {
        s.d1_cost_usd += r.d1_cost_usd;
        s.llm_cost_usd += r.llm_cost_usd;
        let (Some(d1), Some(llm)) = (r.d1_choice, r.llm_classification) else {
            s.sent_to_llm += 1;
            continue;
        };
        s.both_answered += 1;
        let confident_fp = d1 == Choice::FalsePositive && r.d1_confidence >= threshold;
        let agrees = matches!(
            (d1, llm),
            (Choice::TruePositive, Classification::TruePositive)
                | (Choice::FalsePositive, Classification::FalsePositive)
                | (Choice::Unsure, Classification::NeedsInvestigation)
        );
        if agrees {
            raw_agree += 1;
        }
        if r.protected {
            if confident_fp {
                s.protected_marked_fp += 1;
            }
            s.sent_to_llm += 1;
            continue;
        }
        if confident_fp {
            s.prefilter_cleared += 1;
            match llm {
                Classification::FalsePositive => s.prefilter_cleared_llm_agrees += 1,
                Classification::TruePositive => s.cleared_but_llm_tp += 1,
                Classification::NeedsInvestigation => {}
            }
        } else {
            s.sent_to_llm += 1;
        }
    }
    if s.prefilter_cleared > 0 {
        s.agreement_on_cleared = s.prefilter_cleared_llm_agrees as f64 / s.prefilter_cleared as f64;
    }
    if s.both_answered > 0 {
        s.raw_agreement = raw_agree as f64 / s.both_answered as f64;
    }
    let p50 = |mut v: Vec<u64>| -> u64 {
        if v.is_empty() {
            return 0;
        }
        v.sort_unstable();
        v[v.len() / 2]
    };
    s.d1_p50_latency_ms = p50(rows
        .iter()
        .filter(|r| r.d1_choice.is_some())
        .map(|r| r.d1_latency_ms)
        .collect());
    s.llm_p50_latency_ms = p50(rows
        .iter()
        .filter(|r| r.llm_classification.is_some())
        .map(|r| r.llm_latency_ms)
        .collect());
    s
}

pub fn passes(s: &EvalSummary) -> bool {
    s.protected_marked_fp == 0 && s.cleared_but_llm_tp == 0 && s.agreement_on_cleared >= 0.90
}

pub fn run(root: &Path, limit: usize, out: Option<&Path>) -> ExitCode {
    let cfg = config::load_config(root);
    let Some(llm) = LlmClient::from_config(&cfg.triage) else {
        crate::llm::print_setup_instructions();
        return ExitCode::from(2);
    };
    let Some(d1) = D1Client::from_config(&cfg.triage) else {
        return ExitCode::from(2);
    };

    let report = match scanner::run_scan(root, &cfg, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(2);
        }
    };
    // Auditor persona: evaluate on everything the scanner produces, skip deterministic rules.
    let findings: Vec<Finding> = report
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| output::finding_visible(f, Persona::Auditor))
        .filter(|f| {
            let rid = f.rule_id.as_str();
            !(rid.starts_with("DEPSEC-W")
                || rid.starts_with("DEPSEC-V")
                || rid.starts_with("DEPSEC-H"))
        })
        .filter(|f| f.file.is_some() && f.line.is_some())
        .take(limit)
        .cloned()
        .collect();

    eprintln!(
        "Evaluating {} findings with {} and {} (both paid, cache bypassed)...",
        findings.len(),
        d1.model(),
        llm.model()
    );

    let mut rows = Vec::with_capacity(findings.len());
    for (i, f) in findings.iter().enumerate() {
        let mut row = EvalRow {
            rule_id: f.rule_id.clone(),
            package: f.display_label(),
            location: format!(
                "{}:{}",
                f.file.clone().unwrap_or_default(),
                f.line.unwrap_or(0)
            ),
            protected: triage_prefilter::is_protected(f, &cfg.triage.prefilter_always_llm),
            d1_choice: None,
            d1_confidence: 0.0,
            d1_cost_usd: 0.0,
            d1_latency_ms: 0,
            llm_classification: None,
            llm_confidence: 0.0,
            llm_cost_usd: 0.0,
            llm_latency_ms: 0,
        };
        eprint!(
            "  {}/{}: {} {}... ",
            i + 1,
            findings.len(),
            row.package,
            row.rule_id
        );

        // d1 also runs on protected malware/supply-chain findings so we can measure
        // (never act on) its errors. Secret leaks are the exception: their snippets
        // are never sent to a training-eligible model, not even in the eval.
        let skip_d1 = row.rule_id.starts_with("DEPSEC-S");
        if skip_d1 {
            eprint!("[secret: d1 skipped] ");
        }
        let state = if skip_d1 {
            None
        } else {
            triage_prefilter::build_state(f, root, cfg.triage.prefilter_snippet_lines)
        };
        if let Some(state) = state {
            let t = std::time::Instant::now();
            match d1.decide(&state) {
                Ok(d) => {
                    row.d1_latency_ms = t.elapsed().as_millis() as u64;
                    row.d1_choice = Some(d.choice);
                    row.d1_confidence = d.confidence;
                    row.d1_cost_usd = d.cost_usd;
                }
                Err(e) => eprint!("[d1 failed: {e}] "),
            }
        }

        if let Some(ctx) = triage::build_context(f, root) {
            let messages = vec![
                ChatMessage {
                    role: "system".into(),
                    content: triage::SYSTEM_PROMPT.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: triage::build_user_prompt(&ctx),
                },
            ];
            let t = std::time::Instant::now();
            match crate::llm::chat_json::<triage::TriageResult>(&llm, &messages) {
                Ok((r, usage)) => {
                    row.llm_latency_ms = t.elapsed().as_millis() as u64;
                    row.llm_classification = Some(if r.confidence < 0.5 {
                        Classification::NeedsInvestigation
                    } else {
                        r.classification
                    });
                    row.llm_confidence = r.confidence;
                    row.llm_cost_usd =
                        llm.estimate_cost(usage.prompt_tokens, usage.completion_tokens);
                }
                Err(e) => eprint!("[llm failed: {e}] "),
            }
        }
        eprintln!(
            "d1={:?}@{:.2} llm={:?}",
            row.d1_choice, row.d1_confidence, row.llm_classification
        );
        rows.push(row);
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
        "Prefilter eval\n\
         findings evaluated:            {}\n\
         both models answered:          {}\n\
         prefilter would clear (FP):    {}\n\
         ...LLM agrees FP:              {}  ({:.1}%  pass bar >= 90%)\n\
         ...LLM says TP:                {}  (must be 0)\n\
         protected marked FP by d1:     {}  (must be 0; never acted on)\n\
         raw 3-way agreement:           {:.1}%\n\
         still sent to LLM:             {}\n\
         d1 cost:                       ${:.5}  (p50 {} ms)\n\
         LLM cost:                      ${:.4}  (p50 {} ms)\n\
         verdict:                       {}",
        s.findings,
        s.both_answered,
        s.prefilter_cleared,
        s.prefilter_cleared_llm_agrees,
        s.agreement_on_cleared * 100.0,
        s.cleared_but_llm_tp,
        s.protected_marked_fp,
        s.raw_agreement * 100.0,
        s.sent_to_llm,
        s.d1_cost_usd,
        s.d1_p50_latency_ms,
        s.llm_cost_usd,
        s.llm_p50_latency_ms,
        if passes(s) { "PASS" } else { "FAIL" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        rule: &str,
        protected: bool,
        d1: Option<(Choice, f64)>,
        llm: Option<Classification>,
    ) -> EvalRow {
        EvalRow {
            rule_id: rule.into(),
            package: "p".into(),
            location: "f:1".into(),
            protected,
            d1_choice: d1.map(|d| d.0),
            d1_confidence: d1.map(|d| d.1).unwrap_or(0.0),
            d1_cost_usd: 0.00001,
            d1_latency_ms: 100,
            llm_classification: llm,
            llm_confidence: 0.9,
            llm_cost_usd: 0.01,
            llm_latency_ms: 3000,
        }
    }

    #[test]
    fn summary_counts_agreement_and_safety() {
        let rows = vec![
            row(
                "DEPSEC-P001",
                false,
                Some((Choice::FalsePositive, 0.99)),
                Some(Classification::FalsePositive),
            ),
            row(
                "DEPSEC-P001",
                false,
                Some((Choice::FalsePositive, 0.96)),
                Some(Classification::FalsePositive),
            ),
            row(
                "DEPSEC-P003",
                false,
                Some((Choice::FalsePositive, 0.80)),
                Some(Classification::FalsePositive),
            ),
            row(
                "DEPSEC-P008",
                false,
                Some((Choice::TruePositive, 0.90)),
                Some(Classification::TruePositive),
            ),
            row(
                "DEPSEC-P017",
                false,
                Some((Choice::Unsure, 0.50)),
                Some(Classification::NeedsInvestigation),
            ),
            row(
                "DEPSEC-MAL001",
                true,
                Some((Choice::FalsePositive, 0.99)),
                Some(Classification::TruePositive),
            ),
            row(
                "DEPSEC-P001",
                false,
                None,
                Some(Classification::TruePositive),
            ),
        ];
        let s = summarize(&rows, 0.95);
        assert_eq!(s.findings, 7);
        assert_eq!(s.both_answered, 6);
        assert_eq!(s.prefilter_cleared, 2);
        assert_eq!(s.prefilter_cleared_llm_agrees, 2);
        assert!((s.agreement_on_cleared - 1.0).abs() < 1e-9);
        assert_eq!(s.cleared_but_llm_tp, 0);
        assert_eq!(s.protected_marked_fp, 1);
        assert_eq!(s.sent_to_llm, 5);
        assert!((s.raw_agreement - 5.0 / 6.0).abs() < 1e-9);
        assert!((s.d1_cost_usd - 0.00007).abs() < 1e-9);
        assert_eq!(s.d1_p50_latency_ms, 100);
        assert!(!passes(&s), "a protected FP must fail the eval");
    }

    #[test]
    fn pass_bar_requires_90_percent_and_no_tp_clears() {
        let mut rows: Vec<EvalRow> = (0..9)
            .map(|_| {
                row(
                    "DEPSEC-P001",
                    false,
                    Some((Choice::FalsePositive, 0.99)),
                    Some(Classification::FalsePositive),
                )
            })
            .collect();
        rows.push(row(
            "DEPSEC-P001",
            false,
            Some((Choice::FalsePositive, 0.99)),
            Some(Classification::NeedsInvestigation),
        ));
        let s = summarize(&rows, 0.95);
        assert!((s.agreement_on_cleared - 0.9).abs() < 1e-9);
        assert!(passes(&s));

        rows.push(row(
            "DEPSEC-P001",
            false,
            Some((Choice::FalsePositive, 0.99)),
            Some(Classification::TruePositive),
        ));
        let s = summarize(&rows, 0.95);
        assert_eq!(s.cleared_but_llm_tp, 1);
        assert!(!passes(&s));
        assert!(render_summary(&s).contains("FAIL"));
    }
}
