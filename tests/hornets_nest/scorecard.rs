/// Detection layer for categorizing test vectors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    StaticScan,
    Sandbox,
    NetworkMonitor,
    Canary,
    KillChain,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::StaticScan => write!(f, "Static Scan"),
            Layer::Sandbox => write!(f, "Sandbox"),
            Layer::NetworkMonitor => write!(f, "Network Monitor"),
            Layer::Canary => write!(f, "Canary"),
            Layer::KillChain => write!(f, "Kill Chain"),
        }
    }
}

/// Expected test outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    Detect,
    Miss,
}

/// What actually happened
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actual {
    Detect,
    Miss,
}

/// Combined test outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOutcome {
    /// Expected: detect, Actual: detect — working as intended
    Detect,
    /// Expected: detect, Actual: miss — REGRESSION
    Miss,
    /// Expected: miss, Actual: miss — known gap
    Evade,
    /// Expected: miss, Actual: detect — bonus! gap was fixed
    Surprise,
}

impl TestOutcome {
    pub fn from(expected: Expected, actual: Actual) -> Self {
        match (expected, actual) {
            (Expected::Detect, Actual::Detect) => TestOutcome::Detect,
            (Expected::Detect, Actual::Miss) => TestOutcome::Miss,
            (Expected::Miss, Actual::Miss) => TestOutcome::Evade,
            (Expected::Miss, Actual::Detect) => TestOutcome::Surprise,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TestOutcome::Detect => "DETECT",
            TestOutcome::Miss => "MISS",
            TestOutcome::Evade => "EVADE",
            TestOutcome::Surprise => "SURPRISE",
        }
    }

    /// Is this a regression that should fail CI?
    pub fn is_regression(&self) -> bool {
        matches!(self, TestOutcome::Miss)
    }
}

/// Result of a single test vector
#[derive(Debug)]
#[allow(dead_code)]
pub struct VectorResult {
    pub id: String,
    pub name: String,
    pub layer: Layer,
    pub rule_or_technique: String,
    pub expected: Expected,
    pub actual: Actual,
    pub outcome: TestOutcome,
}

/// Print the detection matrix scorecard
#[allow(dead_code)]
pub fn print_scorecard(results: &[VectorResult]) {
    eprintln!("\n╔══════════════════════════════════════════════╗");
    eprintln!("║        HORNETS NEST DETECTION MATRIX         ║");
    eprintln!("╚══════════════════════════════════════════════╝\n");

    // Per-layer summary
    let layers = [
        Layer::StaticScan,
        Layer::Sandbox,
        Layer::NetworkMonitor,
        Layer::Canary,
        Layer::KillChain,
    ];

    let mut total_detected = 0;
    let mut total_vectors = 0;

    for layer in &layers {
        let layer_results: Vec<_> = results.iter().filter(|r| r.layer == *layer).collect();
        if layer_results.is_empty() {
            continue;
        }
        let detected = layer_results
            .iter()
            .filter(|r| matches!(r.outcome, TestOutcome::Detect | TestOutcome::Surprise))
            .count();
        let total = layer_results.len();
        let pct = if total > 0 {
            (detected as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        total_detected += detected;
        total_vectors += total;
        eprintln!("  {:18} {:2}/{:2} ({:.1}%)", layer, detected, total, pct);
    }

    let overall_pct = if total_vectors > 0 {
        (total_detected as f64 / total_vectors as f64) * 100.0
    } else {
        0.0
    };
    eprintln!(
        "  {:18} {:2}/{:2} ({:.1}%)\n",
        "OVERALL", total_detected, total_vectors, overall_pct
    );

    // Detailed per-vector results
    let regressions: Vec<_> = results
        .iter()
        .filter(|r| r.outcome.is_regression())
        .collect();
    let evades: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Evade))
        .collect();
    let surprises: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Surprise))
        .collect();

    if !regressions.is_empty() {
        eprintln!("  !! REGRESSIONS (expected detect, got miss):");
        for r in &regressions {
            eprintln!(
                "  [{}]  {:30} {:6} {}",
                r.outcome.label(),
                r.name,
                r.id,
                r.rule_or_technique
            );
        }
        eprintln!();
    }

    if !surprises.is_empty() {
        eprintln!("  ** SURPRISES (expected miss, got detect):");
        for r in &surprises {
            eprintln!(
                "  [{}] {:30} {:6} {}",
                r.outcome.label(),
                r.name,
                r.id,
                r.rule_or_technique
            );
        }
        eprintln!();
    }

    if !evades.is_empty() {
        eprintln!("  -- Known gaps (expected miss, got miss):");
        for r in &evades {
            eprintln!(
                "  [{}]   {:30} {:6} {}",
                r.outcome.label(),
                r.name,
                r.id,
                r.rule_or_technique
            );
        }
        eprintln!();
    }

    // Final status
    if regressions.is_empty() {
        eprintln!("  Result: PASS (no regressions)");
    } else {
        eprintln!(
            "  Result: FAIL ({} regression(s) detected)",
            regressions.len()
        );
    }
}
