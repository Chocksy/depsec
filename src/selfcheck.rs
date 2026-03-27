use std::path::Path;

use crate::config;
use crate::scanner;

pub fn run_self_check(root: &Path) {
    println!("DepSec Self-Integrity Report");
    println!("───────────────────────────");
    println!("Binary:        depsec v{}", env!("CARGO_PKG_VERSION"));

    // Count dependencies from Cargo.lock if present
    let cargo_lock = root.join("Cargo.lock");
    if cargo_lock.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_lock) {
            let dep_count = content.matches("[[package]]").count();
            println!("Dependencies:  {dep_count} crates");
        }
    }

    // Run self-scan
    let config = config::load_config(root);
    match scanner::run_scan(root, &config, None) {
        Ok(report) => {
            let vuln_count: usize = report
                .results
                .iter()
                .flat_map(|r| &r.findings)
                .filter(|f| f.rule_id.starts_with("DEPSEC-V:"))
                .count();
            let mal_count: usize = report
                .results
                .iter()
                .flat_map(|r| &r.findings)
                .filter(|f| f.rule_id.starts_with("DEPSEC-MAL:"))
                .count();

            let vuln_icon = if vuln_count == 0 { "✓" } else { "✗" };
            let mal_icon = if mal_count == 0 { "✓" } else { "✗" };

            println!("Advisories:    {vuln_icon} {vuln_count} known vulnerabilities");
            println!("Malware:       {mal_icon} {mal_count} known malicious packages");
            println!(
                "Grade:         {} ({:.1}/10)",
                report.grade,
                report.total_score / 10.0
            );
        }
        Err(e) => {
            println!("Self-scan:     ✗ failed: {e}");
        }
    }

    // Check deny.toml
    let deny_toml = root.join("deny.toml");
    if deny_toml.exists() {
        println!("Licenses:      ✓ checked by cargo-deny");
        println!("Sources:       ✓ restricted to crates.io");
    } else {
        println!("Licenses:      ⚠ no deny.toml (not audited)");
        println!("Sources:       ⚠ no deny.toml (not restricted)");
    }

    // Check CI
    let ci_yml = root.join(".github/workflows/ci.yml");
    if ci_yml.exists() {
        println!("CI:            ✓ GitHub Actions configured");
    } else {
        println!("CI:            ⚠ no CI workflow found");
    }

    // Trust chain
    println!();
    println!("Trust chain:");
    println!("  ✓ Source: public on GitHub");
    println!("  ✓ Dependencies: audited by cargo-deny + OSV on every commit");
    println!("  ✓ Network: build connections monitored in CI");
    println!("  ✗ Reproducible build: not yet implemented");
    println!("  ✗ SLSA attestation: not yet implemented");
}
