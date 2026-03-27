use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::parsers;

const BASELINE_FILENAME: &str = "depsec.baseline.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created: String,
    pub allowed_hosts: Vec<String>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: 1,
            created: chrono_date(),
            allowed_hosts: vec![
                "github.com".into(),
                "api.github.com".into(),
                "api.osv.dev".into(),
            ],
        }
    }
}

fn chrono_date() -> String {
    // Simple date without chrono dependency
    let output = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output();

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// Initialize a baseline file with common hosts pre-populated based on detected ecosystem.
pub fn init_baseline(root: &Path) -> anyhow::Result<String> {
    let output_path = root.join(BASELINE_FILENAME);

    let mut baseline = Baseline::default();

    // Detect ecosystem and add relevant registry hosts
    let lockfiles = parsers::parse_all_lockfiles(root, 3);
    let mut ecosystems = std::collections::HashSet::new();

    for (name, _) in &lockfiles {
        if name.contains("Cargo.lock") {
            ecosystems.insert("rust");
        } else if name.contains("package-lock.json")
            || name.contains("yarn.lock")
            || name.contains("pnpm-lock.yaml")
        {
            ecosystems.insert("node");
        } else if name.contains("Gemfile.lock") {
            ecosystems.insert("ruby");
        } else if name.contains("go.sum") {
            ecosystems.insert("go");
        } else if name.contains("poetry.lock")
            || name.contains("Pipfile.lock")
            || name.contains("requirements.txt")
        {
            ecosystems.insert("python");
        }
    }

    if ecosystems.contains("rust") {
        baseline.allowed_hosts.push("crates.io".into());
        baseline.allowed_hosts.push("static.crates.io".into());
    }
    if ecosystems.contains("node") {
        baseline.allowed_hosts.push("registry.npmjs.org".into());
    }
    if ecosystems.contains("ruby") {
        baseline.allowed_hosts.push("rubygems.org".into());
        baseline.allowed_hosts.push("index.rubygems.org".into());
    }
    if ecosystems.contains("go") {
        baseline.allowed_hosts.push("proxy.golang.org".into());
        baseline.allowed_hosts.push("sum.golang.org".into());
    }
    if ecosystems.contains("python") {
        baseline.allowed_hosts.push("pypi.org".into());
        baseline.allowed_hosts.push("files.pythonhosted.org".into());
    }

    // Deduplicate
    baseline.allowed_hosts.sort();
    baseline.allowed_hosts.dedup();

    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(&output_path, &json).context("Failed to write baseline file")?;

    Ok(output_path.to_string_lossy().to_string())
}

/// Check captured connections against baseline.
pub fn check_baseline(
    root: &Path,
    capture_path: Option<&Path>,
) -> anyhow::Result<BaselineCheckResult> {
    let baseline_path = root.join(BASELINE_FILENAME);
    if !baseline_path.exists() {
        anyhow::bail!(
            "No baseline file found. Run 'depsec baseline init' to create one."
        );
    }

    let content = std::fs::read_to_string(&baseline_path).context("Failed to read baseline")?;
    let baseline: Baseline =
        serde_json::from_str(&content).context("Failed to parse baseline")?;

    // If capture file is provided, parse it
    let captured_hosts = match capture_path {
        Some(path) => parse_capture_file(path)?,
        None => vec![],
    };

    let mut matched = Vec::new();
    let mut violations = Vec::new();

    for host in &captured_hosts {
        if baseline.allowed_hosts.contains(host) {
            matched.push(host.clone());
        } else {
            violations.push(host.clone());
        }
    }

    Ok(BaselineCheckResult {
        matched,
        violations,
        total_captured: captured_hosts.len(),
    })
}

#[derive(Debug)]
pub struct BaselineCheckResult {
    pub matched: Vec<String>,
    pub violations: Vec<String>,
    pub total_captured: usize,
}

impl BaselineCheckResult {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Parse a tcpdump capture summary file.
/// Expected format: one hostname or IP per line.
fn parse_capture_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path).context("Failed to read capture file")?;
    let hosts: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    // Deduplicate
    let mut unique: Vec<String> = hosts;
    unique.sort();
    unique.dedup();
    Ok(unique)
}

pub fn print_baseline_check(result: &BaselineCheckResult, use_color: bool) {
    println!("[Network Monitor]");

    for host in &result.matched {
        let icon = if use_color { "\x1b[32m✓\x1b[0m" } else { "✓" };
        println!("  {icon} {host} — in baseline");
    }

    for host in &result.violations {
        let icon = if use_color { "\x1b[31m✗\x1b[0m" } else { "✗" };
        println!("  {icon} {host} — NOT in baseline!");
    }

    if result.total_captured == 0 {
        println!("  No connections captured.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_init_baseline() {
        let dir = TempDir::new().unwrap();
        let path = init_baseline(dir.path()).unwrap();
        assert!(std::path::Path::new(&path).exists());

        let content = fs::read_to_string(&path).unwrap();
        let baseline: Baseline = serde_json::from_str(&content).unwrap();
        assert_eq!(baseline.version, 1);
        assert!(baseline.allowed_hosts.contains(&"github.com".to_string()));
        assert!(baseline.allowed_hosts.contains(&"api.osv.dev".to_string()));
    }

    #[test]
    fn test_init_baseline_with_cargo_lock() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.lock"),
            "version = 3\n[[package]]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        init_baseline(dir.path()).unwrap();
        let content = fs::read_to_string(dir.path().join("depsec.baseline.json")).unwrap();
        let baseline: Baseline = serde_json::from_str(&content).unwrap();
        assert!(baseline.allowed_hosts.contains(&"crates.io".to_string()));
    }

    #[test]
    fn test_check_baseline_no_violations() {
        let dir = TempDir::new().unwrap();
        init_baseline(dir.path()).unwrap();

        let capture = dir.path().join("capture.txt");
        fs::write(&capture, "github.com\napi.osv.dev\n").unwrap();

        let result = check_baseline(dir.path(), Some(&capture)).unwrap();
        assert!(result.passed());
        assert_eq!(result.matched.len(), 2);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_check_baseline_with_violation() {
        let dir = TempDir::new().unwrap();
        init_baseline(dir.path()).unwrap();

        let capture = dir.path().join("capture.txt");
        fs::write(&capture, "github.com\n83.142.209.203\n").unwrap();

        let result = check_baseline(dir.path(), Some(&capture)).unwrap();
        assert!(!result.passed());
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations.contains(&"83.142.209.203".to_string()));
    }
}
