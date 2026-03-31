use std::path::Path;

use crate::checks::{Check, CheckResult, ScanContext};
use crate::config::Config;
use crate::output::ScanReport;

pub fn detect_project_name(root: &Path) -> String {
    // Try Cargo.toml
    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
            if let Ok(parsed) = content.parse::<toml::Table>() {
                if let Some(pkg) = parsed.get("package").and_then(|p| p.as_table()) {
                    if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                        return name.to_string();
                    }
                }
            }
        }
    }

    // Try package.json
    let package_json = root.join("package.json");
    if package_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&package_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(name) = parsed.get("name").and_then(|n| n.as_str()) {
                    return name.to_string();
                }
            }
        }
    }

    // Fallback to directory name
    root.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub fn run_scan(
    root: &Path,
    config: &Config,
    check_filter: Option<&[String]>,
) -> anyhow::Result<ScanReport> {
    let ctx = ScanContext { root, config };

    let all_checks: Vec<Box<dyn Check>> = vec![
        Box::new(crate::checks::workflows::WorkflowsCheck),
        Box::new(crate::checks::deps::DepsCheck),
        Box::new(crate::checks::patterns::PatternsCheck),
        Box::new(crate::checks::secrets::SecretsCheck),
        Box::new(crate::checks::hygiene::HygieneCheck),
        Box::new(crate::checks::capabilities::CapabilitiesCheck),
    ];

    let enabled = &config.checks.enabled;

    let mut results: Vec<CheckResult> = Vec::new();

    for check in &all_checks {
        let name = check.name();

        // Filter by --checks flag if provided
        if let Some(filter) = check_filter {
            if !filter.iter().any(|f| f == name) {
                continue;
            }
        }

        // Filter by config enabled list
        if !enabled.iter().any(|e| e == name) {
            continue;
        }

        match check.run(&ctx) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("Error running {name} check: {e}");
                return Err(e);
            }
        }
    }

    let project_name = detect_project_name(root);
    Ok(ScanReport::new(project_name, results).with_repo_url(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn temp_project() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn test_detect_project_name_cargo() {
        let dir = temp_project();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"my-rust-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        assert_eq!(detect_project_name(dir.path()), "my-rust-app");
    }

    #[test]
    fn test_detect_project_name_package_json() {
        let dir = temp_project();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "my-node-app", "version": "1.0.0"}"#,
        )
        .unwrap();
        assert_eq!(detect_project_name(dir.path()), "my-node-app");
    }

    #[test]
    fn test_detect_project_name_fallback() {
        let dir = temp_project();
        let name = detect_project_name(dir.path());
        // tempdir names are random, just verify it's not empty
        assert!(!name.is_empty());
    }

    #[test]
    fn test_run_scan_empty_project() {
        let dir = temp_project();
        let config = Config::default();
        let report = run_scan(dir.path(), &config, None).unwrap();
        assert!(!report.project_name.is_empty());
        // With no workflows/secrets/hygiene issues in empty dir, should score well
    }

    #[test]
    fn test_run_scan_with_filter() {
        let dir = temp_project();
        let config = Config::default();
        let filter = vec!["workflows".to_string()];
        let report = run_scan(dir.path(), &config, Some(&filter)).unwrap();
        // Should only have workflows results
        for result in &report.results {
            assert_eq!(result.category, "workflows");
        }
    }
}
