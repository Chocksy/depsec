use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Ecosystem type for package directory layout
pub enum Ecosystem {
    Npm,
    Pip,
    Gem,
}

/// Builder for scan-tier test packages (directory-based, no install)
pub struct ScanPackageBuilder {
    name: String,
    ecosystem: Ecosystem,
    files: Vec<(String, String)>,
}

impl ScanPackageBuilder {
    pub fn npm(name: &str) -> Self {
        Self {
            name: name.into(),
            ecosystem: Ecosystem::Npm,
            files: vec![],
        }
    }

    pub fn pip(name: &str) -> Self {
        Self {
            name: name.into(),
            ecosystem: Ecosystem::Pip,
            files: vec![],
        }
    }

    pub fn gem(name: &str) -> Self {
        Self {
            name: name.into(),
            ecosystem: Ecosystem::Gem,
            files: vec![],
        }
    }

    /// Add a file relative to the package root
    pub fn file(mut self, path: &str, content: &str) -> Self {
        self.files.push((path.into(), content.into()));
        self
    }

    /// Build the package in a temp directory with correct ecosystem layout
    pub fn build(self) -> TempDir {
        let dir = TempDir::new().expect("Failed to create temp dir");

        let pkg_dir = match self.ecosystem {
            Ecosystem::Npm => dir.path().join("node_modules").join(&self.name),
            Ecosystem::Pip => dir
                .path()
                .join(".venv/lib/python3.11/site-packages")
                .join(&self.name),
            Ecosystem::Gem => dir
                .path()
                .join("vendor/bundle/ruby/3.2.0/gems")
                .join(&self.name),
        };

        std::fs::create_dir_all(&pkg_dir).expect("Failed to create package dir");

        // Write package.json for npm packages (required by scanner)
        if matches!(self.ecosystem, Ecosystem::Npm) {
            let pkg_json = format!(
                r#"{{"name":"{}","version":"1.0.0","description":"hornets nest test package"}}"#,
                self.name
            );
            std::fs::write(pkg_dir.join("package.json"), pkg_json).unwrap();
        }

        for (path, content) in &self.files {
            let full_path = pkg_dir.join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full_path, content).unwrap();
        }

        // Git init required for secrets check (scanner expects a git repo)
        let _ = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output();

        dir
    }
}

/// Get the depsec binary path (built by cargo test)
fn depsec_bin() -> PathBuf {
    // cargo sets this env var for integration tests
    PathBuf::from(env!("CARGO_BIN_EXE_depsec"))
}

/// Run `depsec scan` on a directory and return JSON stdout
pub fn run_scan(dir: &Path, checks: &str) -> String {
    let output = Command::new(depsec_bin())
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--format",
            "json",
            "--checks",
            checks,
        ])
        .output()
        .expect("Failed to run depsec scan");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if std::env::var("HORNETS_DEBUG").is_ok() {
        eprintln!("[hornets_nest] scan dir: {}", dir.display());
        eprintln!(
            "[hornets_nest] stdout: {}",
            &stdout[..stdout.len().min(500)]
        );
        if !stderr.is_empty() {
            eprintln!(
                "[hornets_nest] stderr: {}",
                &stderr[..stderr.len().min(500)]
            );
        }
    }

    stdout
}

/// Run `depsec scan` and return (stdout, exit_code)
#[allow(dead_code)]
pub fn run_scan_with_exit(dir: &Path, checks: &str) -> (String, i32) {
    let output = Command::new(depsec_bin())
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--format",
            "json",
            "--checks",
            checks,
        ])
        .output()
        .expect("Failed to run depsec scan");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

/// Assert that scan output contains a finding with the given rule_id
#[allow(dead_code)]
pub fn assert_finding(output: &str, rule_id: &str) {
    assert!(
        output.contains(rule_id),
        "Expected finding {} in scan output, but not found.\nOutput:\n{}",
        rule_id,
        &output[..output.len().min(2000)]
    );
}

/// Assert that scan output does NOT contain a finding with the given rule_id
#[allow(dead_code)]
pub fn assert_no_finding(output: &str, rule_id: &str) {
    assert!(
        !output.contains(rule_id),
        "Expected NO finding {} in scan output, but found it.\nOutput:\n{}",
        rule_id,
        &output[..output.len().min(2000)]
    );
}
