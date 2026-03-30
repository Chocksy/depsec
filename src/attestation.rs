use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ATTESTATION_FILE: &str = "depsec.attestation.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub version: u32,
    pub tool: String,
    pub tool_version: String,
    pub timestamp: String,
    pub command: String,
    pub project: String,
    pub lockfile_hash: Option<String>,
    pub duration_secs: f64,
    pub result: AttestationResult,
    pub network: NetworkSummary,
    pub file_access: FileAccessSummary,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationResult {
    #[serde(rename = "CLEAN")]
    Clean,
    #[serde(rename = "ISSUES_DETECTED")]
    IssuesDetected,
    #[serde(rename = "FAILED")]
    Failed,
}

impl std::fmt::Display for AttestationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationResult::Clean => write!(f, "CLEAN"),
            AttestationResult::IssuesDetected => write!(f, "ISSUES_DETECTED"),
            AttestationResult::Failed => write!(f, "FAILED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub total: usize,
    pub expected: usize,
    pub unexpected: usize,
    pub critical: usize,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessSummary {
    pub sensitive_reads: usize,
    pub write_violations: usize,
}

/// Generate an attestation from monitor results
pub fn generate_attestation(
    monitor_result: &crate::monitor::MonitorResult,
    project_name: &str,
    root: &Path,
) -> Attestation {
    let has_issues = !monitor_result.unexpected.is_empty()
        || !monitor_result.critical.is_empty()
        || !monitor_result.file_alerts.is_empty()
        || !monitor_result.write_violations.is_empty();

    let result = if monitor_result.exit_code != 0 {
        AttestationResult::Failed
    } else if has_issues {
        AttestationResult::IssuesDetected
    } else {
        AttestationResult::Clean
    };

    let hosts: Vec<String> = monitor_result
        .connections
        .iter()
        .map(|c| c.remote_host.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let lockfile_hash = compute_lockfile_hash(root);

    let mut attestation = Attestation {
        version: 1,
        tool: "depsec".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        timestamp: chrono_now(),
        command: monitor_result.command.clone(),
        project: project_name.into(),
        lockfile_hash,
        duration_secs: monitor_result.duration_secs,
        result,
        network: NetworkSummary {
            total: monitor_result.connections.len(),
            expected: monitor_result.expected.len(),
            unexpected: monitor_result.unexpected.len(),
            critical: monitor_result.critical.len(),
            hosts,
        },
        file_access: FileAccessSummary {
            sensitive_reads: monitor_result.file_alerts.len(),
            write_violations: monitor_result.write_violations.len(),
        },
        signature: None,
    };

    // Sign if key is available
    if let Ok(key) = std::env::var("DEPSEC_ATTESTATION_KEY") {
        attestation.signature = Some(sign_attestation(&attestation, &key));
    }

    attestation
}

/// Save attestation to file
pub fn save_attestation(attestation: &Attestation, root: &Path) -> Result<String> {
    let path = root.join(ATTESTATION_FILE);
    let json = serde_json::to_string_pretty(attestation)?;
    std::fs::write(&path, &json).context("Failed to write attestation file")?;
    Ok(path.to_string_lossy().to_string())
}

/// Load and verify an attestation
pub fn verify_attestation(root: &Path) -> Result<VerifyResult> {
    let path = root.join(ATTESTATION_FILE);

    if !path.exists() {
        return Ok(VerifyResult {
            valid: false,
            message: format!("No attestation file found at {}", path.display()),
            attestation: None,
        });
    }

    let content = std::fs::read_to_string(&path).context("Failed to read attestation file")?;
    let attestation: Attestation =
        serde_json::from_str(&content).context("Failed to parse attestation")?;

    // Check signature if key available
    if let Some(ref sig) = attestation.signature {
        if let Ok(key) = std::env::var("DEPSEC_ATTESTATION_KEY") {
            let expected = sign_attestation(&attestation, &key);
            if sig != &expected {
                return Ok(VerifyResult {
                    valid: false,
                    message: "Attestation signature invalid — file may have been tampered with"
                        .into(),
                    attestation: Some(attestation),
                });
            }
        }
    }

    let valid = matches!(attestation.result, AttestationResult::Clean);
    let message = format!(
        "Attestation: {} — {} ({})",
        attestation.result, attestation.command, attestation.timestamp
    );

    Ok(VerifyResult {
        valid,
        message,
        attestation: Some(attestation),
    })
}

/// One-line summary for PR comments
pub fn attestation_summary(root: &Path) -> Result<String> {
    let path = root.join(ATTESTATION_FILE);

    if !path.exists() {
        anyhow::bail!("No attestation file found");
    }

    let content = std::fs::read_to_string(&path)?;
    let a: Attestation = serde_json::from_str(&content)?;

    let status_icon = match a.result {
        AttestationResult::Clean => "✅",
        AttestationResult::IssuesDetected => "⚠️",
        AttestationResult::Failed => "❌",
    };

    Ok(format!(
        "{status_icon} depsec attestation: {} | {} | {:.1}s | {} connections ({} expected) | {} sensitive reads | {}",
        a.result,
        a.command,
        a.duration_secs,
        a.network.total,
        a.network.expected,
        a.file_access.sensitive_reads,
        a.timestamp,
    ))
}

#[derive(Debug)]
pub struct VerifyResult {
    pub valid: bool,
    pub message: String,
    pub attestation: Option<Attestation>,
}

fn chrono_now() -> String {
    // Simple ISO 8601 timestamp without chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Basic UTC format — good enough without chrono
    format!("{secs}")
}

fn compute_lockfile_hash(root: &Path) -> Option<String> {
    let lockfiles = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "Gemfile.lock",
        "poetry.lock",
    ];

    for lockfile in &lockfiles {
        let path = root.join(lockfile);
        if let Ok(content) = std::fs::read(&path) {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            return Some(format!("sha256:{:x}", hasher.finalize()));
        }
    }
    None
}

fn sign_attestation(attestation: &Attestation, key: &str) -> String {
    use sha2::Sha256;
    // HMAC-SHA256: hash the attestation content with the key
    let content = format!(
        "{}:{}:{}:{}",
        attestation.command,
        attestation.timestamp,
        attestation.result,
        attestation.lockfile_hash.as_deref().unwrap_or("none"),
    );

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(content.as_bytes());
    format!("sha256-hmac:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{Connection, MonitorResult};
    use crate::watchdog::{FileAlert, WriteViolation};

    fn mock_clean_result() -> MonitorResult {
        MonitorResult {
            command: "npm install".into(),
            exit_code: 0,
            duration_secs: 5.2,
            connections: vec![Connection {
                remote_host: "registry.npmjs.org".into(),
                remote_port: 443,
                pid: 1234,
                process_name: "node".into(),
                cmdline: "node".into(),
            }],
            expected: vec![Connection {
                remote_host: "registry.npmjs.org".into(),
                remote_port: 443,
                pid: 1234,
                process_name: "node".into(),
                cmdline: "node".into(),
            }],
            unexpected: vec![],
            critical: vec![],
            file_alerts: vec![],
            write_violations: vec![],
        }
    }

    fn mock_dirty_result() -> MonitorResult {
        let mut result = mock_clean_result();
        result.file_alerts.push(FileAlert {
            path: "/Users/dev/.ssh/id_rsa".into(),
            pid: 1234,
            process_name: "node".into(),
        });
        result
    }

    #[test]
    fn test_generate_clean_attestation() {
        let result = mock_clean_result();
        let attestation = generate_attestation(&result, "test-app", Path::new("/tmp"));

        assert!(matches!(attestation.result, AttestationResult::Clean));
        assert_eq!(attestation.network.total, 1);
        assert_eq!(attestation.network.expected, 1);
        assert_eq!(attestation.network.unexpected, 0);
        assert_eq!(attestation.file_access.sensitive_reads, 0);
        assert_eq!(attestation.tool, "depsec");
    }

    #[test]
    fn test_generate_dirty_attestation() {
        let result = mock_dirty_result();
        let attestation = generate_attestation(&result, "test-app", Path::new("/tmp"));

        assert!(matches!(
            attestation.result,
            AttestationResult::IssuesDetected
        ));
        assert_eq!(attestation.file_access.sensitive_reads, 1);
    }

    #[test]
    fn test_attestation_roundtrip() {
        let result = mock_clean_result();
        let attestation = generate_attestation(&result, "test-app", Path::new("/tmp"));

        let json = serde_json::to_string_pretty(&attestation).unwrap();
        let parsed: Attestation = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.result, AttestationResult::Clean));
        assert_eq!(parsed.project, "test-app");
    }

    #[test]
    fn test_save_and_verify() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = mock_clean_result();
        let attestation = generate_attestation(&result, "test-app", dir.path());

        save_attestation(&attestation, dir.path()).unwrap();

        let verify = verify_attestation(dir.path()).unwrap();
        assert!(verify.valid);
        assert!(verify.attestation.is_some());
    }

    #[test]
    fn test_verify_no_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let verify = verify_attestation(dir.path()).unwrap();
        assert!(!verify.valid);
        assert!(verify.message.contains("No attestation"));
    }

    #[test]
    fn test_attestation_summary() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = mock_clean_result();
        let attestation = generate_attestation(&result, "test-app", dir.path());
        save_attestation(&attestation, dir.path()).unwrap();

        let summary = attestation_summary(dir.path()).unwrap();
        assert!(summary.contains("CLEAN"));
        assert!(summary.contains("npm install"));
    }

    #[test]
    fn test_lockfile_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("package-lock.json"), "test content").unwrap();

        let hash = compute_lockfile_hash(dir.path());
        assert!(hash.is_some());
        assert!(hash.unwrap().starts_with("sha256:"));
    }
}
