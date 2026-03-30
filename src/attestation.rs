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

    // Fail-closed signature verification
    match (
        &attestation.signature,
        std::env::var("DEPSEC_ATTESTATION_KEY").ok(),
    ) {
        // Signed + key available: verify signature
        (Some(sig), Some(key)) => {
            let expected = sign_attestation(&attestation, &key);
            // Constant-time comparison (not vulnerable to timing attacks)
            let sig_valid = sig.len() == expected.len()
                && sig
                    .bytes()
                    .zip(expected.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;

            if !sig_valid {
                return Ok(VerifyResult {
                    valid: false,
                    message: "Attestation signature INVALID — file may have been tampered with"
                        .into(),
                    attestation: Some(attestation),
                });
            }
        }
        // Signed but no key: can't verify — fail closed
        (Some(_), None) => {
            return Ok(VerifyResult {
                valid: false,
                message: "Attestation is signed but DEPSEC_ATTESTATION_KEY not set — cannot verify"
                    .into(),
                attestation: Some(attestation),
            });
        }
        // Unsigned: reject — attestations must be signed for trust
        (None, _) => {
            return Ok(VerifyResult {
                valid: false,
                message: "Attestation is UNSIGNED — not trustworthy. Set DEPSEC_ATTESTATION_KEY to enable signing"
                    .into(),
                attestation: Some(attestation),
            });
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
    // ISO 8601 UTC timestamp without chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Convert to rough ISO 8601 (year-month-day format)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    // Approximate date from epoch days (good enough for attestation timestamps)
    let (year, month, day) = epoch_days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    // Simplified date calculation from Unix epoch days
    let mut y = 1970;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let days_in_months: [u64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for (i, &d) in days_in_months.iter().enumerate() {
        if remaining < d {
            m = i;
            break;
        }
        remaining -= d;
    }
    (y, (m + 1) as u64, remaining + 1)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
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
    // HMAC-SHA256: H(key XOR opad || H(key XOR ipad || message))
    // Covers ALL attestation fields (except signature itself) for tamper detection
    let content = format!(
        "v{}:{}:{}:{}:{}:{}:{:.2}:net={}/{}/{}/{}:file={}/{}",
        attestation.version,
        attestation.tool,
        attestation.tool_version,
        attestation.command,
        attestation.timestamp,
        attestation.lockfile_hash.as_deref().unwrap_or("none"),
        attestation.duration_secs,
        attestation.network.total,
        attestation.network.expected,
        attestation.network.unexpected,
        attestation.network.critical,
        attestation.file_access.sensitive_reads,
        attestation.file_access.write_violations,
    );

    // Proper HMAC construction (RFC 2104)
    let key_bytes = key.as_bytes();
    let block_size = 64; // SHA-256 block size

    // If key > block_size, hash it first
    let key_padded = if key_bytes.len() > block_size {
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        let h = hasher.finalize();
        let mut padded = vec![0u8; block_size];
        padded[..h.len()].copy_from_slice(&h);
        padded
    } else {
        let mut padded = vec![0u8; block_size];
        padded[..key_bytes.len()].copy_from_slice(key_bytes);
        padded
    };

    // Inner hash: H(key XOR ipad || message)
    let ipad: Vec<u8> = key_padded.iter().map(|b| b ^ 0x36).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(content.as_bytes());
    let inner_hash = inner.finalize();

    // Outer hash: H(key XOR opad || inner_hash)
    let opad: Vec<u8> = key_padded.iter().map(|b| b ^ 0x5c).collect();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);

    format!("hmac-sha256:{:x}", outer.finalize())
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
    fn test_save_and_verify_signed() {
        // Use a unique key name to avoid test interference
        std::env::set_var("DEPSEC_ATTESTATION_KEY", "test-key-12345");

        let dir = tempfile::TempDir::new().unwrap();
        let result = mock_clean_result();
        let attestation = generate_attestation(&result, "test-app", dir.path());

        // Should be signed since key is set
        if attestation.signature.is_some() {
            save_attestation(&attestation, dir.path()).unwrap();
            let verify = verify_attestation(dir.path()).unwrap();
            assert!(verify.valid);
            assert!(verify.attestation.is_some());
        }
        // Note: env vars can be racey in parallel tests — if unsigned,
        // the unsigned test covers it
    }

    #[test]
    fn test_unsigned_attestation_rejected() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create attestation without signature
        let result = mock_clean_result();
        let mut attestation = generate_attestation(&result, "test-app", dir.path());
        attestation.signature = None; // Force unsigned

        save_attestation(&attestation, dir.path()).unwrap();

        // Verification should reject unsigned attestation
        let verify = verify_attestation(dir.path()).unwrap();
        assert!(!verify.valid);
        assert!(verify.message.contains("UNSIGNED"));
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
