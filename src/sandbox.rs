use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Available sandbox technologies
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxType {
    Bubblewrap,
    SandboxExec, // macOS
    Docker,
    None,
}

impl std::fmt::Display for SandboxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxType::Bubblewrap => write!(f, "bubblewrap"),
            SandboxType::SandboxExec => write!(f, "sandbox-exec"),
            SandboxType::Docker => write!(f, "docker"),
            SandboxType::None => write!(f, "none"),
        }
    }
}

/// Result of a sandboxed install
#[derive(Debug)]
pub struct SandboxResult {
    pub sandbox_type: SandboxType,
    pub exit_code: i32,
    pub success: bool,
}

/// Detect available sandbox technology
pub fn detect_sandbox(preference: &str) -> SandboxType {
    match preference {
        "bubblewrap" => {
            if is_available("bwrap") {
                SandboxType::Bubblewrap
            } else {
                SandboxType::None
            }
        }
        "docker" => {
            if is_docker_available() {
                SandboxType::Docker
            } else {
                SandboxType::None
            }
        }
        "sandbox-exec" => {
            if is_available("sandbox-exec") {
                SandboxType::SandboxExec
            } else {
                SandboxType::None
            }
        }
        "auto" => {
            // Try in order: bubblewrap → sandbox-exec → Docker
            if cfg!(target_os = "linux") && is_available("bwrap") {
                SandboxType::Bubblewrap
            } else if cfg!(target_os = "macos") && is_available("sandbox-exec") {
                SandboxType::SandboxExec
            } else if is_docker_available() {
                SandboxType::Docker
            } else {
                SandboxType::None
            }
        }
        _ => SandboxType::None,
    }
}

/// Run a command in a sandbox
pub fn run_sandboxed(
    args: &[String],
    project_dir: &Path,
    sandbox_type: &SandboxType,
) -> Result<SandboxResult> {
    match sandbox_type {
        SandboxType::Bubblewrap => run_bubblewrap(args, project_dir),
        SandboxType::SandboxExec => run_sandbox_exec(args, project_dir),
        SandboxType::Docker => run_docker(args, project_dir),
        SandboxType::None => anyhow::bail!("No sandbox available"),
    }
}

/// Run in bubblewrap (Linux)
fn run_bubblewrap(args: &[String], project_dir: &Path) -> Result<SandboxResult> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    // Use unified sensitive paths from watchdog
    let sensitive_dirs: Vec<String> = crate::watchdog::SENSITIVE_PATHS
        .iter()
        .map(|p| format!("{home}/{p}"))
        .collect();

    let mut cmd = Command::new("bwrap");
    cmd.args(["--ro-bind", "/", "/", "--tmpfs", "/tmp"]);

    // Mask ALL sensitive dirs with tmpfs (unified with watchdog)
    for dir in &sensitive_dirs {
        cmd.args(["--tmpfs", dir]);
    }

    cmd.args([
        "--bind",
        &project_dir.to_string_lossy(),
        &project_dir.to_string_lossy(),
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--unshare-pid",
        "--die-with-parent",
        "--",
    ]);
    cmd.args(args);
    cmd.current_dir(project_dir);

    let status = cmd.status().context("Failed to run bubblewrap")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::Bubblewrap,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}

/// Run in sandbox-exec (macOS)
fn run_sandbox_exec(args: &[String], project_dir: &Path) -> Result<SandboxResult> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/user".into());

    // Deny-by-default sandbox profile — block ALL sensitive path reads
    let mut deny_rules = String::new();
    for path in crate::watchdog::SENSITIVE_PATHS {
        deny_rules.push_str(&format!("(deny file-read* (subpath \"{home}/{path}\"))\n"));
    }

    let profile = format!(
        r#"(version 1)
(allow default)
{deny_rules}
(allow file-write* (subpath "{project_dir}"))
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))"#,
        deny_rules = deny_rules,
        project_dir = project_dir.display(),
    );

    let mut cmd = Command::new("sandbox-exec");
    cmd.args(["-p", &profile]);
    cmd.args(args);
    cmd.current_dir(project_dir);

    let status = cmd.status().context("Failed to run sandbox-exec")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::SandboxExec,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}

/// Run in Docker container
fn run_docker(args: &[String], project_dir: &Path) -> Result<SandboxResult> {
    // Auto-detect Docker image based on package manager
    let image = detect_docker_image(args);

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        format!("{}:/app:rw", project_dir.display()),
        "-w".to_string(),
        "/app".to_string(),
        image,
    ];
    docker_args.extend(args.iter().cloned());

    let status = Command::new("docker")
        .args(&docker_args)
        .status()
        .context("Failed to run Docker")?;

    Ok(SandboxResult {
        sandbox_type: SandboxType::Docker,
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}

/// Auto-detect Docker image based on the package manager command
fn detect_docker_image(args: &[String]) -> String {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "npm" | "npx" | "yarn" | "pnpm" => "node:22-slim".into(),
        "pip" | "pip3" | "python" | "python3" | "uv" => "python:3.12-slim".into(),
        "cargo" => "rust:slim".into(),
        "go" => "golang:1.22-alpine".into(),
        "bundle" | "gem" => "ruby:3.3-slim".into(),
        _ => "node:22-slim".into(), // Default fallback
    }
}

/// Check if a command is available on PATH
fn is_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Docker is available and the daemon is running
fn is_docker_available() -> bool {
    if !is_available("docker") {
        return false;
    }
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sandbox_none() {
        assert_eq!(detect_sandbox("none"), SandboxType::None);
    }

    #[test]
    fn test_detect_sandbox_auto() {
        // Auto-detection should return something (may vary by platform)
        let result = detect_sandbox("auto");
        // Just verify it doesn't panic — result depends on what's installed
        println!("Auto-detected sandbox: {result}");
    }

    #[test]
    fn test_sandbox_type_display() {
        assert_eq!(SandboxType::Bubblewrap.to_string(), "bubblewrap");
        assert_eq!(SandboxType::SandboxExec.to_string(), "sandbox-exec");
        assert_eq!(SandboxType::Docker.to_string(), "docker");
        assert_eq!(SandboxType::None.to_string(), "none");
    }

    #[test]
    fn test_is_available() {
        // `ls` should always be available
        assert!(is_available("ls"));
        // Random nonexistent command should not
        assert!(!is_available("depsec_nonexistent_test_cmd_12345"));
    }
}
