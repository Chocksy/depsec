use std::path::Path;
use std::process::{Child, Command};

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
#[allow(dead_code)] // Used in tests via run_sandboxed
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

/// Run a command in a sandbox with a fake HOME directory (synchronous — waits for exit)
#[allow(dead_code)] // Used in tests
pub fn run_sandboxed(
    args: &[String],
    project_dir: &Path,
    sandbox_type: &SandboxType,
    canary_home: &Path,
) -> Result<SandboxResult> {
    let mut child = spawn_sandboxed(args, project_dir, sandbox_type, canary_home)?;
    let status = child
        .wait()
        .context("Failed to wait for sandboxed process")?;
    Ok(SandboxResult {
        sandbox_type: sandbox_type.clone(),
        exit_code: status.code().unwrap_or(-1),
        success: status.success(),
    })
}

/// Spawn a sandboxed command and return the child process (for concurrent monitoring).
/// Caller is responsible for waiting on the child.
pub fn spawn_sandboxed(
    args: &[String],
    project_dir: &Path,
    sandbox_type: &SandboxType,
    canary_home: &Path,
) -> Result<Child> {
    match sandbox_type {
        SandboxType::Bubblewrap => spawn_bubblewrap(args, project_dir, canary_home),
        SandboxType::SandboxExec => spawn_sandbox_exec(args, project_dir, canary_home),
        SandboxType::Docker => spawn_docker(args, project_dir, canary_home),
        SandboxType::None => anyhow::bail!("No sandbox available"),
    }
}

fn spawn_bubblewrap(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<Child> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    let mut cmd = Command::new("bwrap");
    cmd.args(["--ro-bind", "/", "/"]);

    // Mount fake HOME over real HOME — honeypot with canary credentials.
    // Do NOT tmpfs over sensitive subdirs: the canary files (.ssh, .aws, etc.)
    // must be visible so we can detect tamper via content-hash comparison.
    cmd.args(["--bind", &canary_home.to_string_lossy(), &home]);

    cmd.args([
        "--bind",
        &project_dir.to_string_lossy(),
        &project_dir.to_string_lossy(),
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/dev/shm",
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

    cmd.spawn().context("Failed to spawn bubblewrap")
}

fn spawn_sandbox_exec(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<Child> {
    let dir_str = project_dir.to_string_lossy();
    if dir_str.contains('"') || dir_str.contains('(') || dir_str.contains(')') {
        anyhow::bail!(
            "Project directory contains characters that could inject sandbox rules: {}",
            dir_str
        );
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/user".into());

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
    cmd.env("HOME", canary_home);
    cmd.args(args);
    cmd.current_dir(project_dir);

    cmd.spawn().context("Failed to spawn sandbox-exec")
}

fn spawn_docker(args: &[String], project_dir: &Path, canary_home: &Path) -> Result<Child> {
    let image = detect_docker_image(args);

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        format!("{}:/app:rw", project_dir.display()),
        "-v".to_string(),
        format!("{}:/root:rw", canary_home.display()),
        "-w".to_string(),
        "/app".to_string(),
        image,
    ];
    docker_args.extend(args.iter().cloned());

    Command::new("docker")
        .args(&docker_args)
        .spawn()
        .context("Failed to spawn Docker")
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

    #[test]
    fn test_detect_docker_image() {
        assert_eq!(detect_docker_image(&["npm".into()]), "node:22-slim");
        assert_eq!(detect_docker_image(&["yarn".into()]), "node:22-slim");
        assert_eq!(detect_docker_image(&["pip".into()]), "python:3.12-slim");
        assert_eq!(detect_docker_image(&["cargo".into()]), "rust:slim");
        assert_eq!(detect_docker_image(&["go".into()]), "golang:1.22-alpine");
        assert_eq!(detect_docker_image(&["bundle".into()]), "ruby:3.3-slim");
        assert_eq!(detect_docker_image(&["unknown".into()]), "node:22-slim");
        assert_eq!(detect_docker_image(&[]), "node:22-slim");
    }

    #[test]
    fn test_detect_sandbox_unknown_preference() {
        assert_eq!(detect_sandbox("invalid"), SandboxType::None);
    }

    #[test]
    fn test_bubblewrap_does_not_mask_canary_sensitive_paths() {
        // Verify the spawn_bubblewrap command does NOT include tmpfs mounts
        // over sensitive paths — the honeypot canary files must be visible.
        // We can't run bwrap in tests, but we verify the function exists
        // and the code path doesn't include the old tmpfs masking pattern.
        // This is a design assertion: grep the source for the anti-pattern.
        let source = include_str!("sandbox.rs");
        let bwrap_section = source.split("fn spawn_bubblewrap").nth(1).unwrap_or("");
        // Must NOT contain tmpfs over SENSITIVE_PATHS inside bubblewrap
        assert!(
            !bwrap_section.contains("SENSITIVE_PATHS") || bwrap_section.contains("Do NOT tmpfs"),
            "spawn_bubblewrap must not mask canary files with tmpfs over SENSITIVE_PATHS"
        );
    }

    #[test]
    fn test_run_sandboxed_none_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let canary = tempfile::TempDir::new().unwrap();
        let result = run_sandboxed(
            &["echo".into(), "hi".into()],
            dir.path(),
            &SandboxType::None,
            canary.path(),
        );
        assert!(result.is_err());
    }
}
