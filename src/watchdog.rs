use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Sensitive paths that should never be accessed by package install scripts.
/// Shared between watchdog (detection) and sandbox (prevention).
pub const SENSITIVE_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".env",
    ".npmrc",
    ".config/gh",
    ".docker/config.json",
    ".kube/config",
];

/// A detected file access by a child process
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileAlert {
    pub path: String,
    pub pid: u32,
    pub process_name: String,
}

/// A detected write outside expected directories
#[derive(Debug, Clone, serde::Serialize)]
pub struct WriteViolation {
    pub path: String,
    pub pid: u32,
    pub process_name: String,
}

/// Build the full list of sensitive paths to monitor
pub fn build_sensitive_paths(extra_paths: &[String]) -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let home = Path::new(&home);

    let mut paths: Vec<PathBuf> = SENSITIVE_PATHS.iter().map(|p| home.join(p)).collect();

    for extra in extra_paths {
        let expanded = if extra.starts_with('~') {
            home.join(extra.strip_prefix("~/").unwrap_or(extra))
        } else {
            PathBuf::from(extra)
        };
        paths.push(expanded);
    }

    paths
}

/// Check if a file path matches any sensitive path (is inside a sensitive directory)
pub fn is_sensitive_path(file_path: &str, sensitive_paths: &[PathBuf]) -> bool {
    let path = Path::new(file_path);
    sensitive_paths
        .iter()
        .any(|sp| path.starts_with(sp) || path == sp.as_path())
}

/// Scan open file descriptors for a process tree rooted at `root_pid`.
/// Returns any alerts for sensitive file access.
pub fn check_process_files(
    root_pid: u32,
    sensitive_paths: &[PathBuf],
    seen_alerts: &mut HashSet<String>,
) -> Vec<FileAlert> {
    let mut alerts = Vec::new();

    // Get all child PIDs (process tree)
    let pids = get_process_tree(root_pid);

    for pid in pids {
        let open_files = get_open_files(pid);
        for (file_path, process_name) in open_files {
            if is_sensitive_path(&file_path, sensitive_paths) {
                let key = format!("{pid}:{file_path}");
                if seen_alerts.insert(key) {
                    alerts.push(FileAlert {
                        path: file_path,
                        pid,
                        process_name,
                    });
                }
            }
        }
    }

    alerts
}

/// Check for writes outside expected directories
pub fn check_write_boundaries(
    root_pid: u32,
    allowed_write_dirs: &[PathBuf],
    seen_violations: &mut HashSet<String>,
) -> Vec<WriteViolation> {
    let mut violations = Vec::new();
    let pids = get_process_tree(root_pid);

    for pid in pids {
        let open_files = get_open_files_writable(pid);
        for (file_path, process_name) in open_files {
            let path = Path::new(&file_path);
            let is_allowed = allowed_write_dirs.iter().any(|d| path.starts_with(d));

            if !is_allowed {
                let key = format!("{pid}:{file_path}");
                if seen_violations.insert(key) {
                    violations.push(WriteViolation {
                        path: file_path,
                        pid,
                        process_name,
                    });
                }
            }
        }
    }

    violations
}

/// Public API for process tree (used by monitor for PID filtering)
pub fn get_process_tree_pub(root_pid: u32) -> Vec<u32> {
    get_process_tree(root_pid)
}

/// Get all PIDs in the process tree rooted at `root_pid` (recursive BFS — finds grandchildren)
fn get_process_tree(root_pid: u32) -> Vec<u32> {
    let mut children_map: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();

    if cfg!(target_os = "linux") {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    let stat_path = format!("/proc/{pid}/stat");
                    if let Ok(stat) = std::fs::read_to_string(&stat_path) {
                        // Parse ppid correctly — handle spaces in process names
                        // Format: pid (name with spaces) state ppid ...
                        if let Some(close_paren) = stat.rfind(')') {
                            let after = &stat[close_paren + 2..];
                            let fields: Vec<&str> = after.split_whitespace().collect();
                            if let Some(ppid_str) = fields.get(1) {
                                if let Ok(ppid) = ppid_str.parse::<u32>() {
                                    children_map.entry(ppid).or_default().push(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // macOS: single ps call for full process table
        if let Ok(output) = Command::new("ps").args(["-axo", "pid,ppid"]).output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let (Ok(pid), Ok(ppid)) =
                            (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                        {
                            children_map.entry(ppid).or_default().push(pid);
                        }
                    }
                }
            }
        }
    }

    // BFS from root_pid to collect full descendant tree
    let mut result = vec![root_pid];
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_pid);

    while let Some(pid) = queue.pop_front() {
        if let Some(children) = children_map.get(&pid) {
            for &child in children {
                result.push(child);
                queue.push_back(child);
            }
        }
    }

    result
}

/// Get open files for a process (all file descriptors)
fn get_open_files(pid: u32) -> Vec<(String, String)> {
    if cfg!(target_os = "linux") {
        get_open_files_proc(pid)
    } else {
        get_open_files_lsof(pid)
    }
}

/// Get writable open files for a process
fn get_open_files_writable(pid: u32) -> Vec<(String, String)> {
    if cfg!(target_os = "linux") {
        get_open_files_writable_proc(pid)
    } else {
        get_open_files_writable_lsof(pid)
    }
}

/// Linux: read /proc/PID/fd to find open file paths
fn get_open_files_proc(pid: u32) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let fd_dir = format!("/proc/{pid}/fd");

    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        let process_name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();

        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let path = target.to_string_lossy().to_string();
                if !path.starts_with("/dev/")
                    && !path.starts_with("pipe:")
                    && !path.starts_with("socket:")
                {
                    files.push((path, process_name.clone()));
                }
            }
        }
    }

    files
}

/// Linux: check /proc/PID/fdinfo for writable files
fn get_open_files_writable_proc(pid: u32) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let fd_dir = format!("/proc/{pid}/fd");

    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        let process_name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();

        for entry in entries.flatten() {
            let fd_num = entry.file_name().to_string_lossy().to_string();
            let fdinfo_path = format!("/proc/{pid}/fdinfo/{fd_num}");

            // Check if file is opened for writing (flags contain O_WRONLY or O_RDWR)
            if let Ok(fdinfo) = std::fs::read_to_string(&fdinfo_path) {
                let is_writable = fdinfo.lines().any(|l| {
                    if let Some(flags_str) = l.strip_prefix("flags:\t") {
                        if let Ok(flags) = u32::from_str_radix(flags_str.trim_start_matches("0"), 8)
                        {
                            return flags & 0o3 != 0; // O_WRONLY=1 or O_RDWR=2
                        }
                    }
                    false
                });

                if is_writable {
                    if let Ok(target) = std::fs::read_link(entry.path()) {
                        let path = target.to_string_lossy().to_string();
                        if !path.starts_with("/dev/") {
                            files.push((path, process_name.clone()));
                        }
                    }
                }
            }
        }
    }

    files
}

/// macOS: use lsof to find open files for a process
fn get_open_files_lsof(pid: u32) -> Vec<(String, String)> {
    let output = Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fcn"])
        .output();

    match output {
        Ok(out) => parse_lsof_output(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => vec![],
    }
}

/// macOS: use lsof with write filter
fn get_open_files_writable_lsof(pid: u32) -> Vec<(String, String)> {
    let output = Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fcna"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Filter for write access (a field contains 'w' or 'u')
            parse_lsof_output_writable(&stdout)
        }
        Err(_) => vec![],
    }
}

/// Parse lsof -Fn output (field-based format)
fn parse_lsof_output(output: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut current_process = String::new();

    for line in output.lines() {
        if let Some(name) = line.strip_prefix('c') {
            current_process = name.trim().to_string();
        } else if let Some(path) = line.strip_prefix('n') {
            if !path.starts_with("/dev/") && path.starts_with('/') {
                files.push((path.to_string(), current_process.clone()));
            }
        }
    }

    files
}

/// Parse lsof -Fna output for writable files
fn parse_lsof_output_writable(output: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut current_process = String::new();
    let mut current_access = String::new();

    for line in output.lines() {
        if let Some(name) = line.strip_prefix('c') {
            current_process = name.trim().to_string();
        } else if line.starts_with('f') {
            // Reset access mode on new file descriptor boundary
            current_access.clear();
        } else if let Some(access) = line.strip_prefix('a') {
            current_access = access.to_string();
        } else if let Some(path) = line.strip_prefix('n') {
            if (current_access == "w" || current_access == "u")
                && !path.starts_with("/dev/")
                && path.starts_with('/')
            {
                files.push((path.to_string(), current_process.clone()));
            }
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sensitive_paths() {
        let paths = build_sensitive_paths(&[]);
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.to_string_lossy().contains(".ssh")));
        assert!(paths.iter().any(|p| p.to_string_lossy().contains(".aws")));
        assert!(paths.iter().any(|p| p.to_string_lossy().contains(".gnupg")));
    }

    #[test]
    fn test_build_sensitive_paths_with_extras() {
        let extra = vec!["~/.kube/config".into()];
        let paths = build_sensitive_paths(&extra);
        assert!(paths.iter().any(|p| p.to_string_lossy().contains(".kube")));
    }

    #[test]
    fn test_is_sensitive_path() {
        let home = std::env::var("HOME").unwrap();
        let paths = build_sensitive_paths(&[]);

        assert!(is_sensitive_path(&format!("{home}/.ssh/id_rsa"), &paths));
        assert!(is_sensitive_path(
            &format!("{home}/.aws/credentials"),
            &paths
        ));
        assert!(!is_sensitive_path("/tmp/safe-file.txt", &paths));
        assert!(!is_sensitive_path(
            "/usr/lib/node_modules/pkg/index.js",
            &paths
        ));
    }

    #[test]
    fn test_is_sensitive_path_env_file() {
        let home = std::env::var("HOME").unwrap();
        let paths = build_sensitive_paths(&[]);
        assert!(is_sensitive_path(&format!("{home}/.env"), &paths));
    }

    #[test]
    fn test_parse_lsof_output() {
        let output =
            "p1234\nc node\nn/Users/dev/.ssh/id_rsa\nn/Users/dev/project/index.js\nn/dev/null\n";
        let files = parse_lsof_output(output);

        assert_eq!(files.len(), 2); // .ssh/id_rsa and project/index.js, not /dev/null
        assert_eq!(files[0].0, "/Users/dev/.ssh/id_rsa");
        assert_eq!(files[0].1, "node");
    }

    #[test]
    fn test_parse_lsof_output_writable() {
        let output = "p1234\nc node\naw\nn/tmp/malicious.js\nar\nn/Users/dev/.ssh/id_rsa\nau\nn/tmp/both-rw.txt\n";
        let files = parse_lsof_output_writable(output);

        assert_eq!(files.len(), 2); // write + read-write, not read-only
        assert_eq!(files[0].0, "/tmp/malicious.js");
        assert_eq!(files[1].0, "/tmp/both-rw.txt");
    }

    #[test]
    fn test_dedup_alerts() {
        let paths = build_sensitive_paths(&[]);
        let mut seen = HashSet::new();

        // First call should produce alerts
        // (Can't test with real PIDs in unit tests, but verify dedup logic)
        let key1 = "1234:/home/user/.ssh/id_rsa".to_string();
        assert!(seen.insert(key1.clone()));
        assert!(!seen.insert(key1)); // Duplicate suppressed
    }

    #[test]
    fn test_get_process_tree_self() {
        // Should at least find our own PID
        let pids = get_process_tree(std::process::id());
        assert!(pids.contains(&std::process::id()));
    }
}
