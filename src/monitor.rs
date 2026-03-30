use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use regex::Regex;

const POLL_INTERVAL_MS: u64 = 100;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Connection {
    pub remote_host: String,
    pub remote_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub cmdline: String,
}

#[derive(Debug, serde::Serialize)]
pub struct MonitorResult {
    pub command: String,
    pub exit_code: i32,
    pub duration_secs: f64,
    pub connections: Vec<Connection>,
    pub expected: Vec<Connection>,
    pub unexpected: Vec<Connection>,
    pub critical: Vec<Connection>,
    pub file_alerts: Vec<crate::watchdog::FileAlert>,
    pub write_violations: Vec<crate::watchdog::WriteViolation>,
}

/// Known-malicious IPs that are always flagged
const ALWAYS_BLOCK: &[&str] = &["169.254.169.254", "169.254.170.2"];

/// Expected registry hosts per package manager process
fn default_expected_hosts() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("npm", vec!["registry.npmjs.org"]);
    m.insert("node", vec!["registry.npmjs.org"]);
    m.insert("yarn", vec!["registry.yarnpkg.com", "registry.npmjs.org"]);
    m.insert("pnpm", vec!["registry.npmjs.org"]);
    m.insert("pip", vec!["pypi.org", "files.pythonhosted.org"]);
    m.insert("pip3", vec!["pypi.org", "files.pythonhosted.org"]);
    m.insert("python", vec!["pypi.org", "files.pythonhosted.org"]);
    m.insert("python3", vec!["pypi.org", "files.pythonhosted.org"]);
    m.insert("uv", vec!["pypi.org", "files.pythonhosted.org"]);
    m.insert(
        "cargo",
        vec!["crates.io", "static.crates.io", "index.crates.io"],
    );
    m.insert("go", vec!["proxy.golang.org", "sum.golang.org"]);
    m.insert("bundle", vec!["rubygems.org", "index.rubygems.org"]);
    m.insert("gem", vec!["rubygems.org", "index.rubygems.org"]);
    m
}

/// Hosts always expected (GitHub, DNS, etc.)
const UNIVERSAL_EXPECTED: &[&str] = &[
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
];

/// Run a command and monitor its network activity.
pub fn run_monitor(
    args: &[String],
    baseline_path: Option<&Path>,
    learn_mode: bool,
    json_output: bool,
) -> anyhow::Result<MonitorResult> {
    if args.is_empty() {
        anyhow::bail!("No command specified. Usage: depsec monitor <command> [args...]");
    }

    let command_str = args.join(" ");
    let start = std::time::Instant::now();

    // Shared state for connections collected by the polling thread
    let connections: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_addrs: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // Spawn the monitored command
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("Failed to start: {}", args[0]))?;

    let child_pid = child.id();

    // Start network polling in a background thread
    let conn_clone = connections.clone();
    let seen_clone = seen_addrs.clone();
    let running_clone = running.clone();

    let poll_handle = std::thread::spawn(move || {
        poll_connections(child_pid, &conn_clone, &seen_clone, &running_clone);
    });

    // Start file access watchdog in a parallel thread
    let file_alerts: Arc<Mutex<Vec<crate::watchdog::FileAlert>>> = Arc::new(Mutex::new(Vec::new()));
    let write_violations: Arc<Mutex<Vec<crate::watchdog::WriteViolation>>> =
        Arc::new(Mutex::new(Vec::new()));
    let running_watchdog = running.clone();
    let alerts_clone = file_alerts.clone();
    let violations_clone = write_violations.clone();

    let sensitive_paths = crate::watchdog::build_sensitive_paths(&[]);
    let project_root = std::env::current_dir().unwrap_or_default();
    let allowed_write_dirs: Vec<std::path::PathBuf> = vec![
        project_root.join("node_modules"),
        project_root.join("vendor"),
        project_root.join(".venv"),
        std::env::temp_dir(),
    ];

    let watchdog_handle = std::thread::spawn(move || {
        let mut seen_alerts = std::collections::HashSet::new();
        let mut seen_violations = std::collections::HashSet::new();

        while running_watchdog.load(std::sync::atomic::Ordering::Relaxed) {
            let new_alerts =
                crate::watchdog::check_process_files(child_pid, &sensitive_paths, &mut seen_alerts);
            if !new_alerts.is_empty() {
                alerts_clone.lock().unwrap().extend(new_alerts);
            }

            let new_violations = crate::watchdog::check_write_boundaries(
                child_pid,
                &allowed_write_dirs,
                &mut seen_violations,
            );
            if !new_violations.is_empty() {
                violations_clone.lock().unwrap().extend(new_violations);
            }

            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
    });

    // Wait for the child to finish
    let status = child.wait().context("Failed to wait for child process")?;
    let duration = start.elapsed();

    // Stop both polling threads
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = poll_handle.join();
    let _ = watchdog_handle.join();

    let all_connections = connections.lock().unwrap().clone();
    let all_file_alerts = file_alerts.lock().unwrap().clone();
    let all_write_violations = write_violations.lock().unwrap().clone();

    // Load baseline for comparison
    let user_baseline = baseline_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok());

    let user_allowed: HashSet<String> = user_baseline
        .as_ref()
        .and_then(|b| b.get("allowed_hosts"))
        .and_then(|h| h.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let defaults = default_expected_hosts();

    // Classify connections
    let mut expected = Vec::new();
    let mut unexpected = Vec::new();
    let mut critical = Vec::new();

    for conn in &all_connections {
        if ALWAYS_BLOCK.iter().any(|b| conn.remote_host == *b) {
            critical.push(conn.clone());
        } else if is_expected_connection(conn, &defaults, &user_allowed) {
            expected.push(conn.clone());
        } else {
            unexpected.push(conn.clone());
        }
    }

    // In learn mode, save all connections as a baseline
    if learn_mode {
        save_learned_baseline(&all_connections, baseline_path)?;
    }

    let result = MonitorResult {
        command: command_str,
        exit_code: status.code().unwrap_or(-1),
        duration_secs: duration.as_secs_f64(),
        connections: all_connections,
        expected,
        unexpected,
        critical,
        file_alerts: all_file_alerts,
        write_violations: all_write_violations,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_monitor_result(&result);
    }

    Ok(result)
}

fn is_expected_connection(
    conn: &Connection,
    defaults: &HashMap<&str, Vec<&str>>,
    user_allowed: &HashSet<String>,
) -> bool {
    // Check universal hosts
    if UNIVERSAL_EXPECTED
        .iter()
        .any(|h| conn.remote_host.contains(h))
    {
        return true;
    }

    // Check user baseline
    if user_allowed.contains(&conn.remote_host) {
        return true;
    }

    // Check process-specific defaults
    let process_base = conn
        .process_name
        .rsplit('/')
        .next()
        .unwrap_or(&conn.process_name);

    if let Some(expected_hosts) = defaults.get(process_base) {
        if expected_hosts.iter().any(|h| conn.remote_host.contains(h)) {
            return true;
        }
    }

    false
}

/// Poll network connections using ss (Linux) or lsof (macOS)
fn poll_connections(
    _child_pid: u32,
    connections: &Arc<Mutex<Vec<Connection>>>,
    seen: &Arc<Mutex<HashSet<String>>>,
    running: &Arc<std::sync::atomic::AtomicBool>,
) {
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        if let Ok(conns) = get_current_connections() {
            let mut seen_lock = seen.lock().unwrap();
            let mut conns_lock = connections.lock().unwrap();

            for conn in conns {
                let key = format!("{}:{}:{}", conn.remote_host, conn.remote_port, conn.pid);
                if seen_lock.insert(key) {
                    conns_lock.push(conn);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

/// Get current TCP connections with process info
fn get_current_connections() -> anyhow::Result<Vec<Connection>> {
    if cfg!(target_os = "linux") {
        get_connections_ss()
    } else {
        get_connections_lsof()
    }
}

/// Linux: parse `ss -tnp` output
fn get_connections_ss() -> anyhow::Result<Vec<Connection>> {
    let output = Command::new("ss")
        .args(["-tnp"])
        .output()
        .context("Failed to run ss")?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let re = Regex::new(
        r#"ESTAB\s+\d+\s+\d+\s+\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+.*users:\(\("([^"]+)",pid=(\d+)"#,
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in stdout.lines() {
        if let Some(caps) = re.captures(line) {
            let remote_host = caps[1].to_string();
            let remote_port: u16 = caps[2].parse().unwrap_or(0);
            let process_name = caps[3].to_string();
            let pid: u32 = caps[4].parse().unwrap_or(0);

            let cmdline = read_proc_cmdline(pid);

            connections.push(Connection {
                remote_host,
                remote_port,
                pid,
                process_name,
                cmdline,
            });
        }
    }

    Ok(connections)
}

/// macOS: parse `lsof -i -n -P` output
fn get_connections_lsof() -> anyhow::Result<Vec<Connection>> {
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "+c0"])
        .output()
        .context("Failed to run lsof")?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    // lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // NAME format: host:port->remote_host:remote_port (ESTABLISHED)
    let re = Regex::new(r"->(\d+\.\d+\.\d+\.\d+):(\d+)\s+\(ESTABLISHED\)")?;

    for line in stdout.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let process_name = parts[0].to_string();
        let pid: u32 = parts[1].parse().unwrap_or(0);
        let name_field = parts.last().unwrap_or(&"");

        // Join remaining fields to handle names with spaces
        let name_str = parts[8..].join(" ");

        if let Some(caps) = re.captures(&name_str) {
            connections.push(Connection {
                remote_host: caps[1].to_string(),
                remote_port: caps[2].parse().unwrap_or(0),
                pid,
                process_name,
                cmdline: format!("{} (pid {})", name_field, pid),
            });
        }
    }

    Ok(connections)
}

/// Read /proc/<pid>/cmdline on Linux
fn read_proc_cmdline(pid: u32) -> String {
    let path = format!("/proc/{pid}/cmdline");
    std::fs::read_to_string(&path)
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_else(|_| format!("(pid {pid})"))
}

fn save_learned_baseline(connections: &[Connection], path: Option<&Path>) -> anyhow::Result<()> {
    let output_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".depsec/monitor-baseline.json"));

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut hosts: Vec<String> = connections
        .iter()
        .map(|c| c.remote_host.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    hosts.sort();

    let baseline = serde_json::json!({
        "version": 1,
        "learned": true,
        "allowed_hosts": hosts,
    });

    std::fs::write(&output_path, serde_json::to_string_pretty(&baseline)?)?;
    eprintln!(
        "Baseline saved to {} ({} hosts learned)",
        output_path.display(),
        hosts.len()
    );

    Ok(())
}

fn print_monitor_result(result: &MonitorResult) {
    println!(
        "\ndepsec monitor — {} completed in {:.1}s (exit code {})\n",
        result.command, result.duration_secs, result.exit_code
    );

    if result.connections.is_empty() {
        println!("[Network Activity]");
        println!("  No outbound connections detected.");
        return;
    }

    println!(
        "[Network Activity] {} connection{} monitored\n",
        result.connections.len(),
        if result.connections.len() == 1 {
            ""
        } else {
            "s"
        }
    );

    for conn in &result.critical {
        println!(
            "  \x1b[31m✗\x1b[0m {}:{} — \x1b[31mCRITICAL: cloud credential endpoint!\x1b[0m",
            conn.remote_host, conn.remote_port
        );
        println!("    → Process: {} (pid {})", conn.process_name, conn.pid);
        if !conn.cmdline.is_empty() && conn.cmdline != format!("(pid {})", conn.pid) {
            println!("    → Command: {}", conn.cmdline);
        }
    }

    for conn in &result.unexpected {
        println!(
            "  \x1b[31m✗\x1b[0m {}:{} — UNEXPECTED",
            conn.remote_host, conn.remote_port
        );
        println!("    → Process: {} (pid {})", conn.process_name, conn.pid);
        if !conn.cmdline.is_empty() && conn.cmdline != format!("(pid {})", conn.pid) {
            println!("    → Command: {}", conn.cmdline);
        }
    }

    for conn in &result.expected {
        println!(
            "  \x1b[32m✓\x1b[0m {}:{} — expected ({})",
            conn.remote_host, conn.remote_port, conn.process_name
        );
    }

    // File access alerts
    println!("\n[File Access]");
    if result.file_alerts.is_empty() {
        println!("  \x1b[32m✓\x1b[0m No sensitive files accessed");
    } else {
        for alert in &result.file_alerts {
            println!(
                "  \x1b[31m🔴 READ {}\x1b[0m — by {} (pid {})",
                alert.path, alert.process_name, alert.pid
            );
        }
    }

    // Write boundary violations
    if !result.write_violations.is_empty() {
        println!("\n[Write Boundary]");
        for violation in &result.write_violations {
            println!(
                "  \x1b[31m⚠ WRITE outside expected dirs: {}\x1b[0m — by {} (pid {})",
                violation.path, violation.process_name, violation.pid
            );
        }
    }

    println!();
    let total = result.connections.len();
    let bad = result.unexpected.len() + result.critical.len();
    let file_issues = result.file_alerts.len() + result.write_violations.len();

    if bad > 0 || file_issues > 0 {
        print!("{total} connections monitored");
        if bad > 0 {
            print!(", \x1b[31m{bad} unexpected\x1b[0m");
        }
        if !result.file_alerts.is_empty() {
            print!(
                ", \x1b[31m{} sensitive file reads\x1b[0m",
                result.file_alerts.len()
            );
        }
        if !result.write_violations.is_empty() {
            print!(
                ", \x1b[31m{} write violations\x1b[0m",
                result.write_violations.len()
            );
        }
        println!(".");
    } else {
        println!("{total} connections monitored, all expected. No file access issues.");
    }
}
