use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ignore: IgnoreConfig,
    pub checks: ChecksConfig,
    pub scoring: ScoringConfig,
    pub patterns: PatternsConfig,
    pub capabilities: CapabilitiesConfig,
    pub triage: TriageConfig,
    pub install: InstallConfig,
}

/// Configuration for the patterns check
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PatternsConfig {
    /// Per-package rule allowlisting: package name → list of rule IDs to suppress
    /// Example: { "posthog-js" = ["DEPSEC-P001"], "vitest" = ["DEPSEC-P001"] }
    pub allow: HashMap<String, Vec<String>>,
    /// Additional directory names to skip inside dep dirs
    pub skip_dirs: Vec<String>,
}

/// Configuration for the capabilities check
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CapabilitiesConfig {
    /// Per-package capability allowlisting: package name → allowed capability names
    /// Example: { "@my-org/http-client" = ["network"], "my-build-tool" = ["exec", "fs_write"] }
    pub allow: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    pub patterns: Vec<String>,
    pub secrets: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ChecksConfig {
    pub enabled: Vec<String>,
}

impl Default for ChecksConfig {
    fn default() -> Self {
        Self {
            enabled: vec![
                "workflows".into(),
                "deps".into(),
                "patterns".into(),
                "secrets".into(),
                "hygiene".into(),
                "capabilities".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScoringConfig {
    pub workflows: u32,
    pub deps: u32,
    pub patterns: u32,
    pub secrets: u32,
    pub hygiene: u32,
    pub capabilities: u32,
    pub external_rules: u32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            workflows: 25,
            deps: 20,
            patterns: 10,
            secrets: 25,
            hygiene: 10,
            capabilities: 10,
            external_rules: 0,
        }
    }
}

impl ScoringConfig {
    pub fn weight_for(&self, category: &str) -> u32 {
        match category {
            "workflows" => self.workflows,
            "deps" => self.deps,
            "patterns" => self.patterns,
            "secrets" => self.secrets,
            "hygiene" => self.hygiene,
            "capabilities" => self.capabilities,
            "external_rules" => self.external_rules,
            _ => 0,
        }
    }
}

/// Configuration for LLM triage
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TriageConfig {
    /// Environment variable name holding the API key
    pub api_key_env: String,
    /// Model to use for triage (OpenRouter model ID)
    pub model: String,
    /// Maximum findings to triage per scan
    pub max_findings: usize,
    /// Timeout per API call in seconds
    pub timeout_seconds: u64,
    /// Cache TTL in days
    pub cache_ttl_days: u32,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            api_key_env: "OPENROUTER_API_KEY".into(),
            model: "anthropic/claude-sonnet-4-6".into(),
            max_findings: 50,
            timeout_seconds: 60,
            cache_ttl_days: 30,
        }
    }
}

/// Configuration for install-guard behavior
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InstallConfig {
    /// Mode: monitor (default), sandbox, report-only, none
    pub mode: String,
    /// Run preflight typosquatting check before install
    pub preflight: bool,
    /// Generate attestation after install
    pub attestation: bool,
    /// Sandbox technology: auto, bubblewrap, docker, none
    pub sandbox: String,
    /// Additional sensitive paths to watch
    pub watch_paths: Vec<String>,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            mode: "monitor".into(),
            preflight: true,
            attestation: false,
            sandbox: "none".into(),
            watch_paths: vec![],
        }
    }
}

// ── Global Config (~/.depsec/config.toml) ─────────────────────

/// Global configuration stored at ~/.depsec/config.toml
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub setup: GlobalSetupConfig,
    pub protect: GlobalProtectConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalSetupConfig {
    /// Whether shell hooks were installed
    pub shell_hook: bool,
    /// "project" or "global"
    pub hook_scope: String,
    /// Path to the shell RC file that was modified
    pub shell_profile: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalProtectConfig {
    /// true = auto-detect sandbox, false = off
    pub sandbox: bool,
}

/// Returns the path to the global config directory (~/.depsec/)
pub fn global_config_dir() -> PathBuf {
    dirs_path().join(".depsec")
}

/// Returns the path to the global config file (~/.depsec/config.toml)
pub fn global_config_path() -> PathBuf {
    global_config_dir().join("config.toml")
}

fn dirs_path() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Load global config from ~/.depsec/config.toml (returns default if missing)
pub fn load_global_config() -> GlobalConfig {
    let path = global_config_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<GlobalConfig>(&content) {
                Ok(config) => return config,
                Err(e) => {
                    eprintln!("Warning: failed to parse ~/.depsec/config.toml: {e}");
                }
            },
            Err(e) => {
                eprintln!("Warning: failed to read ~/.depsec/config.toml: {e}");
            }
        }
    }
    GlobalConfig::default()
}

/// Save global config to ~/.depsec/config.toml with 0600 permissions
pub fn save_global_config(config: &GlobalConfig) -> anyhow::Result<()> {
    let dir = global_config_dir();
    std::fs::create_dir_all(&dir)?;

    let content = toml::to_string_pretty(config)?;
    let path = global_config_path();
    std::fs::write(&path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Resolve whether sandbox should be used.
/// Priority: CLI flag > project depsec.toml > global ~/.depsec/config.toml > off
pub fn resolve_sandbox(cli_flag: Option<bool>, project: &Config, global: &GlobalConfig) -> bool {
    // CLI flag takes absolute precedence
    if let Some(flag) = cli_flag {
        return flag;
    }

    // Project config: if sandbox is explicitly set to something other than "none"
    if project.install.sandbox != "none" {
        return true;
    }

    // Project config: if mode is explicitly "sandbox"
    if project.install.mode == "sandbox" {
        return true;
    }

    // Global config
    if global.protect.sandbox {
        return true;
    }

    // Default: off (backward compat)
    false
}

// ── Project Config (depsec.toml) ──────────────────────────────

pub fn load_config(root: &Path) -> Config {
    let config_path = root.join("depsec.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => return config,
                Err(e) => {
                    eprintln!("Warning: failed to parse depsec.toml: {e}");
                }
            },
            Err(e) => {
                eprintln!("Warning: failed to read depsec.toml: {e}");
            }
        }
    }
    Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.scoring.workflows, 25);
        assert_eq!(config.scoring.deps, 20);
        assert_eq!(config.scoring.patterns, 10);
        assert_eq!(config.scoring.secrets, 25);
        assert_eq!(config.scoring.hygiene, 10);
        assert_eq!(config.scoring.capabilities, 10);
        assert_eq!(config.scoring.external_rules, 0);
        assert_eq!(config.checks.enabled.len(), 6);
        assert!(config.ignore.patterns.is_empty());
    }

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[ignore]
patterns = ["DEPSEC-P003"]
secrets = ["tests/fixtures/*"]
hosts = ["internal-mirror.company.com"]

[checks]
enabled = ["workflows", "secrets"]

[scoring]
workflows = 30
deps = 30
secrets = 20
hygiene = 10
capabilities = 10
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.ignore.patterns, vec!["DEPSEC-P003"]);
        assert_eq!(config.ignore.secrets, vec!["tests/fixtures/*"]);
        assert_eq!(config.checks.enabled.len(), 2);
        assert_eq!(config.scoring.workflows, 30);
        assert_eq!(config.scoring.secrets, 20);
    }

    #[test]
    fn test_weight_for() {
        let scoring = ScoringConfig::default();
        assert_eq!(scoring.weight_for("workflows"), 25);
        assert_eq!(scoring.weight_for("deps"), 20);
        assert_eq!(scoring.weight_for("patterns"), 10);
        assert_eq!(scoring.weight_for("unknown"), 0);
    }

    #[test]
    fn test_patterns_config() {
        let toml_str = r#"
[patterns.allow]
"posthog-js" = ["DEPSEC-P001"]
"vitest" = ["DEPSEC-P001", "DEPSEC-P007"]

[patterns]
skip_dirs = ["custom-cache"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.patterns.allow.get("posthog-js").unwrap(),
            &vec!["DEPSEC-P001".to_string()]
        );
        assert_eq!(config.patterns.allow.get("vitest").unwrap().len(), 2);
        assert_eq!(config.patterns.skip_dirs, vec!["custom-cache"]);
    }

    #[test]
    fn test_default_patterns_config() {
        let config = Config::default();
        assert!(config.patterns.allow.is_empty());
        assert!(config.patterns.skip_dirs.is_empty());
    }

    #[test]
    fn test_load_config_no_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = load_config(dir.path());
        assert_eq!(config.scoring.workflows, 25);
    }

    #[test]
    fn test_load_config_with_file() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("depsec.toml"),
            "[scoring]\nworkflows = 50\n",
        )
        .unwrap();
        let config = load_config(dir.path());
        assert_eq!(config.scoring.workflows, 50);
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("depsec.toml"), "{{invalid toml}}").unwrap();
        let config = load_config(dir.path());
        // Should fall back to defaults
        assert_eq!(config.scoring.workflows, 25);
    }

    #[test]
    fn test_default_triage_config() {
        let config = TriageConfig::default();
        assert_eq!(config.api_key_env, "OPENROUTER_API_KEY");
        assert_eq!(config.model, "anthropic/claude-sonnet-4-6");
        assert_eq!(config.max_findings, 50);
        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.cache_ttl_days, 30);
    }

    #[test]
    fn test_default_install_config() {
        let config = InstallConfig::default();
        assert_eq!(config.mode, "monitor");
        assert!(config.preflight);
        assert!(!config.attestation);
        assert_eq!(config.sandbox, "none");
        assert!(config.watch_paths.is_empty());
    }

    #[test]
    fn test_parse_triage_config() {
        let toml_str = r#"
[triage]
api_key_env = "MY_KEY"
model = "gpt-4o"
max_findings = 10
timeout_seconds = 30
cache_ttl_days = 7
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.triage.api_key_env, "MY_KEY");
        assert_eq!(config.triage.model, "gpt-4o");
        assert_eq!(config.triage.max_findings, 10);
    }

    #[test]
    fn test_global_config_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_dir = dir.path().join(".depsec");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");

        let config = GlobalConfig {
            setup: GlobalSetupConfig {
                shell_hook: true,
                hook_scope: "global".into(),
                shell_profile: "/home/user/.zshrc".into(),
            },
            protect: GlobalProtectConfig { sandbox: true },
        };

        let content = toml::to_string_pretty(&config).unwrap();
        std::fs::write(&config_path, &content).unwrap();

        let parsed: GlobalConfig = toml::from_str(&content).unwrap();
        assert!(parsed.setup.shell_hook);
        assert_eq!(parsed.setup.hook_scope, "global");
        assert_eq!(parsed.setup.shell_profile, "/home/user/.zshrc");
        assert!(parsed.protect.sandbox);
    }

    #[test]
    fn test_global_config_defaults() {
        let config = GlobalConfig::default();
        assert!(!config.setup.shell_hook);
        assert_eq!(config.setup.hook_scope, "");
        assert!(!config.protect.sandbox);
    }

    #[test]
    fn test_resolve_sandbox_cli_flag_wins() {
        let project = Config::default();
        let global = GlobalConfig {
            protect: GlobalProtectConfig { sandbox: true },
            ..Default::default()
        };
        // CLI --no-sandbox overrides global config
        assert!(!resolve_sandbox(Some(false), &project, &global));
        // CLI --sandbox overrides default off
        let global_off = GlobalConfig::default();
        assert!(resolve_sandbox(Some(true), &project, &global_off));
    }

    #[test]
    fn test_resolve_sandbox_project_config() {
        let mut project = Config::default();
        project.install.sandbox = "auto".into();
        let global = GlobalConfig::default();
        assert!(resolve_sandbox(None, &project, &global));
    }

    #[test]
    fn test_resolve_sandbox_global_config() {
        let project = Config::default(); // sandbox = "none"
        let global = GlobalConfig {
            protect: GlobalProtectConfig { sandbox: true },
            ..Default::default()
        };
        assert!(resolve_sandbox(None, &project, &global));
    }

    #[test]
    fn test_resolve_sandbox_default_off() {
        let project = Config::default();
        let global = GlobalConfig::default();
        assert!(!resolve_sandbox(None, &project, &global));
    }

    #[test]
    fn test_parse_install_config() {
        let toml_str = r#"
[install]
mode = "sandbox"
preflight = false
attestation = true
sandbox = "docker"
watch_paths = ["~/.npmrc"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.install.mode, "sandbox");
        assert!(!config.install.preflight);
        assert!(config.install.attestation);
        assert_eq!(config.install.sandbox, "docker");
        assert_eq!(config.install.watch_paths, vec!["~/.npmrc"]);
    }
}
