use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ignore: IgnoreConfig,
    pub checks: ChecksConfig,
    pub scoring: ScoringConfig,
    pub patterns: PatternsConfig,
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
    pub network: u32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            workflows: 25,
            deps: 20,
            patterns: 10,
            secrets: 25,
            hygiene: 10,
            network: 10,
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
            "network" => self.network,
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
        assert_eq!(config.scoring.network, 10);
        assert_eq!(config.checks.enabled.len(), 5);
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
network = 10
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
