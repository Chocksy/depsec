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
}
