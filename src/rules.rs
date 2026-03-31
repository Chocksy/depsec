use std::path::{Path, PathBuf};

use anyhow::Context;
use regex::Regex;
use serde::Deserialize;

use crate::checks::{Finding, Severity};

const RULES_DIR: &str = ".depsec/rules";
const GLOBAL_RULES_DIR: &str = ".config/depsec/rules";
const COMMUNITY_REPO_URL: &str = "https://api.github.com/repos/chocksy/depsec-rules/contents/rules";

#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub rule: RuleDef,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RuleDef {
    pub id: String,
    pub name: String,
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(rename = "match")]
    pub match_config: MatchConfig,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MatchConfig {
    #[serde(default)]
    pub file_patterns: Vec<String>,
    #[serde(default)]
    pub content_patterns: Vec<String>,
    #[serde(default)]
    pub scan_directories: Vec<String>,
}

impl RuleDef {
    pub fn severity(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

/// Load all external rules from project and global directories
pub fn load_external_rules(root: &Path) -> Vec<RuleDef> {
    let mut rules = Vec::new();

    // Project-level rules
    let project_dir = root.join(RULES_DIR);
    if project_dir.exists() {
        load_rules_from_dir(&project_dir, &mut rules);
    }

    // Global rules
    if let Some(home) = dirs_home() {
        let global_dir = home.join(GLOBAL_RULES_DIR);
        if global_dir.exists() {
            load_rules_from_dir(&global_dir, &mut rules);
        }
    }

    rules
}

fn load_rules_from_dir(dir: &Path, rules: &mut Vec<RuleDef>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        match load_rule_file(&path) {
            Ok(rule) => rules.push(rule),
            Err(e) => eprintln!("Warning: failed to load rule {}: {e}", path.display()),
        }
    }
}

fn load_rule_file(path: &Path) -> anyhow::Result<RuleDef> {
    let content = std::fs::read_to_string(path).context("Failed to read rule file")?;
    let rule_file: RuleFile = toml::from_str(&content).context("Failed to parse rule file")?;
    Ok(rule_file.rule)
}

/// Apply external rules against scanned files, returning findings
pub fn apply_rules(rules: &[RuleDef], root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        let compiled_patterns: Vec<Regex> = rule
            .match_config
            .content_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        if compiled_patterns.is_empty() {
            continue;
        }

        // Determine which directories to scan
        let scan_dirs: Vec<PathBuf> = if rule.match_config.scan_directories.is_empty() {
            vec![root.to_path_buf()]
        } else {
            rule.match_config
                .scan_directories
                .iter()
                .map(|d| root.join(d))
                .filter(|p| p.exists())
                .collect()
        };

        for dir in &scan_dirs {
            for entry in walkdir::WalkDir::new(dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();

                // Check file pattern match
                if !rule.match_config.file_patterns.is_empty() {
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    let matches_pattern = rule.match_config.file_patterns.iter().any(|pattern| {
                        if let Some(ext) = pattern.strip_prefix("*.") {
                            filename.ends_with(&format!(".{ext}"))
                        } else {
                            filename == pattern
                        }
                    });
                    if !matches_pattern {
                        continue;
                    }
                }

                let content = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let rel_path = path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                for (line_num, line) in content.lines().enumerate() {
                    for re in &compiled_patterns {
                        if re.is_match(line) {
                            let mut f = Finding::new(
                                rule.id.clone(),
                                rule.severity(),
                                format!("{}: {}", rule.name, line.trim()),
                            )
                            .with_file(&rel_path, line_num + 1);
                            if !rule.description.is_empty() {
                                f = f.with_suggestion(rule.description.clone());
                            }
                            findings.push(f);
                            break; // One match per line per rule
                        }
                    }
                }
            }
        }
    }

    findings
}

/// List all active rules (built-in + external)
pub fn list_rules(root: &Path) {
    let external = load_external_rules(root);

    println!("Built-in rules:");
    println!("  DEPSEC-W001..W005  Workflow security (5 rules)");
    println!("  DEPSEC-P001..P019  Malicious patterns (17 rules)");
    println!("  DEPSEC-CAP:*       Capability analysis (8 combination rules)");
    println!("  DEPSEC-S001..S020  Secret detection (20 rules)");
    println!("  DEPSEC-H001..H004  Repo hygiene (4 rules)");
    println!("  DEPSEC-T001..T007  Trust/metadata (7 rules)");
    println!("  DEPSEC-V:*         Vulnerability advisories (live from OSV)");
    println!("  DEPSEC-MAL:*       Malicious packages (live from OSV)");
    println!();

    if external.is_empty() {
        println!("External rules: none");
        println!("  Add rules to {} or run 'depsec rules update'", RULES_DIR);
    } else {
        println!("External rules ({}):", external.len());
        for rule in &external {
            println!(
                "  {}  {} [{}]",
                rule.id,
                rule.name,
                rule.severity.to_uppercase()
            );
        }
    }
}

/// Update rules from community repository
pub fn update_rules(root: &Path) -> anyhow::Result<usize> {
    let rules_dir = root.join(RULES_DIR);
    std::fs::create_dir_all(&rules_dir).context("Failed to create rules directory")?;

    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(15))
        .user_agent("depsec")
        .build();

    // Try to fetch the community rules index
    let resp = match agent.get(COMMUNITY_REPO_URL).call() {
        Ok(r) => r,
        Err(e) => {
            anyhow::bail!("Failed to fetch rules from community repo: {e}");
        }
    };

    let entries: Vec<serde_json::Value> = resp.into_json().context("Failed to parse response")?;

    let mut count = 0;
    for entry in &entries {
        let name = entry["name"].as_str().unwrap_or("");
        let download_url = entry["download_url"].as_str().unwrap_or("");

        if !name.ends_with(".toml") || download_url.is_empty() {
            continue;
        }

        match agent.get(download_url).call() {
            Ok(resp) => {
                let content: String = resp.into_string().context("Failed to read rule content")?;
                // Validate it parses
                if toml::from_str::<RuleFile>(&content).is_ok() {
                    let rule_path = rules_dir.join(name);
                    std::fs::write(&rule_path, &content)?;
                    println!("  Updated: {name}");
                    count += 1;
                } else {
                    eprintln!("  Skipped {name}: invalid rule format");
                }
            }
            Err(e) => eprintln!("  Failed to download {name}: {e}"),
        }
    }

    Ok(count)
}

/// Add a custom rule file to the project
pub fn add_rule(root: &Path, rule_path: &Path) -> anyhow::Result<()> {
    // Validate the rule first
    let _rule = load_rule_file(rule_path)?;

    let rules_dir = root.join(RULES_DIR);
    std::fs::create_dir_all(&rules_dir)?;

    let filename = rule_path.file_name().context("Invalid rule file path")?;
    let dest = rules_dir.join(filename);
    std::fs::copy(rule_path, &dest)?;

    println!("Rule added: {}", dest.display());
    Ok(())
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_rule_file() {
        let content = r#"
[rule]
id = "TEST-001"
name = "Test rule"
severity = "high"
description = "A test rule"

[rule.match]
file_patterns = ["*.js"]
content_patterns = ["eval\\("]
"#;
        let rule_file: RuleFile = toml::from_str(content).unwrap();
        assert_eq!(rule_file.rule.id, "TEST-001");
        assert_eq!(rule_file.rule.severity(), Severity::High);
        assert_eq!(rule_file.rule.match_config.file_patterns, vec!["*.js"]);
    }

    #[test]
    fn test_load_external_rules_empty() {
        let dir = TempDir::new().unwrap();
        let rules = load_external_rules(dir.path());
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_and_apply_rule() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join(".depsec/rules");
        fs::create_dir_all(&rules_dir).unwrap();

        // Write a test rule
        fs::write(
            rules_dir.join("test.toml"),
            r#"
[rule]
id = "TEST-001"
name = "Eval detection"
severity = "high"

[rule.match]
file_patterns = ["*.js"]
content_patterns = ["eval\\("]
"#,
        )
        .unwrap();

        // Write a target file
        fs::write(dir.path().join("test.js"), "var x = eval(input);").unwrap();

        let rules = load_external_rules(dir.path());
        assert_eq!(rules.len(), 1);

        let findings = apply_rules(&rules, dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TEST-001");
    }

    #[test]
    fn test_rule_file_pattern_filtering() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join(".depsec/rules");
        fs::create_dir_all(&rules_dir).unwrap();

        fs::write(
            rules_dir.join("test.toml"),
            r#"
[rule]
id = "TEST-002"
name = "Python only"
severity = "medium"

[rule.match]
file_patterns = ["*.py"]
content_patterns = ["exec\\("]
"#,
        )
        .unwrap();

        // JS file should NOT match
        fs::write(dir.path().join("test.js"), "exec(code)").unwrap();
        // Python file SHOULD match
        fs::write(dir.path().join("test.py"), "exec(code)").unwrap();

        let rules = load_external_rules(dir.path());
        let findings = apply_rules(&rules, dir.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].file.as_ref().unwrap().ends_with("test.py"));
    }
}
