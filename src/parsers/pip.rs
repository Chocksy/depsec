use std::path::Path;

use anyhow::Context;

use super::{Ecosystem, Package};

/// Parse poetry.lock (TOML format).
/// Packages are under [[package]] with name and version fields.
pub fn parse_poetry(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read poetry.lock")?;
    let parsed: toml::Value = toml::from_str(&content).context("Failed to parse poetry.lock")?;

    let packages = parsed
        .get("package")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let name = entry.get("name")?.as_str()?.to_string();
                    let version = entry.get("version")?.as_str()?.to_string();
                    Some(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::PyPI,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(packages)
}

/// Parse Pipfile.lock (JSON format).
/// Packages are under "default" and "develop" keys.
pub fn parse_pipfile(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read Pipfile.lock")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse Pipfile.lock")?;

    let mut packages = Vec::new();

    for section in ["default", "develop"] {
        if let Some(deps) = parsed.get(section).and_then(|d| d.as_object()) {
            for (name, value) in deps {
                if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                    // Version format: "==1.2.3"
                    let clean = version.trim_start_matches("==");
                    packages.push(Package {
                        name: name.clone(),
                        version: clean.to_string(),
                        ecosystem: Ecosystem::PyPI,
                    });
                }
            }
        }
    }

    Ok(packages)
}

/// Parse requirements.txt.
/// Only includes entries with exact pins (==).
/// Warns about unpinned entries.
pub fn parse_requirements(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read requirements.txt")?;
    let mut packages = Vec::new();
    let mut unpinned_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Look for exact pins (name==version)
        if let Some((name, version)) = trimmed.split_once("==") {
            let name = name.trim();
            let version = version.split(';').next().unwrap_or(version).trim(); // Strip markers
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::PyPI,
                });
            }
        } else if trimmed.contains(">=") || trimmed.contains("<=") || trimmed.contains("~=") {
            unpinned_count += 1;
        } else if !trimmed.contains("==") && !trimmed.starts_with('-') {
            // Bare package name without version
            unpinned_count += 1;
        }
    }

    if unpinned_count > 0 {
        eprintln!(
            "Warning: {unpinned_count} unpinned entries in requirements.txt skipped (only == pins are checked)"
        );
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_poetry_lock() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("poetry.lock");
        fs::write(
            &lock,
            r#"[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "3.0.0"
"#,
        )
        .unwrap();

        let packages = parse_poetry(&lock).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
    }

    #[test]
    fn test_parse_pipfile_lock() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("Pipfile.lock");
        fs::write(
            &lock,
            r#"{
    "_meta": { "hash": {"sha256": "abc"} },
    "default": {
        "requests": { "version": "==2.31.0" },
        "flask": { "version": "==3.0.0" }
    },
    "develop": {
        "pytest": { "version": "==7.4.0" }
    }
}"#,
        )
        .unwrap();

        let packages = parse_pipfile(&lock).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(packages.iter().any(|p| p.name == "pytest" && p.version == "7.4.0"));
    }

    #[test]
    fn test_parse_requirements_pinned() {
        let dir = TempDir::new().unwrap();
        let req = dir.path().join("requirements.txt");
        fs::write(
            &req,
            r#"# dependencies
requests==2.31.0
flask==3.0.0 ; python_version >= "3.8"
numpy>=1.24.0
pandas
"#,
        )
        .unwrap();

        let packages = parse_requirements(&req).unwrap();
        assert_eq!(packages.len(), 2); // Only pinned entries
        assert!(packages.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(packages.iter().any(|p| p.name == "flask" && p.version == "3.0.0"));
    }
}
