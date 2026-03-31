use std::path::Path;

use anyhow::Context;

use super::{Ecosystem, Package};

/// Parse package-lock.json (v1, v2, v3).
/// v1 uses `dependencies`, v2/v3 use `packages`.
pub fn parse_npm(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read package-lock.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse package-lock.json")?;

    let mut packages = Vec::new();

    // v2/v3: "packages" object (keys are paths like "node_modules/pkg")
    if let Some(pkgs) = parsed.get("packages").and_then(|p| p.as_object()) {
        for (key, value) in pkgs {
            // Skip the root entry (empty key)
            if key.is_empty() {
                continue;
            }

            // Extract package name from the key path (e.g., "node_modules/lodash" -> "lodash")
            let name = key.rsplit("node_modules/").next().unwrap_or(key);
            if name.is_empty() {
                continue;
            }

            if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                packages.push(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }
    // v1: "dependencies" object
    else if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
        collect_v1_deps(deps, &mut packages, 0);
    }

    Ok(packages)
}

const MAX_V1_DEPTH: usize = 20; // Prevent stack overflow from pathological nesting

fn collect_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    packages: &mut Vec<Package>,
    depth: usize,
) {
    if depth > MAX_V1_DEPTH {
        return;
    }
    for (name, value) in deps {
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            packages.push(Package {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: Ecosystem::Npm,
            });
        }

        // v1 can have nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            collect_v1_deps(nested, packages, depth + 1);
        }
    }
}

/// Parse yarn.lock v1 (classic yarn).
/// Format: quoted package name with version constraint, then indented "version" field.
pub fn parse_yarn(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read yarn.lock")?;
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // Package header: "name@version:" or "name@version, name@version:"
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            // Extract the package name (before the @version part)
            let entry = trimmed.trim_end_matches(':').trim_matches('"');
            if let Some(at_pos) = entry.rfind('@') {
                if at_pos > 0 {
                    let name = &entry[..at_pos];
                    current_name = Some(name.to_string());
                }
            }
        }

        // Version line within a package block
        if trimmed.starts_with("version ") && current_name.is_some() {
            let version = trimmed.trim_start_matches("version ").trim_matches('"');
            if let Some(name) = current_name.take() {
                packages.push(Package {
                    name,
                    version: version.to_string(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }

    Ok(packages)
}

/// Parse pnpm-lock.yaml.
/// Packages are under `packages` key with paths like "/pkg@version".
/// Uses line-based parsing to avoid YAML library dependency.
pub fn parse_pnpm(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read pnpm-lock.yaml")?;
    let mut packages = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        // Detect the top-level `packages:` section
        if line == "packages:" {
            in_packages = true;
            continue;
        }

        // End of packages section (next top-level key)
        if in_packages && !line.starts_with(' ') && !line.starts_with('\t') && !line.is_empty() {
            break;
        }

        if !in_packages {
            continue;
        }

        // Package entries are indented and end with ':'
        // e.g., "  /lodash@4.17.21:" or "  /@types/node@18.0.0:" or "  lodash@4.17.21:"
        let trimmed = line.trim();
        if !trimmed.ends_with(':') || trimmed.starts_with('#') {
            continue;
        }
        // Skip sub-keys (deeper indentation like "    resolution:")
        let indent = line.len() - line.trim_start().len();
        if indent > 4 {
            continue;
        }

        let key = trimmed
            .trim_end_matches(':')
            .trim_matches('\'')
            .trim_matches('"');
        let entry = key.trim_start_matches('/');

        // Parse name@version
        let (name, version) = if let Some(rest) = entry.strip_prefix('@') {
            // @scope/name@version
            if let Some(at_pos) = rest.rfind('@') {
                let at_pos = at_pos + 1;
                (&entry[..at_pos], &entry[at_pos + 1..])
            } else {
                continue;
            }
        } else if let Some(at_pos) = entry.rfind('@') {
            (&entry[..at_pos], &entry[at_pos + 1..])
        } else {
            continue;
        };

        if !name.is_empty() && !version.is_empty() {
            packages.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: Ecosystem::Npm,
            });
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_npm_v2() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("package-lock.json");
        fs::write(
            &lock,
            r#"{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "test-project", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/express": { "version": "4.18.2" }
  }
}"#,
        )
        .unwrap();

        let packages = parse_npm(&lock).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21"));
        assert!(packages.iter().any(|p| p.name == "express"));
    }

    #[test]
    fn test_parse_npm_v1() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("package-lock.json");
        fs::write(
            &lock,
            r#"{
  "name": "test-project",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": { "version": "4.17.21" },
    "express": { "version": "4.18.2" }
  }
}"#,
        )
        .unwrap();

        let packages = parse_npm(&lock).unwrap();
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn test_parse_yarn_v1() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("yarn.lock");
        fs::write(
            &lock,
            r#"# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
"#,
        )
        .unwrap();

        let packages = parse_yarn(&lock).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21"));
    }

    #[test]
    fn test_parse_pnpm() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &lock,
            r#"lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-xyz}
  /@types/node@18.0.0:
    resolution: {integrity: sha512-abc}
"#,
        )
        .unwrap();

        let packages = parse_pnpm(&lock).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21"));
        assert!(packages
            .iter()
            .any(|p| p.name == "@types/node" && p.version == "18.0.0"));
    }
}
