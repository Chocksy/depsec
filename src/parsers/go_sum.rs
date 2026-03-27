use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;

use super::{Ecosystem, Package};

/// Parse go.sum.
/// Format: "module version hash" — one line per entry.
/// Entries may appear twice (module and go.mod hash). Deduplicate by name+version.
pub fn parse(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read go.sum")?;
    let mut seen = HashSet::new();
    let mut packages = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }

        let module = parts[0];
        let version_raw = parts[1];

        // Strip /go.mod suffix if present
        let version = version_raw.trim_end_matches("/go.mod");

        // Strip v prefix for OSV queries
        let clean_version = version.trim_start_matches('v');

        let key = (module.to_string(), clean_version.to_string());
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        packages.push(Package {
            name: module.to_string(),
            version: clean_version.to_string(),
            ecosystem: Ecosystem::Go,
        });
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_go_sum() {
        let dir = TempDir::new().unwrap();
        let sum = dir.path().join("go.sum");
        fs::write(
            &sum,
            r#"github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqFPSI0=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL/0KcuqOSEn6kXjhF9YSjl=
golang.org/x/crypto v0.17.0 h1:r8bRNjWMQoez8ZSjI=
golang.org/x/crypto v0.17.0/go.mod h1:Fb2=
github.com/stretchr/testify v1.8.4 h1:CcVxjf3Q8PM=
"#,
        )
        .unwrap();

        let packages = parse(&sum).unwrap();
        assert_eq!(packages.len(), 3); // Deduplicated
        assert!(packages
            .iter()
            .any(|p| p.name == "github.com/gin-gonic/gin" && p.version == "1.9.1"));
        assert!(packages
            .iter()
            .any(|p| p.name == "golang.org/x/crypto" && p.version == "0.17.0"));
        assert!(packages.iter().all(|p| p.ecosystem == Ecosystem::Go));
    }
}
