pub mod cargo_lock;
pub mod gemfile_lock;
pub mod go_sum;
pub mod package_lock;
pub mod pip;

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Ecosystem {
    #[serde(rename = "crates.io")]
    CratesIo,
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "RubyGems")]
    RubyGems,
    #[serde(rename = "Go")]
    Go,
    #[serde(rename = "PyPI")]
    PyPI,
}

impl Ecosystem {
    /// OSV API ecosystem string
    pub fn osv_name(&self) -> &str {
        match self {
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Go => "Go",
            Ecosystem::PyPI => "PyPI",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

/// Detect and parse all lockfiles under `root`, up to `max_depth` levels deep.
pub fn parse_all_lockfiles(root: &Path, max_depth: usize) -> Vec<(String, Vec<Package>)> {
    let mut results = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip hidden directories and common non-project dirs
        let rel = path.strip_prefix(root).unwrap_or(path);
        if rel.components().any(|c| {
            let s = c.as_os_str().to_str().unwrap_or("");
            s.starts_with('.') || s == "node_modules" || s == "target" || s == "vendor"
        }) {
            continue;
        }

        let rel_path = rel.to_string_lossy().to_string();

        let packages = match filename {
            "Cargo.lock" => cargo_lock::parse(path),
            "package-lock.json" => package_lock::parse_npm(path),
            "yarn.lock" => package_lock::parse_yarn(path),
            "pnpm-lock.yaml" => package_lock::parse_pnpm(path),
            "Gemfile.lock" => gemfile_lock::parse(path),
            "go.sum" => go_sum::parse(path),
            "poetry.lock" => pip::parse_poetry(path),
            "Pipfile.lock" => pip::parse_pipfile(path),
            "requirements.txt" => pip::parse_requirements(path),
            _ => continue,
        };

        match packages {
            Ok(pkgs) if !pkgs.is_empty() => {
                results.push((rel_path, pkgs));
            }
            Ok(_) => {} // Empty, skip
            Err(e) => {
                eprintln!("Warning: failed to parse {rel_path}: {e}");
            }
        }
    }

    results
}

/// Deduplicate packages by (name, version, ecosystem)
pub fn deduplicate(packages: Vec<Package>) -> Vec<Package> {
    let mut seen = std::collections::HashSet::new();
    packages
        .into_iter()
        .filter(|p| seen.insert((p.name.clone(), p.version.clone(), p.ecosystem.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_osv_name() {
        assert_eq!(Ecosystem::CratesIo.osv_name(), "crates.io");
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
        assert_eq!(Ecosystem::RubyGems.osv_name(), "RubyGems");
        assert_eq!(Ecosystem::Go.osv_name(), "Go");
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
    }

    #[test]
    fn test_deduplicate_empty() {
        let result = deduplicate(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_deduplicate_removes_dupes() {
        let packages = vec![
            Package {
                name: "serde".into(),
                version: "1.0".into(),
                ecosystem: Ecosystem::CratesIo,
            },
            Package {
                name: "serde".into(),
                version: "1.0".into(),
                ecosystem: Ecosystem::CratesIo,
            },
            Package {
                name: "tokio".into(),
                version: "1.0".into(),
                ecosystem: Ecosystem::CratesIo,
            },
        ];
        let result = deduplicate(packages);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_deduplicate_keeps_different_versions() {
        let packages = vec![
            Package {
                name: "serde".into(),
                version: "1.0".into(),
                ecosystem: Ecosystem::CratesIo,
            },
            Package {
                name: "serde".into(),
                version: "2.0".into(),
                ecosystem: Ecosystem::CratesIo,
            },
        ];
        let result = deduplicate(packages);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_all_lockfiles_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let results = parse_all_lockfiles(dir.path(), 3);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_all_lockfiles_with_cargo_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let cargo_lock = r#"
[[package]]
name = "anyhow"
version = "1.0.75"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        std::fs::write(dir.path().join("Cargo.lock"), cargo_lock).unwrap();
        let results = parse_all_lockfiles(dir.path(), 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "Cargo.lock");
        assert_eq!(results[0].1.len(), 2);
    }

    #[test]
    fn test_parse_all_lockfiles_skips_hidden() {
        let dir = tempfile::TempDir::new().unwrap();
        let hidden = dir.path().join(".hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(
            hidden.join("Cargo.lock"),
            "[[package]]\nname = \"x\"\nversion = \"1\"",
        )
        .unwrap();
        let results = parse_all_lockfiles(dir.path(), 3);
        assert!(results.is_empty());
    }
}
