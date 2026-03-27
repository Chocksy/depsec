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
