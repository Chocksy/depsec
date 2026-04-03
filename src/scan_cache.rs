//! Lock file-based scan caching.
//! Parses package-lock.json / yarn.lock / Cargo.lock to identify packages by
//! name + version + integrity hash. Caches scan results so unchanged packages
//! are skipped on subsequent scans.

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A package identity from a lock file
#[derive(Debug, Clone)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub integrity: String, // SHA-512 for npm, checksum for Cargo, version for Gemfile
    /// Filesystem path relative to project root (e.g., "node_modules/lodash",
    /// "node_modules/@babel/core", "node_modules/express/node_modules/qs").
    /// Used by the lockfile-driven scanner to walk per-package instead of the entire dep tree.
    pub dir_path: Option<String>,
}

/// Cache of previously scanned packages
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanCache {
    /// Map of "name@version" → integrity hash at time of last scan
    pub scanned: HashMap<String, String>,
}

impl ScanCache {
    /// Load cache from .depsec/scan-cache.json
    pub fn load(root: &Path) -> Self {
        let cache_path = root.join(".depsec/scan-cache.json");
        if let Ok(content) = std::fs::read_to_string(&cache_path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Save cache to .depsec/scan-cache.json
    pub fn save(&self, root: &Path) {
        let cache_dir = root.join(".depsec");
        let _ = std::fs::create_dir_all(&cache_dir);
        let cache_path = cache_dir.join("scan-cache.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(cache_path, json);
        }
    }

    /// Check which packages need scanning (new or changed since last scan)
    pub fn packages_to_scan(&self, lock_packages: &[LockPackage]) -> Vec<LockPackage> {
        lock_packages
            .iter()
            .filter(|pkg| {
                let key = format!("{}@{}", pkg.name, pkg.version);
                match self.scanned.get(&key) {
                    Some(cached_integrity) => cached_integrity != &pkg.integrity,
                    None => true, // New package
                }
            })
            .cloned()
            .collect()
    }

    /// Mark packages as scanned
    pub fn mark_scanned(&mut self, packages: &[LockPackage]) {
        for pkg in packages {
            let key = format!("{}@{}", pkg.name, pkg.version);
            self.scanned.insert(key, pkg.integrity.clone());
        }
    }

    /// Clean up entries that are no longer in the lock file
    pub fn prune(&mut self, lock_packages: &[LockPackage]) {
        let current_keys: HashSet<String> = lock_packages
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        self.scanned.retain(|k, _| current_keys.contains(k));
    }
}

/// Parse a package-lock.json (npm v2/v3 format)
pub fn parse_npm_lockfile(root: &Path) -> Vec<LockPackage> {
    let lock_path = root.join("package-lock.json");
    let content = match std::fs::read_to_string(&lock_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut packages = Vec::new();

    // v3 format: "packages" key with "node_modules/..." paths
    if let Some(pkgs) = parsed.get("packages").and_then(|p| p.as_object()) {
        for (path, info) in pkgs {
            // Skip the root package (empty string key)
            if path.is_empty() {
                continue;
            }

            // Extract package name from path: "node_modules/@scope/name" → "@scope/name"
            let name = if let Some(rest) = path.strip_prefix("node_modules/") {
                // Handle nested: "node_modules/a/node_modules/b" → "b"
                if let Some(pos) = rest.rfind("node_modules/") {
                    &rest[pos + 13..]
                } else {
                    rest
                }
            } else {
                continue;
            };

            let version = info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let integrity = info
                .get("integrity")
                .and_then(|v| v.as_str())
                .unwrap_or(&version) // Fall back to version if no integrity
                .to_string();

            if !name.is_empty() && !version.is_empty() {
                packages.push(LockPackage {
                    name: name.to_string(),
                    version,
                    integrity,
                    dir_path: Some(path.clone()), // v3 key IS the fs path
                });
            }
        }
    }

    // v1 format: "dependencies" key (fallback)
    if packages.is_empty() {
        if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_deps(deps, &mut packages);
        }
    }

    packages
}

fn parse_npm_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    packages: &mut Vec<LockPackage>,
) {
    for (name, info) in deps {
        let version = info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let integrity = info
            .get("integrity")
            .and_then(|v| v.as_str())
            .unwrap_or(&version)
            .to_string();

        if !version.is_empty() {
            packages.push(LockPackage {
                name: name.clone(),
                version,
                integrity,
                dir_path: Some(format!("node_modules/{name}")),
            });
        }

        // Recurse into nested dependencies
        if let Some(nested) = info.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_deps(nested, packages);
        }
    }
}

/// Parse a Cargo.lock file
pub fn parse_cargo_lockfile(root: &Path) -> Vec<LockPackage> {
    let lock_path = root.join("Cargo.lock");
    let content = match std::fs::read_to_string(&lock_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let parsed: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut packages = Vec::new();

    if let Some(pkgs) = parsed.get("package").and_then(|p| p.as_array()) {
        for pkg in pkgs {
            let name = pkg
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let checksum = pkg
                .get("checksum")
                .and_then(|c| c.as_str())
                .unwrap_or(&version)
                .to_string();

            if !name.is_empty() && !version.is_empty() {
                packages.push(LockPackage {
                    name,
                    version,
                    integrity: checksum,
                    dir_path: None, // Cargo deps are in ~/.cargo/registry, not project dir
                });
            }
        }
    }

    packages
}

/// Parse a Gemfile.lock (Ruby/Bundler) — uses version as cache key (no integrity hash)
pub fn parse_gemfile_lockfile(root: &Path) -> Vec<LockPackage> {
    let lock_path = root.join("Gemfile.lock");
    let content = match std::fs::read_to_string(&lock_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut packages = Vec::new();
    let mut in_specs = false;

    for line in content.lines() {
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs && !line.starts_with(' ') {
            in_specs = false;
        }
        if in_specs {
            // Lines like "    nokogiri (1.16.0)" — 4 spaces = top-level gem
            let trimmed = line.trim();
            if line.starts_with("    ") && !line.starts_with("      ") {
                if let Some(paren_pos) = trimmed.find('(') {
                    let name = trimmed[..paren_pos].trim().to_string();
                    let version = trimmed[paren_pos + 1..]
                        .trim_end_matches(')')
                        .trim()
                        .to_string();
                    if !name.is_empty() && !version.is_empty() {
                        packages.push(LockPackage {
                            name: name.clone(),
                            integrity: version.clone(), // Use version as integrity
                            dir_path: None,             // Resolved at scan time from vendor/bundle
                            version,
                        });
                    }
                }
            }
        }
    }

    packages
}

/// Detect and parse any available lock file in the project
pub fn parse_lockfile(root: &Path) -> Vec<LockPackage> {
    // Try each lock file in order of priority
    let npm = parse_npm_lockfile(root);
    if !npm.is_empty() {
        return npm;
    }

    let cargo = parse_cargo_lockfile(root);
    if !cargo.is_empty() {
        return cargo;
    }

    let gemfile = parse_gemfile_lockfile(root);
    if !gemfile.is_empty() {
        return gemfile;
    }

    // No lock file found — fall back to full scan
    vec![]
}

/// Update the cache after a scan completes
pub fn update_cache(root: &Path) {
    let lock_packages = parse_lockfile(root);
    if lock_packages.is_empty() {
        return;
    }

    let mut cache = ScanCache::load(root);
    cache.mark_scanned(&lock_packages);
    cache.prune(&lock_packages);
    cache.save(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_new_packages() {
        let cache = ScanCache::default();
        let packages = vec![
            LockPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                integrity: "sha512-abc".into(),
                dir_path: None,
            },
            LockPackage {
                name: "express".into(),
                version: "4.18.2".into(),
                integrity: "sha512-def".into(),
                dir_path: None,
            },
        ];

        let to_scan = cache.packages_to_scan(&packages);
        assert_eq!(
            to_scan.len(),
            2,
            "All packages should need scanning on first run"
        );
    }

    #[test]
    fn test_cache_skips_unchanged() {
        let mut cache = ScanCache::default();
        let packages = vec![
            LockPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                integrity: "sha512-abc".into(),
                dir_path: None,
            },
            LockPackage {
                name: "express".into(),
                version: "4.18.2".into(),
                integrity: "sha512-def".into(),
                dir_path: None,
            },
        ];

        // Mark as scanned
        cache.mark_scanned(&packages);

        // Same packages → nothing to scan
        let to_scan = cache.packages_to_scan(&packages);
        assert!(to_scan.is_empty(), "Unchanged packages should be skipped");
    }

    #[test]
    fn test_cache_detects_changed_integrity() {
        let mut cache = ScanCache::default();
        let original = vec![LockPackage {
            name: "lodash".into(),
            version: "4.17.21".into(),
            integrity: "sha512-abc".into(),
            dir_path: None,
        }];
        cache.mark_scanned(&original);

        // Same name+version but different integrity (compromised!)
        let updated = vec![LockPackage {
            name: "lodash".into(),
            version: "4.17.21".into(),
            integrity: "sha512-DIFFERENT".into(),
            dir_path: None,
        }];

        let to_scan = cache.packages_to_scan(&updated);
        assert_eq!(to_scan.len(), 1, "Changed integrity should trigger re-scan");
    }

    #[test]
    fn test_cache_detects_new_package() {
        let mut cache = ScanCache::default();
        cache.mark_scanned(&[LockPackage {
            name: "lodash".into(),
            version: "4.17.21".into(),
            integrity: "sha512-abc".into(),
            dir_path: None,
        }]);

        let packages = vec![
            LockPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                integrity: "sha512-abc".into(),
                dir_path: None,
            },
            LockPackage {
                name: "evil-package".into(),
                version: "1.0.0".into(),
                integrity: "sha512-evil".into(),
                dir_path: None,
            },
        ];

        let to_scan = cache.packages_to_scan(&packages);
        assert_eq!(to_scan.len(), 1);
        assert_eq!(to_scan[0].name, "evil-package");
    }

    #[test]
    fn test_prune_removes_uninstalled() {
        let mut cache = ScanCache::default();
        cache.mark_scanned(&[
            LockPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                integrity: "sha512-abc".into(),
                dir_path: None,
            },
            LockPackage {
                name: "removed-pkg".into(),
                version: "1.0.0".into(),
                integrity: "sha512-old".into(),
                dir_path: None,
            },
        ]);

        // Only lodash remains in lock file
        let current = vec![LockPackage {
            name: "lodash".into(),
            version: "4.17.21".into(),
            integrity: "sha512-abc".into(),
            dir_path: None,
        }];

        cache.prune(&current);
        assert_eq!(cache.scanned.len(), 1);
        assert!(cache.scanned.contains_key("lodash@4.17.21"));
    }
}
