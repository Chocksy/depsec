use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::checks::Finding;
use crate::triage::TriageResult;

/// Get the cache directory (~/.cache/depsec/triage/)
fn cache_dir() -> PathBuf {
    let base = dirs_or_default();
    base.join("triage")
}

fn dirs_or_default() -> PathBuf {
    // Use XDG cache dir or fallback to ~/.cache/depsec
    std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".cache")
        })
        .join("depsec")
}

/// Compute a cache key for a finding based on its content context
fn cache_key(finding: &Finding, root: &Path) -> Option<String> {
    let file = finding.file.as_ref()?;
    let line = finding.line?;
    let package = finding.package.as_deref().unwrap_or("unknown");

    // Read the file and hash the surrounding context (±10 lines)
    let full_path = root.join(file);
    let content = std::fs::read_to_string(&full_path).ok()?;
    let lines: Vec<&str> = content.lines().collect();

    let start = line.saturating_sub(11);
    let end = (line + 10).min(lines.len());
    let context = lines.get(start..end)?.join("\n");

    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    let short_hash = &hash[..12]; // 12 hex chars = 48 bits, birthday collision at ~16M entries

    // Sanitize both package and rule_id for filesystem safety
    let safe_pkg = package.replace('/', "_");
    let safe_rule = finding.rule_id.replace('/', "_");

    Some(format!("{safe_pkg}/{safe_rule}-{short_hash}.json"))
}

/// Look up a cached triage result
pub fn get_cached(finding: &Finding, root: &Path, ttl_days: u32) -> Option<TriageResult> {
    let key = cache_key(finding, root)?;
    let path = cache_dir().join(&key);

    if !path.exists() {
        return None;
    }

    // Check TTL
    if let Ok(metadata) = path.metadata() {
        if let Ok(modified) = metadata.modified() {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age > Duration::from_secs(ttl_days as u64 * 86400) {
                // Expired — remove and return None
                let _ = std::fs::remove_file(&path);
                return None;
            }
        }
    }

    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Store a triage result in the cache
pub fn set_cached(finding: &Finding, root: &Path, result: &TriageResult) -> Result<()> {
    let key = match cache_key(finding, root) {
        Some(k) => k,
        None => return Ok(()), // Can't cache without a key
    };

    let path = cache_dir().join(&key);

    // Create parent directories
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(&path, json)?;

    Ok(())
}

/// Clear all cached triage results
pub fn clear_cache() -> Result<usize> {
    let dir = cache_dir();
    if !dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        std::fs::remove_file(entry.path())?;
        count += 1;
    }

    // Clean up empty directories
    let _ = std::fs::remove_dir_all(&dir);

    Ok(count)
}

/// Get cache statistics
pub fn cache_stats() -> (usize, u64) {
    let dir = cache_dir();
    if !dir.exists() {
        return (0, 0);
    }

    let mut count = 0;
    let mut total_size = 0u64;

    for entry in walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        count += 1;
        if let Ok(meta) = entry.metadata() {
            total_size += meta.len();
        }
    }

    (count, total_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Confidence, Severity};
    use crate::triage::Classification;

    fn test_finding() -> Finding {
        Finding {
            rule_id: "DEPSEC-P001".into(),
            severity: Severity::High,
            confidence: Some(Confidence::High),
            message: "test finding".into(),
            file: Some("node_modules/test-pkg/index.js".into()),
            line: Some(10),
            suggestion: None,
            package: Some("test-pkg".into()),
            reachable: None,
            auto_fixable: false,
        }
    }

    #[test]
    fn test_cache_key_generation() {
        let finding = test_finding();
        let key = cache_key(&finding, Path::new("/nonexistent"));
        // Should return None because the file doesn't exist
        assert!(key.is_none());
    }

    #[test]
    fn test_cache_key_format() {
        // Create a temp dir with a test file
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/test-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("index.js"),
            "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n",
        )
        .unwrap();

        let finding = test_finding();
        let key = cache_key(&finding, dir.path());
        assert!(key.is_some());
        let key = key.unwrap();
        assert!(key.starts_with("test-pkg/DEPSEC-P001-"));
        assert!(key.ends_with(".json"));
    }

    #[test]
    fn test_roundtrip_cache() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = dir.path().join("node_modules/test-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("index.js"),
            "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n",
        )
        .unwrap();

        let finding = test_finding();
        let result = TriageResult {
            classification: Classification::FalsePositive,
            confidence: 0.95,
            reasoning: "Test reasoning".into(),
            recommendation: "Test recommendation".into(),
        };

        // Store
        set_cached(&finding, dir.path(), &result).unwrap();

        // Retrieve
        let cached = get_cached(&finding, dir.path(), 30);
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.classification, Classification::FalsePositive);
        assert_eq!(cached.confidence, 0.95);
    }
}
