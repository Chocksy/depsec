use std::path::Path;

use anyhow::Context;

use super::{Ecosystem, Package};

/// Parse Gemfile.lock.
/// Gems are listed under the "GEM" section's "specs:" subsection.
/// Format: "    gem_name (version)"
pub fn parse(path: &Path) -> anyhow::Result<Vec<Package>> {
    let content = std::fs::read_to_string(path).context("Failed to read Gemfile.lock")?;
    let mut packages = Vec::new();
    let mut in_gem_section = false;
    let mut in_gem_specs = false;

    for line in content.lines() {
        // Track which top-level section we're in
        if !line.starts_with(' ') && !line.is_empty() {
            in_gem_section = line == "GEM";
            in_gem_specs = false;
            continue;
        }

        // Only look for specs: within the GEM section
        if in_gem_section && line.trim() == "specs:" {
            in_gem_specs = true;
            continue;
        }

        // End of specs subsection (unindented within GEM section)
        if in_gem_specs && !line.starts_with("  ") && !line.is_empty() {
            in_gem_specs = false;
            continue;
        }

        if !in_gem_specs {
            continue;
        }

        // Gem entries are indented 4 spaces: "    gem_name (version)"
        // Sub-dependencies are indented 6 spaces: "      dep_name (constraint)"
        // We only want direct gems (4-space indent)
        let trimmed = line.trim();
        if line.starts_with("    ") && !line.starts_with("      ") {
            if let Some((name, rest)) = trimmed.split_once(' ') {
                let version = rest.trim_start_matches('(').trim_end_matches(')');
                packages.push(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::RubyGems,
                });
            }
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
    fn test_parse_gemfile_lock() {
        let dir = TempDir::new().unwrap();
        let lock = dir.path().join("Gemfile.lock");
        fs::write(
            &lock,
            r#"GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.3)
      actionpack (= 7.1.3)
    actionpack (7.1.3)
      rack (~> 3.0)
    rack (3.0.8)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  actioncable
  rack

BUNDLED WITH
   2.5.0
"#,
        )
        .unwrap();

        let packages = parse(&lock).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(packages
            .iter()
            .any(|p| p.name == "actioncable" && p.version == "7.1.3"));
        assert!(packages
            .iter()
            .any(|p| p.name == "actionpack" && p.version == "7.1.3"));
        assert!(packages
            .iter()
            .any(|p| p.name == "rack" && p.version == "3.0.8"));
        assert!(packages.iter().all(|p| p.ecosystem == Ecosystem::RubyGems));
    }
}
