use std::path::Path;

use anyhow::{bail, Context};
use regex::Regex;

#[derive(Debug)]
pub struct FixResult {
    pub file: String,
    pub action: String,
    pub old_ref: String,
    pub new_sha: String,
    pub applied: bool,
}

pub fn fix_workflow_pinning(
    root: &Path,
    dry_run: bool,
) -> anyhow::Result<Vec<FixResult>> {
    let workflows_dir = root.join(".github").join("workflows");
    if !workflows_dir.exists() {
        return Ok(vec![]);
    }

    let mut results = Vec::new();
    let entries = std::fs::read_dir(&workflows_dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yml" | "yaml")) {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        let rel_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        let (new_content, file_results) = fix_file_pinning(&content, &rel_path)?;

        if !file_results.is_empty() && !dry_run {
            std::fs::write(&path, &new_content)?;
        }

        results.extend(file_results);
    }

    Ok(results)
}

fn fix_file_pinning(content: &str, file: &str) -> anyhow::Result<(String, Vec<FixResult>)> {
    let uses_re = Regex::new(r"(?m)(^\s*-?\s*uses:\s*)([^\s#]+)(.*)$").unwrap();
    let sha_re = Regex::new(r"@[0-9a-f]{40}$").unwrap();

    let mut new_content = String::new();
    let mut results = Vec::new();

    for line in content.lines() {
        if let Some(caps) = uses_re.captures(line) {
            let prefix = caps.get(1).unwrap().as_str();
            let action_ref = caps.get(2).unwrap().as_str();
            let suffix = caps.get(3).unwrap().as_str();

            // Skip local, Docker, or already-pinned actions
            if action_ref.starts_with("./")
                || action_ref.starts_with("docker://")
                || !action_ref.contains('@')
                || sha_re.is_match(action_ref)
            {
                new_content.push_str(line);
                new_content.push('\n');
                continue;
            }

            // Parse owner/repo@tag
            let (action_name, tag) = match action_ref.rsplit_once('@') {
                Some((name, tag)) => (name, tag),
                None => {
                    new_content.push_str(line);
                    new_content.push('\n');
                    continue;
                }
            };

            // Resolve tag to SHA via GitHub API
            match resolve_tag_to_sha(action_name, tag) {
                Ok(sha) => {
                    let new_line = format!(
                        "{prefix}{action_name}@{sha}{suffix} # {tag}"
                    );
                    new_content.push_str(&new_line);
                    new_content.push('\n');

                    results.push(FixResult {
                        file: file.into(),
                        action: action_name.into(),
                        old_ref: tag.into(),
                        new_sha: sha,
                        applied: true,
                    });
                }
                Err(e) => {
                    eprintln!("Warning: could not resolve {action_name}@{tag}: {e}");
                    new_content.push_str(line);
                    new_content.push('\n');

                    results.push(FixResult {
                        file: file.into(),
                        action: action_name.into(),
                        old_ref: tag.into(),
                        new_sha: String::new(),
                        applied: false,
                    });
                }
            }
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    Ok((new_content, results))
}

fn resolve_tag_to_sha(action: &str, tag: &str) -> anyhow::Result<String> {
    let (owner, repo) = action
        .split_once('/')
        .context("Invalid action format — expected owner/repo")?;

    // Strip any sub-path (e.g., "actions/cache/restore" -> "actions/cache")
    let repo = repo.split('/').next().unwrap_or(repo);

    let token = std::env::var("GITHUB_TOKEN").ok();
    let client = reqwest::blocking::Client::new();

    // Try as a tag first, then as a branch
    for ref_type in ["tags", "heads"] {
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/git/ref/{ref_type}/{tag}"
        );

        let mut req = client
            .get(&url)
            .header("User-Agent", "depsec")
            .header("Accept", "application/vnd.github.v3+json");

        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }

        let resp = req.send().context("GitHub API request failed")?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json()?;

            // Handle annotated tags (type: "tag") — need to dereference
            if let Some(obj) = body.get("object") {
                let obj_type = obj["type"].as_str().unwrap_or("");
                let sha = obj["sha"].as_str().unwrap_or("");

                if obj_type == "tag" {
                    // Dereference annotated tag to get the commit SHA
                    let tag_url = obj["url"].as_str().unwrap_or("");
                    if !tag_url.is_empty() {
                        let mut tag_req = client
                            .get(tag_url)
                            .header("User-Agent", "depsec")
                            .header("Accept", "application/vnd.github.v3+json");
                        if let Some(ref t) = token {
                            tag_req = tag_req.header("Authorization", format!("Bearer {t}"));
                        }
                        let tag_resp = tag_req.send()?;
                        if tag_resp.status().is_success() {
                            let tag_body: serde_json::Value = tag_resp.json()?;
                            if let Some(commit_sha) = tag_body["object"]["sha"].as_str() {
                                return Ok(commit_sha.to_string());
                            }
                        }
                    }
                }

                if !sha.is_empty() {
                    return Ok(sha.to_string());
                }
            }
        }
    }

    bail!("Could not resolve {action}@{tag} — tag/branch not found")
}

pub fn print_fix_results(results: &[FixResult], dry_run: bool) {
    if results.is_empty() {
        println!("No actions to fix — all already pinned to SHAs.");
        return;
    }

    let prefix = if dry_run { "[dry-run] " } else { "" };

    for result in results {
        if result.applied {
            println!(
                "{prefix}Fixed: {} — {}@{} → {}@{} # {}",
                result.file, result.action, result.old_ref, result.action, result.new_sha, result.old_ref
            );
        } else {
            println!(
                "{prefix}Failed: {} — {}@{} (could not resolve SHA)",
                result.file, result.action, result.old_ref
            );
        }
    }

    let fixed = results.iter().filter(|r| r.applied).count();
    let failed = results.iter().filter(|r| !r.applied).count();

    println!(
        "\n{fixed} action{} fixed, {failed} failed.",
        if fixed == 1 { "" } else { "s" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_file_already_pinned() {
        let content = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let (_, results) = fix_file_pinning(content, "ci.yml").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_fix_file_skips_local_action() {
        let content = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
"#;
        let (_, results) = fix_file_pinning(content, "ci.yml").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_fix_file_skips_docker_action() {
        let content = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.18
"#;
        let (_, results) = fix_file_pinning(content, "ci.yml").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_print_fix_results_empty() {
        print_fix_results(&[], false);
        // Should not panic
    }
}
