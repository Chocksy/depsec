use regex::Regex;

use crate::checks::{Check, CheckResult, Finding, ScanContext, Severity};

/// User-controlled GitHub Actions context expressions that are injection vectors.
const INJECTION_EXPRESSIONS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.discussion.body",
    "github.event.discussion.title",
];

pub struct WorkflowsCheck;

impl Check for WorkflowsCheck {
    fn name(&self) -> &str {
        "workflows"
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<CheckResult> {
        let max_score = ctx.config.scoring.weight_for("workflows") as f64;
        let workflows_dir = ctx.root.join(".github").join("workflows");

        if !workflows_dir.exists() {
            return Ok(CheckResult::new(
                "workflows",
                vec![],
                max_score,
                vec!["No GitHub Actions workflows found (N/A)".into()],
            ));
        }

        let mut findings = Vec::new();
        let mut pass_messages = Vec::new();
        let mut workflow_count = 0;

        let entries = std::fs::read_dir(&workflows_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if !matches!(ext, Some("yml" | "yaml")) {
                continue;
            }

            workflow_count += 1;
            let content = std::fs::read_to_string(&path)?;
            let rel_path = path
                .strip_prefix(ctx.root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            check_action_pinning(&content, &rel_path, &mut findings);
            check_permissions(&content, &rel_path, &mut findings);
            check_pull_request_target(&content, &rel_path, &mut findings);
            check_expression_injection(&content, &rel_path, &mut findings);
            check_dangerous_git_flags(&content, &rel_path, &mut findings);
        }

        if workflow_count == 0 {
            return Ok(CheckResult::new(
                "workflows",
                vec![],
                max_score,
                vec!["No workflow files found in .github/workflows/".into()],
            ));
        }

        // Build pass messages for checks that found no issues
        let has_pinning_issue = findings.iter().any(|f| f.rule_id == "DEPSEC-W001");
        let has_permissions_issue = findings.iter().any(|f| f.rule_id == "DEPSEC-W002");
        let has_prt_issue = findings.iter().any(|f| f.rule_id == "DEPSEC-W003");
        let has_injection_issue = findings.iter().any(|f| f.rule_id == "DEPSEC-W004");
        let has_git_flag_issue = findings.iter().any(|f| f.rule_id == "DEPSEC-W005");

        if !has_pinning_issue {
            pass_messages.push("All GitHub Actions pinned to SHA".into());
        }
        if !has_permissions_issue {
            pass_messages.push("Workflow permissions minimized".into());
        }
        if !has_prt_issue && !has_injection_issue {
            pass_messages.push("No injection patterns detected".into());
        }
        if !has_git_flag_issue {
            pass_messages.push("No dangerous git flags found".into());
        }

        Ok(CheckResult::new(
            "workflows",
            findings,
            max_score,
            pass_messages,
        ))
    }
}

/// DEPSEC-W001: Actions not pinned to commit SHA
fn check_action_pinning(content: &str, file: &str, findings: &mut Vec<Finding>) {
    // Match `uses: owner/repo@ref` but not already a 40-char hex SHA
    let re = Regex::new(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)").unwrap();
    let sha_re = Regex::new(r"@[0-9a-f]{40}$").unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = re.captures(line) {
            let action_ref = caps.get(1).unwrap().as_str();

            // Skip local actions (./), Docker actions (docker://), and bare actions without @
            if action_ref.starts_with("./")
                || action_ref.starts_with("docker://")
                || !action_ref.contains('@')
            {
                continue;
            }

            // Check if already pinned to a SHA
            if sha_re.is_match(action_ref) {
                continue;
            }

            findings.push(Finding {
                rule_id: "DEPSEC-W001".into(),
                severity: Severity::High,
                message: format!("Action not pinned to commit SHA: {action_ref}"),
                file: Some(file.into()),
                line: Some(line_num + 1),
                suggestion: Some("Pin to a full commit SHA instead of a tag".into()),
                confidence: None,
                package: None,
                auto_fixable: true,
            });
        }
    }
}

/// DEPSEC-W002: permissions block missing or write-all
fn check_permissions(content: &str, file: &str, findings: &mut Vec<Finding>) {
    // Look for a top-level `permissions:` line (not indented = top-level in YAML)
    let mut has_permissions = false;
    let mut is_write_all = false;

    for line in content.lines() {
        // Top-level key: starts at column 0, not a comment
        if line.starts_with("permissions:") {
            has_permissions = true;
            let value = line.trim_start_matches("permissions:").trim();
            if value == "write-all" {
                is_write_all = true;
            }
            break;
        }
    }

    if !has_permissions {
        findings.push(Finding {
            rule_id: "DEPSEC-W002".into(),
            severity: Severity::Medium,
            message: "No top-level permissions block — defaults to write-all".into(),
            file: Some(file.into()),
            line: None,
            suggestion: Some(
                "Add 'permissions: {}' for read-only, or specify minimal permissions".into(),
            ),
            confidence: None,
            package: None,
            auto_fixable: false,
        });
    } else if is_write_all {
        findings.push(Finding {
            rule_id: "DEPSEC-W002".into(),
            severity: Severity::Medium,
            message: "Workflow permissions set to write-all".into(),
            file: Some(file.into()),
            line: None,
            suggestion: Some("Set minimal permissions per job instead of write-all".into()),
            confidence: None,
            package: None,
            auto_fixable: false,
        });
    }
}

/// DEPSEC-W003: pull_request_target with checkout
fn check_pull_request_target(content: &str, file: &str, findings: &mut Vec<Finding>) {
    let has_prt = content.contains("pull_request_target");
    if !has_prt {
        return;
    }

    let checkout_re = Regex::new(r"(?i)uses:\s*actions/checkout").unwrap();
    for (line_num, line) in content.lines().enumerate() {
        // Skip commented lines
        if line.trim().starts_with('#') {
            continue;
        }
        if checkout_re.is_match(line) {
            findings.push(Finding {
                rule_id: "DEPSEC-W003".into(),
                severity: Severity::Critical,
                message: "pull_request_target with actions/checkout detected (code injection risk)"
                    .into(),
                file: Some(file.into()),
                line: Some(line_num + 1),
                suggestion: Some(
                    "Use pull_request instead, or avoid checking out PR code in pull_request_target"
                        .into(),
                ),
                confidence: None, package: None,
                auto_fixable: false,
            });
        }
    }
}

/// DEPSEC-W004: User-controlled expressions in run: blocks
fn check_expression_injection(content: &str, file: &str, findings: &mut Vec<Finding>) {
    let mut in_run_block = false;
    let mut run_indent: usize = 0;

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Detect `run:` lines (may appear as `run:` or `- run:`)
        let is_run_line = trimmed.starts_with("run:") || trimmed.starts_with("- run:");
        if is_run_line {
            // Detect block scalar indicators: |, |-, |+, >, >-, >+
            let after_run = trimmed
                .split_once("run:")
                .map(|(_, r)| r.trim())
                .unwrap_or("");
            in_run_block = after_run.starts_with('|') || after_run.starts_with('>');
            run_indent = line.len() - line.trim_start().len();
            check_line_for_injection(line, line_num, file, findings);
            continue;
        }

        // Continue checking multiline run blocks
        if in_run_block {
            if trimmed.is_empty() {
                continue; // Blank lines within a block are OK
            }
            // End of block when indentation returns to or below the run: level
            let current_indent = line.len() - line.trim_start().len();
            if current_indent <= run_indent {
                in_run_block = false;
                continue;
            }
            check_line_for_injection(line, line_num, file, findings);
        }
    }
}

fn check_line_for_injection(line: &str, line_num: usize, file: &str, findings: &mut Vec<Finding>) {
    for expr in INJECTION_EXPRESSIONS {
        // Match both "${{ expr }}" (with space) and "${{expr}}" (without space)
        let pattern_spaced = format!("${{{{ {expr}");
        let pattern_compact = format!("${{{{{expr}");
        if line.contains(&pattern_spaced) || line.contains(&pattern_compact) {
            findings.push(Finding {
                rule_id: "DEPSEC-W004".into(),
                severity: Severity::Critical,
                message: format!("User-controlled expression in run block: ${{{{ {expr} }}}}"),
                file: Some(file.into()),
                line: Some(line_num + 1),
                suggestion: Some(
                    "Pass the value through an environment variable instead of inline expansion"
                        .into(),
                ),
                confidence: None,
                package: None,
                auto_fixable: false,
            });
        }
    }
}

/// DEPSEC-W005: --no-verify or --force in git commands
fn check_dangerous_git_flags(content: &str, file: &str, findings: &mut Vec<Finding>) {
    let git_noverify = Regex::new(r"git\s+.*--no-verify").unwrap();
    let git_force = Regex::new(r"git\s+push\s+.*--force(?:\s|$)").unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if git_noverify.is_match(line) {
            findings.push(Finding {
                rule_id: "DEPSEC-W005".into(),
                severity: Severity::Medium,
                message: "git --no-verify flag skips pre-commit hooks".into(),
                file: Some(file.into()),
                line: Some(line_num + 1),
                suggestion: Some("Remove --no-verify to ensure hooks run".into()),
                confidence: None,
                package: None,
                auto_fixable: false,
            });
        }

        if git_force.is_match(line) {
            findings.push(Finding {
                rule_id: "DEPSEC-W005".into(),
                severity: Severity::Medium,
                message: "git push --force can overwrite remote history".into(),
                file: Some(file.into()),
                line: Some(line_num + 1),
                suggestion: Some("Use --force-with-lease instead of --force".into()),
                confidence: None,
                package: None,
                auto_fixable: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;
    use tempfile::TempDir;

    fn setup_workflow(content: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let wf_dir = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        let wf_file = wf_dir.join("ci.yml");
        fs::write(&wf_file, content).unwrap();
        (dir, wf_file)
    }

    #[test]
    fn test_no_workflows_dir() {
        let dir = TempDir::new().unwrap();
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        assert_eq!(result.score, 25.0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_pinned_action_passes() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let pinning_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W001")
            .collect();
        assert!(pinning_findings.is_empty());
    }

    #[test]
    fn test_unpinned_action_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let pinning_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W001")
            .collect();
        assert_eq!(pinning_findings.len(), 1);
        assert!(pinning_findings[0].auto_fixable);
    }

    #[test]
    fn test_missing_permissions_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let perm_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W002")
            .collect();
        assert_eq!(perm_findings.len(), 1);
    }

    #[test]
    fn test_write_all_permissions_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let perm_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W002")
            .collect();
        assert_eq!(perm_findings.len(), 1);
    }

    #[test]
    fn test_pull_request_target_with_checkout() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: pull_request_target
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let prt_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W003")
            .collect();
        assert_eq!(prt_findings.len(), 1);
        assert_eq!(prt_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_expression_injection_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: issues
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let inj_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W004")
            .collect();
        assert_eq!(inj_findings.len(), 1);
        assert_eq!(inj_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_git_no_verify_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: git commit --no-verify -m "skip hooks"
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let git_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W005")
            .collect();
        assert_eq!(git_findings.len(), 1);
    }

    #[test]
    fn test_git_force_push_detected() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: git push --force origin main
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let git_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W005")
            .collect();
        assert_eq!(git_findings.len(), 1);
    }

    #[test]
    fn test_local_action_not_flagged() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let pinning_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W001")
            .collect();
        assert!(pinning_findings.is_empty());
    }

    #[test]
    fn test_docker_action_not_flagged() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.18
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        let pinning_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "DEPSEC-W001")
            .collect();
        assert!(pinning_findings.is_empty());
    }

    #[test]
    fn test_perfect_workflow_full_score() {
        let (dir, _) = setup_workflow(
            r#"
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: cargo test
"#,
        );
        let config = Config::default();
        let ctx = ScanContext {
            root: dir.path(),
            config: &config,
        };
        let result = WorkflowsCheck.run(&ctx).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 25.0);
    }
}
