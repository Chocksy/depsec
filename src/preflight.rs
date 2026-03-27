use std::path::Path;

use crate::checks::{Finding, Severity};
use crate::parsers;

/// Top-1000 npm packages (abbreviated — full list would be generated from download stats)
const NPM_TOP_PACKAGES: &[&str] = &[
    "lodash",
    "chalk",
    "react",
    "express",
    "commander",
    "debug",
    "glob",
    "minimist",
    "semver",
    "axios",
    "uuid",
    "mkdirp",
    "yargs",
    "fs-extra",
    "rimraf",
    "async",
    "moment",
    "bluebird",
    "underscore",
    "request",
    "colors",
    "through2",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "body-parser",
    "cors",
    "dotenv",
    "mongoose",
    "sequelize",
    "pg",
    "mysql",
    "redis",
    "socket.io",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "nodemailer",
    "winston",
    "morgan",
    "helmet",
    "compression",
    "cookie-parser",
    "multer",
    "next",
    "nuxt",
    "vue",
    "angular",
    "svelte",
    "tailwindcss",
    "postcss",
    "babel",
    "rollup",
    "vite",
    "esbuild",
    "turbo",
    "nx",
    "lerna",
    "inquirer",
    "ora",
    "got",
    "node-fetch",
    "superagent",
    "cheerio",
    "puppeteer",
    "playwright",
    "cypress",
    "storybook",
    "three",
    "d3",
    "rxjs",
    "graphql",
    "apollo",
    "prisma",
    "knex",
    "typeorm",
    "sharp",
    "jimp",
    "pdf-lib",
    "xlsx",
    "csv-parser",
    "xml2js",
    "dotenv",
    "cross-env",
    "concurrently",
    "nodemon",
    "ts-node",
    "husky",
    "lint-staged",
    "commitlint",
    "semantic-release",
    "aws-sdk",
    "firebase",
    "stripe",
    "twilio",
    "sendgrid",
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "cohere",
    "telnyx",
    "faker",
    "chance",
    "casual",
];

/// Top PyPI packages
const PYPI_TOP_PACKAGES: &[&str] = &[
    "boto3",
    "requests",
    "urllib3",
    "setuptools",
    "certifi",
    "charset-normalizer",
    "idna",
    "typing-extensions",
    "botocore",
    "python-dateutil",
    "pip",
    "packaging",
    "s3transfer",
    "numpy",
    "pyyaml",
    "six",
    "jmespath",
    "cryptography",
    "wheel",
    "attrs",
    "cffi",
    "pycparser",
    "platformdirs",
    "importlib-metadata",
    "zipp",
    "click",
    "markupsafe",
    "jinja2",
    "pygments",
    "pillow",
    "scipy",
    "pandas",
    "pytz",
    "filelock",
    "colorama",
    "virtualenv",
    "distlib",
    "tomli",
    "flask",
    "django",
    "fastapi",
    "uvicorn",
    "gunicorn",
    "celery",
    "sqlalchemy",
    "psycopg2",
    "pymysql",
    "redis",
    "pymongo",
    "pytest",
    "tox",
    "coverage",
    "black",
    "mypy",
    "ruff",
    "isort",
    "pydantic",
    "httpx",
    "aiohttp",
    "scrapy",
    "beautifulsoup4",
    "tensorflow",
    "torch",
    "transformers",
    "scikit-learn",
    "matplotlib",
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "cohere",
    "telnyx",
    "twilio",
    "stripe",
    "sendgrid",
];

/// Top crates.io packages
const CRATES_TOP_PACKAGES: &[&str] = &[
    "serde",
    "serde_json",
    "tokio",
    "clap",
    "rand",
    "regex",
    "log",
    "anyhow",
    "thiserror",
    "reqwest",
    "hyper",
    "axum",
    "actix-web",
    "warp",
    "rocket",
    "sqlx",
    "diesel",
    "sea-orm",
    "rusqlite",
    "redis",
    "tracing",
    "env_logger",
    "pretty_env_logger",
    "chrono",
    "uuid",
    "url",
    "base64",
    "sha2",
    "ring",
    "rayon",
    "crossbeam",
    "dashmap",
    "parking_lot",
    "syn",
    "quote",
    "proc-macro2",
    "darling",
    "toml",
    "config",
    "dotenv",
    "envy",
    "itertools",
    "once_cell",
    "lazy_static",
    "paste",
    "bytes",
    "memmap2",
    "walkdir",
    "glob",
    "tempfile",
];

pub struct PreflightResult {
    pub findings: Vec<Finding>,
    pub packages_checked: usize,
}

pub fn run_preflight(root: &Path, json_output: bool) -> anyhow::Result<PreflightResult> {
    let mut findings = Vec::new();

    // 1. Check package.json install scripts
    check_package_json_scripts(root, &mut findings);

    // 2. Parse lockfiles and check for typosquatting
    let lockfile_results = parsers::parse_all_lockfiles(root, 3);
    let mut all_packages: Vec<parsers::Package> = Vec::new();

    for (_name, pkgs) in &lockfile_results {
        all_packages.extend(pkgs.iter().cloned());
    }
    let packages = parsers::deduplicate(all_packages);
    let package_count = packages.len();

    // Check typosquatting
    for pkg in &packages {
        check_typosquatting(pkg, &mut findings);
    }

    // 3. Check lockfile hash integrity
    check_lockfile_hashes(root, &mut findings);

    // 4. Query deps.dev for metadata (if packages are few enough)
    if package_count <= 50 {
        check_package_metadata(&packages, &mut findings);
    }

    let result = PreflightResult {
        findings: findings.clone(),
        packages_checked: package_count,
    };

    if json_output {
        let output = serde_json::json!({
            "packages_checked": package_count,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_preflight_result(&result);
    }

    Ok(result)
}

fn check_package_json_scripts(root: &Path, findings: &mut Vec<Finding>) {
    let package_json = root.join("package.json");
    if !package_json.exists() {
        return;
    }

    let content = match std::fs::read_to_string(&package_json) {
        Ok(c) => c,
        Err(_) => return,
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    let scripts = match parsed.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return,
    };

    let hooks = ["preinstall", "postinstall", "install"];
    for hook in &hooks {
        if let Some(script) = scripts.get(*hook).and_then(|s| s.as_str()) {
            findings.push(Finding {
                rule_id: "DEPSEC-PF001".into(),
                severity: Severity::Medium,
                message: format!("Install script '{hook}': {script}"),
                file: Some("package.json".into()),
                line: None,
                suggestion: Some(format!(
                    "Review the '{hook}' script — install hooks run automatically during npm install"
                )),
                auto_fixable: false,
            });
        }
    }
}

fn check_typosquatting(pkg: &parsers::Package, findings: &mut Vec<Finding>) {
    let popular = match pkg.ecosystem {
        parsers::Ecosystem::Npm => NPM_TOP_PACKAGES,
        parsers::Ecosystem::PyPI => PYPI_TOP_PACKAGES,
        parsers::Ecosystem::CratesIo => CRATES_TOP_PACKAGES,
        _ => return,
    };

    // Skip if the package IS in the top list
    if popular.contains(&pkg.name.as_str()) {
        return;
    }

    for &top_pkg in popular {
        let distance = levenshtein(&pkg.name, top_pkg);
        if distance > 0 && distance <= 2 {
            findings.push(Finding {
                rule_id: "DEPSEC-T001".into(),
                severity: Severity::High,
                message: format!(
                    "Possible typosquat: '{}' is similar to popular package '{top_pkg}' (distance: {distance})",
                    pkg.name
                ),
                file: None,
                line: None,
                suggestion: Some(format!(
                    "Verify you intended to install '{}' and not '{top_pkg}'",
                    pkg.name
                )),
                auto_fixable: false,
            });
            break; // One match per package is enough
        }
    }
}

/// Levenshtein distance — pure Rust, no dependencies
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, a_char) in a.chars().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_char) in b.chars().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

fn check_lockfile_hashes(root: &Path, findings: &mut Vec<Finding>) {
    // Check package-lock.json for integrity hashes
    let npm_lock = root.join("package-lock.json");
    if npm_lock.exists() {
        if let Ok(content) = std::fs::read_to_string(&npm_lock) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(pkgs) = parsed.get("packages").and_then(|p| p.as_object()) {
                    let missing_hash = pkgs
                        .values()
                        .filter(|v| {
                            !v.get("link").and_then(|l| l.as_bool()).unwrap_or(false)
                                && v.get("integrity").is_none()
                                && v.get("version").is_some()
                        })
                        .count();

                    if missing_hash > 0 {
                        findings.push(Finding {
                            rule_id: "DEPSEC-T007".into(),
                            severity: Severity::Medium,
                            message: format!(
                                "{missing_hash} packages in package-lock.json missing integrity hashes"
                            ),
                            file: Some("package-lock.json".into()),
                            line: None,
                            suggestion: Some("Regenerate lockfile with 'npm install' to add integrity hashes".into()),
                            auto_fixable: false,
                        });
                    }
                }
            }
        }
    }
}

fn check_package_metadata(packages: &[parsers::Package], findings: &mut Vec<Finding>) {
    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(10))
        .user_agent("depsec")
        .build();

    for pkg in packages.iter().take(20) {
        // Rate limit: only check first 20
        let ecosystem = match pkg.ecosystem {
            parsers::Ecosystem::Npm => "npm",
            parsers::Ecosystem::PyPI => "pypi",
            parsers::Ecosystem::CratesIo => "cargo",
            parsers::Ecosystem::Go => "go",
            parsers::Ecosystem::RubyGems => continue, // deps.dev doesn't support well
        };

        let url = format!(
            "https://api.deps.dev/v3alpha/systems/{}/packages/{}/versions/{}",
            ecosystem,
            urlencoded(&pkg.name),
            urlencoded(&pkg.version)
        );

        let resp = match agent.get(&url).call() {
            Ok(r) => r,
            Err(_) => continue, // Skip on network error
        };

        let body: serde_json::Value = match resp.into_json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check publish date — flag packages published very recently
        if let Some(published) = body.get("publishedAt").and_then(|p| p.as_str()) {
            if is_recently_published(published, 7) {
                findings.push(Finding {
                    rule_id: "DEPSEC-T002".into(),
                    severity: Severity::Medium,
                    message: format!(
                        "Package {} {} was published recently ({})",
                        pkg.name,
                        pkg.version,
                        &published[..10_usize.min(published.len())]
                    ),
                    file: None,
                    line: None,
                    suggestion: Some(
                        "Newly published packages near popular names may be typosquats".into(),
                    ),
                    auto_fixable: false,
                });
            }
        }

        // Check for missing source repo
        let has_source = body
            .get("links")
            .and_then(|l| l.as_array())
            .map(|links| {
                links
                    .iter()
                    .any(|l| l["label"].as_str() == Some("SOURCE_REPO"))
            })
            .unwrap_or(false);

        if !has_source {
            findings.push(Finding {
                rule_id: "DEPSEC-T004".into(),
                severity: Severity::Low,
                message: format!(
                    "Package {} {} has no linked source repository",
                    pkg.name, pkg.version
                ),
                file: None,
                line: None,
                suggestion: Some("Packages without source repos are harder to audit".into()),
                auto_fixable: false,
            });
        }
    }
}

/// Simple URL encoding for package names (handles @ and /)
fn urlencoded(s: &str) -> String {
    s.replace('@', "%40").replace('/', "%2F")
}

/// Check if an ISO 8601 date string is within `days` of today.
/// Simple implementation without chrono dependency.
fn is_recently_published(date_str: &str, days: u64) -> bool {
    // Parse "2026-03-27T..." — extract YYYY-MM-DD
    if date_str.len() < 10 {
        return false;
    }
    let date_part = &date_str[..10];
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return false;
    }

    let year: i64 = parts[0].parse().unwrap_or(0);
    let month: i64 = parts[1].parse().unwrap_or(0);
    let day: i64 = parts[2].parse().unwrap_or(0);

    // Get today's date
    let today = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let today = today.trim();

    let today_parts: Vec<&str> = today.split('-').collect();
    if today_parts.len() != 3 {
        return false;
    }

    let ty: i64 = today_parts[0].parse().unwrap_or(0);
    let tm: i64 = today_parts[1].parse().unwrap_or(0);
    let td: i64 = today_parts[2].parse().unwrap_or(0);

    // Approximate days difference (not perfect but good enough)
    let pub_days = year * 365 + month * 30 + day;
    let today_days = ty * 365 + tm * 30 + td;
    let diff = today_days - pub_days;

    diff >= 0 && diff <= days as i64
}

fn print_preflight_result(result: &PreflightResult) {
    println!(
        "\ndepsec preflight — {} packages analyzed\n",
        result.packages_checked
    );

    if result.findings.is_empty() {
        println!("\x1b[32m✓\x1b[0m All clear — no pre-install concerns found.");
        return;
    }

    let critical = result
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .count();
    let warnings = result.findings.len() - critical;

    for finding in &result.findings {
        let icon = match finding.severity {
            Severity::Critical | Severity::High => "\x1b[31m✗\x1b[0m",
            _ => "\x1b[33m⚠\x1b[0m",
        };
        println!("  {icon} [{}] {}", finding.rule_id, finding.message);
        if let Some(ref suggestion) = finding.suggestion {
            println!("    → {suggestion}");
        }
    }

    println!();
    if critical > 0 {
        println!(
            "\x1b[31m{critical} high-risk finding{}\x1b[0m, {warnings} warning{}.",
            if critical == 1 { "" } else { "s" },
            if warnings == 1 { "" } else { "s" }
        );
    } else {
        println!(
            "{warnings} warning{} found.",
            if warnings == 1 { "" } else { "s" }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein("lodash", "lodash"), 0);
    }

    #[test]
    fn test_levenshtein_one_char() {
        assert_eq!(levenshtein("lodash", "lodas"), 1); // deletion
        assert_eq!(levenshtein("lodash", "lodahs"), 2); // transposition = 2 ops in Levenshtein
        assert_eq!(levenshtein("lodash", "lodashh"), 1); // insertion
    }

    #[test]
    fn test_levenshtein_typosquat() {
        assert!(levenshtein("loadsh", "lodash") <= 2);
        assert!(levenshtein("requets", "requests") <= 2);
        assert!(levenshtein("colorsama", "colorama") <= 2);
    }

    #[test]
    fn test_levenshtein_different() {
        assert!(levenshtein("react", "express") > 2);
    }

    #[test]
    fn test_levenshtein_empty() {
        assert_eq!(levenshtein("", "hello"), 5);
        assert_eq!(levenshtein("hello", ""), 5);
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn test_typosquatting_detection() {
        let mut findings = Vec::new();
        let pkg = parsers::Package {
            name: "loadsh".into(), // typosquat of "lodash"
            version: "1.0.0".into(),
            ecosystem: parsers::Ecosystem::Npm,
        };
        check_typosquatting(&pkg, &mut findings);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "DEPSEC-T001");
    }

    #[test]
    fn test_legitimate_package_not_flagged() {
        let mut findings = Vec::new();
        let pkg = parsers::Package {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: parsers::Ecosystem::Npm,
        };
        check_typosquatting(&pkg, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoded("@types/node"), "%40types%2Fnode");
        assert_eq!(urlencoded("express"), "express");
    }
}
