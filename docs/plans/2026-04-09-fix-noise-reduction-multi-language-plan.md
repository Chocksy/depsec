# Sprint 8: Noise Reduction — Multi-Language False Positives + Secrets Tuning

## Problem Statement

Real-world scans on ai-standups (Python) and hubstaff-server (Ruby/Rails) reveal significant
noise issues after Sprint 7's multi-language parity work. The scanner applies JS-centric
assumptions to Python/Ruby/Rust code, producing hundreds of false positives.

## Evidence

### ai-standups (Python + JS): 1103 findings from .venv

| Rule | Count | Problem |
|------|------:|---------|
| P007 | 389 | High-entropy strings in data tables (google pkg: 360 alone) |
| **P011** | **289** | **JS-only regex (`process.env`) matching `os.environ` in Python** |
| P020 | 161 | eval/exec is standard in Python (flask, jinja2, mako, sqlalchemy) |
| P023 | 134 | `__import__()` is standard Python for compatibility/lazy loading |
| P001 | 67 | Regex overlap with AST — exec() in Python already caught by P020 |
| P024 | 30 | pickle is common in Python data processing packages |
| P003 | 15 | Raw IP `127.0.0.1` in test/config files |
| **P013** | **2** | **JS `require()` regex firing on Python files** |
| **P014** | **2** | **JS `fromCharCode` regex firing on Python files** |

Noisiest packages: `google` (393), `_pytest` (83), `sqlalchemy` (80), `openai` (32)

### hubstaff-server (Ruby/Rails): Grade F (3.8/10)

**Secrets check: 0% (52 findings) — almost all false positives:**

| Category | Count | Problem |
|----------|------:|---------|
| `clie...RET` Generic Secret | ~30 | ENV var references like `client_secret` — NOT actual secrets, just variable names |
| JWT tokens in spec/ | 8 | Test fixture tokens — not real secrets |
| Private keys in spec/ | 3 | Test fixture keys — not real secrets |
| `clie...374` in spec/ | 5 | Test fixture data |
| High-entropy "secrets" | 4 | URLs like AUTH_URL, TOKEN_URL, AUTH_SCOPE — not secrets |
| Private key in docs/ | 1 | Example key in documentation |
| Postgres conn string | 1 | Uses `${DATABASE_NAME}` env var — not a real credential |

**Root causes:**
1. No test/spec directory exclusion — secrets scanner flags test fixtures
2. No ENV var reference detection — `ENV['CLIENT_SECRET']` treated as a leaked secret
3. No URL detection — high-entropy URLs flagged as secrets
4. No `.yml` template detection — config files with `<%= ENV['...'] %>` treated as secrets

**Patterns: 56% (364 findings):**
- 317 build-tool findings suppressed (good!) but 47 remain in 8 runtime packages

**Workflows: 0% (110 findings):**
- 88 unpinned workflow actions — real issue but not a depsec noise problem

## Implementation Plan

### Phase 1: Gate JS-Only Regex Rules by Language (kills ~293 FPs in Python)

**Problem:** P011, P013, P014, P008, P017, P018, P019 are JS-specific patterns that
should never fire on Python/Ruby/Rust files.

**Fix in `scan_single_file()` (patterns.rs):**
```rust
// Before regex matching, check if rule is JS-only and file is non-JS
fn is_js_only_rule(rule_id: &str) -> bool {
    matches!(rule_id,
        "DEPSEC-P008" | "DEPSEC-P011" | "DEPSEC-P013" | "DEPSEC-P014" |
        "DEPSEC-P015" | "DEPSEC-P017" | "DEPSEC-P018" | "DEPSEC-P019"
    )
}

// In the regex loop:
if is_js_only_rule(rule.rule_id) && !is_js_or_ts(path) {
    continue;
}
```

**Expected impact:** -293 false positives on ai-standups Python scan

### Phase 2: Python-Specific Severity Tuning

**P020 (eval/exec):** In Python, `exec("static string")` is standard for template engines.
- Static string arg → Low severity (currently Medium)
- Variable arg → keep High

**P023 (__import__):** In Python, `__import__("os")` is standard for compatibility shims.
- Static string arg → Low severity (currently Medium)
- Variable arg → keep Critical
- Consider: skip if inside `six.py`, `importlib` or well-known compatibility modules

**P024 (pickle):** Context matters.
- In data packages → Medium (currently Critical)
- When combined with network capability → keep Critical (actual exfil risk)

**P001 regex on Python:** Should be suppressed when AST P020-P024 already handled the file.
- Same `ast_handled && is_ast_rule` pattern already used for JS — extend to Python/Ruby/Rust

### Phase 3: Secrets Scanner — Test Fixture Exclusion

**Problem:** hubstaff-server has 52 secret findings, ~45 are test fixtures or ENV references.

**Fix 1: Skip test directories by default**
```rust
// In secrets scanner, skip known test dirs
const SECRETS_SKIP_DIRS: &[&str] = &[
    "spec", "test", "tests", "__tests__", "fixtures",
    "factories", "e2e", "cypress",
];
```
Provide `--include-tests` flag to override.

**Fix 2: ENV var reference detection**
```rust
// Don't flag: ENV['CLIENT_SECRET'], process.env.SECRET, os.environ['KEY']
fn is_env_var_reference(line: &str, match_pos: usize) -> bool {
    // Check if the "secret" is inside ENV[...], process.env., os.environ[...], etc.
}
```

**Fix 3: URL detection**
```rust
// Don't flag high-entropy strings that are clearly URLs
fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}
```

**Fix 4: ERB/YAML template detection**
```rust
// Don't flag: <%= ENV['CLIENT_SECRET'] %> in .yml/.erb files
fn is_template_reference(line: &str) -> bool {
    line.contains("<%=") || line.contains("${") || line.contains("#{ENV")
}
```

### Phase 4: P007 High-Entropy String Tuning

**Problem:** 389 findings in ai-standups, 360 from `google` package alone.

**Fixes:**
1. Raise minimum length from 200 to 300 chars (reduces data table noise)
2. Skip `.json` files (structured data, not executable)
3. Skip files with >5 high-entropy hits (likely a data file, not code)
4. Consider: add entropy threshold per language (Python data modules have higher baselines)

### Phase 5: Suppress Regex When AST Already Handled (cross-language)

**Problem:** P001 regex fires 67 times on Python files alongside P020/P021/P022 AST findings.

**Fix:** Extend the `ast_handled` suppression to all languages:
```rust
fn is_ast_rule_for_lang(rule_id: &str, lang: Option<Lang>) -> bool {
    match lang {
        Some(Lang::Python) => matches!(rule_id, "DEPSEC-P001"),
        Some(Lang::Ruby) => matches!(rule_id, "DEPSEC-P001"),
        Some(Lang::Rust) => matches!(rule_id, "DEPSEC-P001"),
        _ => is_ast_rule(rule_id), // existing JS handling
    }
}
```

## Target Impact

| Project | Before | After (est.) |
|---------|--------|-------------|
| ai-standups (.venv) | 1103 findings | ~200 (meaningful) |
| hubstaff-server secrets | 52 (0%) | ~5 (real issues) |
| hubstaff-server patterns | 364 (56%) | ~50 (runtime only) |

## Hubstaff-Server Specific Issues (from real scan output)

### Secrets — True Positives to Keep
- `config/initializers/geocoder.rb:11` — `api_...KEY'` — **review**: could be a real hardcoded key
- `config/initializers/webhooks.rb:6` — `api_...RET'` — **review**: could be a real hardcoded key
- `lib/customer_io_manager.rb:92` — `api_...KEY'` — **review**: could be a real hardcoded key
- `spec/fixtures/files/staging-hubstaff-app-929d729ca748.json:5` — Private key in fixture — **real risk** if staging key

### Secrets — False Positives to Suppress
- `config/integrations.yml` (18 findings) — All `client_secret` ERB template references
- `config/payments.yml` (4 findings) — All `client_secret` ERB template references
- `spec/` (15 findings) — All test fixtures (JWT tokens, mock secrets)
- `docs/` (2 findings) — Example keys in documentation
- `lib/firebase_cloud_message_sender.rb` — AUTH_SCOPE is a URL, not a secret
- `lib/slack_utils.rb` — AUTH_URL is a URL, not a secret
- `bin/add_partitions:5` — Postgres conn uses `${DATABASE_NAME}` env var

### Workflow Issues (real, not noise)
- 88 unpinned workflow actions — `depsec fix` can address these
- 22 workflow permission issues — need review

## Files to Modify

- `src/checks/patterns.rs` — JS-only rule gating, AST suppression for Python/Ruby/Rust
- `src/checks/secrets.rs` — Test dir exclusion, ENV reference detection, URL filtering
- `src/checks/capabilities.rs` — No changes needed (already multi-language)
- `tests/` — Add noise reduction tests

## Key Principle

**Better to miss a subtle attack than to cry wolf 1000 times.** A scanner with 90%
false positive rate gets ignored. Target: <5% FP rate for High/Critical findings.
