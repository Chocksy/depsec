# Layer 2: LLM Triage — Detailed Design

**Date:** 2026-03-28
**Status:** Draft
**Goal:** For each finding from Layer 1, answer "is this actually dangerous in context?" using LLM analysis.
**Prerequisite:** Layer 1 (smart filtering) should be implemented first to minimize what needs LLM triage.

---

## Overview

Layer 2 adds an optional `--triage` flag that sends remaining findings (after Layer 1's AST filtering) to an LLM for contextual analysis. This is the **SAST-first, LLM-second** architecture proven by Semgrep Assistant (96% agreement with security researchers), CyberArk Vulnhalla (96% FP reduction), and Datadog Bits AI.

**The key insight:** LLMs are better at *filtering* false positives than at *finding* vulnerabilities. We use the LLM to reduce noise, not to generate findings.

---

## 1. Architecture

```
depsec scan . --triage

┌─────────────────────────────────────────────────┐
│ Stage 1: Normal Scan (Layer 1)                  │
│ ├── Workflows check                             │
│ ├── Deps check (OSV API)                        │
│ ├── Patterns check (regex + tree-sitter)        │
│ ├── Secrets check                               │
│ └── Hygiene check                               │
│                                                 │
│ Output: N findings (after AST filtering)        │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ Stage 2: LLM Triage (Layer 2)                   │
│                                                 │
│ For each finding:                               │
│ 1. Gather context (surrounding code, imports,   │
│    package metadata, dataflow)                  │
│ 2. Send to LLM with structured prompt           │
│ 3. LLM returns: TP/FP/NEEDS_INFO + confidence  │
│ 4. Filter output based on LLM verdict           │
│                                                 │
│ Output: M findings (M << N)                     │
└─────────────────────────────────────────────────┘
```

### Why SAST-first?

| Approach | False Positive Rate | Source |
|----------|-------------------|--------|
| LLM-only (no SAST) | Very high, unreliable | Checkmarx evaluation, academic benchmarks |
| SAST-only (no LLM) | 92% on OWASP Benchmark | arxiv 2601.22952 |
| SAST → LLM triage | **6.3%** on OWASP Benchmark | arxiv 2601.22952 |

---

## 2. LLM Provider: OpenRouter

### 2.1 Why OpenRouter

- **Single API endpoint** — `https://openrouter.ai/api/v1/chat/completions`
- **OpenAI-compatible API** — use any Rust HTTP client, no SDK needed
- **Model flexibility** — users choose: Claude Sonnet (best), GPT-4o, Gemini, open-source models
- **No vendor lock-in** — if OpenRouter disappears, swap to direct Anthropic/OpenAI API with minimal changes
- **Cost transparency** — OpenRouter shows per-request costs

### 2.2 Configuration

```toml
# depsec.toml
[triage]
enabled = false                    # Must opt-in
api_key_env = "OPENROUTER_API_KEY" # Env var name for the API key
model = "anthropic/claude-sonnet-4-6"  # Default model
max_findings = 50                  # Don't send more than N findings per scan
timeout_seconds = 30               # Per-finding timeout
```

Or via environment:
```bash
export OPENROUTER_API_KEY="sk-or-..."
depsec scan . --triage
```

### 2.3 Rust Implementation

Use `reqwest` (already a dependency) + `serde_json`:

```rust
// No new crate dependencies needed!
// Just reqwest + serde_json (both already in Cargo.toml)

struct TriageRequest {
    model: String,
    messages: Vec<Message>,
    response_format: ResponseFormat, // JSON schema enforcement
    temperature: f32,                // 0.1 — low creativity for classification
}
```

**Minimal dependency footprint** — no LLM SDK crate needed. Just HTTP POST with JSON.

---

## 3. Context Construction

### 3.1 What to Send Per Finding

Stolen from Semgrep Assistant + Heelan's o3 approach:

```
For each finding, construct a context bundle:

1. The flagged code (the line that triggered the rule)
2. ±30 lines of surrounding code
3. Import statements in the file (first 50 lines or until first function)
4. The file path (relative to package root)
5. Package name + version
6. The rule that triggered (ID, description, severity)
7. If available: the function/class this code is inside of
```

**What NOT to send:**
- The entire file (token waste)
- Other files in the package (save for Layer 3)
- The full dependency tree
- Other findings (each finding is triaged independently)

### 3.2 Context Extraction Code

```rust
fn build_finding_context(finding: &Finding, root: &Path) -> TriageContext {
    let file_content = fs::read_to_string(&finding.file).unwrap_or_default();
    let lines: Vec<&str> = file_content.lines().collect();

    let start = finding.line.saturating_sub(30);
    let end = (finding.line + 30).min(lines.len());
    let surrounding = lines[start..end].join("\n");

    // Extract imports (first 50 lines or until first function/class)
    let imports = extract_imports(&lines);

    // Extract containing function/class
    let container = extract_containing_scope(&lines, finding.line);

    TriageContext {
        flagged_line: lines[finding.line - 1].to_string(),
        surrounding_code: surrounding,
        imports,
        containing_scope: container,
        file_path: finding.file.strip_prefix(root).unwrap().to_path_buf(),
        package_name: finding.package.clone(),
        rule_id: finding.rule_id.clone(),
        rule_description: finding.message.clone(),
        rule_severity: finding.severity,
    }
}
```

---

## 4. Prompt Design

### 4.1 System Prompt

Stolen from Anthropic security-review + Vulnhalla + Heelan:

```
You are a security analyst triaging static analysis findings. Your job is to classify
each finding as a True Positive (real vulnerability), False Positive (not a real issue),
or Needs Investigation (insufficient context to decide).

CRITICAL RULES:
- Better to miss a theoretical issue than report a false positive
- You MUST cite specific line numbers and code as evidence for your classification
- If the code uses the flagged pattern safely (e.g., static strings, sanitized input),
  classify as False Positive
- If the flagged pattern handles user-controlled input without sanitization,
  classify as True Positive
- If you cannot determine the input source, classify as Needs Investigation

Respond ONLY with the JSON schema provided. Do not add commentary outside the schema.
```

### 4.2 User Prompt Template

```
## Finding to Triage

**Rule:** {rule_id} — {rule_description}
**Severity:** {severity}
**Package:** {package_name}
**File:** {file_path}:{line_number}

### Flagged Line
```{language}
{flagged_line}
```

### Surrounding Code (±30 lines)
```{language}
{surrounding_code}
```

### File Imports
```{language}
{imports}
```

### Containing Function/Class
```{language}
{containing_scope}
```

Classify this finding.
```

### 4.3 Response Schema (Structured Output)

Stolen from Vulnhalla's numeric codes + Anthropic's confidence scores:

```json
{
    "classification": "TP|FP|NI",
    "confidence": 0.0-1.0,
    "reasoning": "One paragraph explaining the classification with specific code references",
    "evidence": {
        "flagged_pattern": "What the rule detected",
        "context_analysis": "What the surrounding code reveals",
        "input_source": "Where the data comes from (user input, static, internal, unknown)",
        "sanitization": "Whether input is sanitized before reaching the flagged pattern"
    },
    "recommendation": "What the user should do (if TP: fix suggestion, if FP: why it's safe)"
}
```

**Confidence thresholds:**
- `>= 0.8`: Show the classification as-is
- `0.5 - 0.8`: Show as "Likely TP/FP" with reduced confidence
- `< 0.5`: Classify as Needs Investigation regardless of LLM's answer

### 4.4 Anti-Hallucination Techniques

| Technique | Stolen From | Implementation |
|-----------|-------------|----------------|
| Require line number citations | GitHub Taskflow Agent | Prompt directive: "cite specific line numbers" |
| Conservative bias | Heelan, Anthropic | "Better to miss theoretical issues than report FPs" |
| Structured JSON output | Vulnhalla, Anthropic | Response schema enforcement via OpenRouter |
| Low temperature | Vulnhalla | temperature: 0.1 |
| Confidence threshold | Anthropic security-review | Discard findings below 0.5 confidence |
| Evidence requirement | GitHub Taskflow Agent | JSON schema forces `evidence` field |

---

## 5. Output Integration

### 5.1 Triage-Enhanced Output

```
[Patterns — LLM Triage Results]
  ✗ TRUE POSITIVE (0.95 confidence):
    shelljs@0.8.5 — exec() with unsanitized variable in src/exec.js:45
    → Input comes from function parameter, no validation
    → Recommendation: Validate/escape the command argument

  ~ NEEDS INVESTIGATION (0.62 confidence):
    execa@5.1.1 — exec() with variable in lib/command.js:23
    → Variable comes from internal function, source unclear
    → Recommendation: Trace the call chain to verify input source

  ✓ FALSE POSITIVE (0.91 confidence):
    posthog-js@1.57.2 — 3 exec() calls are all regex.exec() on user-agent strings
    → Safe: regex pattern matching, not shell execution

  Summary: 1 true positive, 1 needs investigation, 1 false positive (3 total triaged)
  LLM cost: ~$0.003 (3 findings × ~1k tokens each)
```

### 5.2 Cost Estimation

Before running triage, show estimated cost:

```
depsec scan . --triage

Found 47 findings to triage.
Estimated cost: ~$0.05 (Claude Sonnet, ~1k tokens/finding)
Proceed? [Y/n]
```

In CI mode (`--ci` or non-interactive), skip the prompt and proceed (or respect `--triage-budget 0.10` max cost).

---

## 6. Caching

### 6.1 Cache Strategy

Cache triage results by `(package_name, package_version, rule_id, file_hash)`:

```
~/.cache/depsec/triage/
├── shelljs@0.8.5/
│   └── P001-a3f2b1c4.json  # hash of the flagged code context
├── posthog-js@1.57.2/
│   └── P001-b7d1e3f2.json
```

If the package version and flagged code haven't changed, reuse the cached verdict. This means:
- First scan with `--triage`: pays API cost
- Subsequent scans: instant (cached)
- Package update: re-triages only changed packages

### 6.2 Cache Expiration

```toml
[triage.cache]
ttl_days = 30  # Re-triage after 30 days even if code hasn't changed
```

---

## 7. Batch Mode vs Individual Mode

### 7.1 Individual Mode (Default)

One API call per finding. Simpler, better context per finding, easier to cache.

### 7.2 Batch Mode (For Large Scans)

Group findings by package and send all findings for one package in a single request:

```
"Package: shelljs@0.8.5 has 3 findings. Triage each:

Finding 1: P001 at src/exec.js:45 — exec() with variable
[context...]

Finding 2: P001 at src/exec.js:78 — exec() with variable
[context...]

Finding 3: P006 at scripts/install.sh:12 — curl in install script
[context...]

Classify each finding independently."
```

**Advantage:** Shared package context (imports, purpose) improves accuracy.
**Disadvantage:** Harder to cache individual findings.

**Recommendation:** Start with individual mode. Add batch mode later if cost becomes an issue.

---

## 8. Model Recommendations

| Model | Best For | Cost/1k tokens | Quality |
|-------|----------|----------------|---------|
| `anthropic/claude-sonnet-4-6` | Default — best accuracy/cost | ~$0.003/$0.015 | Excellent |
| `anthropic/claude-haiku-4-5` | Budget — high volume scans | ~$0.001/$0.005 | Good |
| `anthropic/claude-opus-4-6` | Deep audit (Layer 3) | ~$0.015/$0.075 | Best |
| `openai/gpt-4o` | Alternative | ~$0.005/$0.015 | Very Good |
| `meta-llama/llama-3.3-70b` | Privacy-conscious (some providers run locally) | Varies | Acceptable |

Default to Claude Sonnet — it significantly outperforms other models for security analysis per VulnHuntr benchmarks.

---

## 9. Error Handling

- **API key missing:** Clear error message with setup instructions
- **API timeout:** Skip finding, mark as "triage failed — timeout"
- **Rate limiting:** Exponential backoff with max 3 retries
- **Invalid response:** Mark as "triage failed — invalid response", include in output
- **Budget exceeded:** Stop triaging, show results so far + count of untriaged findings
- **Network offline:** Fall back to Layer 1 output only, suggest `--triage` when online

---

## 10. Privacy Considerations

**What gets sent to the LLM API:**
- Snippets of dependency source code (node_modules, vendor — open source code)
- Package names and versions
- File paths within the dependency

**What does NOT get sent:**
- Your own source code (only dependency code is analyzed)
- API keys or secrets (secrets check runs locally, never sent to LLM)
- Full files (only ±30 lines around findings)

**Disclosure:** Add to `--triage` output:
```
Note: Triage sends snippets of open-source dependency code to [model provider] for analysis.
Your own source code is never sent. Use --triage-dry-run to see what would be sent.
```

---

## 11. Implementation Order

1. **OpenRouter client** — simple reqwest wrapper for chat completions
2. **Context extraction** — build context bundles from findings
3. **Prompt templates** — system + user prompt with structured output
4. **CLI integration** — `--triage` flag, cost estimation, interactive confirm
5. **Output formatting** — triage-enhanced findings display
6. **Caching** — file-based cache by package+version+rule+hash
7. **Error handling** — timeouts, retries, budget limits
8. **`--triage-dry-run`** — show what would be sent without calling API
