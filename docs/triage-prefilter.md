# Triage (Liquid d1 via OpenRouter, no Sonnet tier)

> **Changed:** triage is now d1-only. There is no Claude Sonnet / expensive LLM tier in `depsec scan --triage`.
> depsec reads its own key from `DEPSEC_OPENROUTER_API_KEY` and does **not** fall back to `OPENROUTER_API_KEY`
> unless you opt in with `triage.allow_shared_key = true` or `DEPSEC_ALLOW_SHARED_OPENROUTER_KEY=1`.
> If no key is found, `--triage` prints setup help and triage is skipped.
> `depsec audit` uses the same d1 model and key rules (one verdict per capability site). The old Sonnet code has been removed.

## Decision rules (current)

| Finding | Result |
|---|---|
| Deterministic rule | Auto-resolved, no model call |
| Protected family (list below) | Never sent to d1, never suppressed: NEEDS INVESTIGATION |
| d1 says `FP` with confidence >= `prefilter_fp_threshold` (0.95) | FALSE POSITIVE |
| d1 says `TP` | TRUE POSITIVE |
| `FP` below the bar, `UNSURE`, or API error | NEEDS INVESTIGATION |

## Eval

`depsec triage-eval <corpus> --label tp|fp --limit 200 --out eval.json` runs d1 on a labelled corpus
(tp = malware, fp = benign) and reports FP-filter precision/recall, malware TP recall, malware marked FP at
the bar (must be 0), cost and latency. Secret findings (DEPSEC-S*) are never sent. Stops at `DEPSEC_EVAL_BUDGET`
USD (default 0.95). Paid, never run in CI.

---

_Historical notes (original prefilter design) follow; key and Sonnet details below are superseded._

# Triage prefilter (Liquid d1 via OpenRouter)

`depsec scan --triage` sends every ambiguous finding to the triage LLM (Claude Sonnet 4.6 by default, about $3/M input tokens). The prefilter adds a cheap first pass with Liquid's `d1-ultra` decision model ($0.042/M input tokens, output free, served through OpenRouter's System One endpoint). It only auto-clears findings it is very sure are false positives. Everything else still goes to the LLM exactly as before.

## Enable

Off by default. Turn it on per run or in `depsec.toml`:

```sh
export OPENROUTER_API_KEY=sk-or-...        # same key as --triage
depsec scan . --triage --triage-prefilter d1
```

```toml
[triage]
prefilter = "d1"                   # "" (off, default) or "d1"
prefilter_model = "liquid/d1-ultra"
prefilter_fp_threshold = 0.95      # auto-mark FP only at/above this confidence
prefilter_snippet_lines = 3        # code lines sent on each side of the flagged line
prefilter_always_llm = []          # extra rule-ID prefixes that always skip the prefilter
```

The API key is read from the env var named in `api_key_env` (default `OPENROUTER_API_KEY`). It is only ever placed in the `Authorization` header and is never printed or logged.

## Decision rules

d1 answers one `choice` question per finding: `TP`, `FP` or `UNSURE`, with a confidence.

| d1 answer | What happens |
|---|---|
| `FP` with confidence >= `prefilter_fp_threshold` | Finding marked FALSE POSITIVE, stage `prefilter`. No LLM call. |
| `FP` below threshold, `TP`, `UNSURE`, or API error | Sent to the LLM as today. The d1 cost and latency are added to that finding's totals. |

These rule families never reach the prefilter and always go to the LLM, regardless of config:

- `DEPSEC-MAL*` known malware
- `DEPSEC-T*` typosquatting
- `DEPSEC-D*` and `DEPSEC-V*` dependency advisories and known vulnerabilities
- `DEPSEC-S*` secret leaks
- `DEPSEC-PF*` preflight
- `DEPSEC-P006`, `DEPSEC-P012`, `DEPSEC-P016` install-script findings
- `DEPSEC-P015` self-deleting code

`prefilter_always_llm` can only add to this list.

## Privacy: what gets sent

OpenRouter notes that requests to `liquid/d1-ultra` may be used for training. The prefilter therefore never sends whole files. Each request contains only:

- rule ID, rule message, severity, package label, relative file path and line number
- the flagged line plus `prefilter_snippet_lines` lines on each side (default 3), each line capped at 200 characters

Secrets never reach the prefilter at all (see the protected list above). Set `prefilter_snippet_lines = 0` to send the flagged line only. The full LLM triage is unchanged and still sends its usual ±30 lines of context.

## Output

Every triage verdict now records which stage decided it and what it cost:

```
  ✓ FALSE POSITIVE (97%) [prefilter]: lodash — DEPSEC-P001
    node_modules/lodash/index.js:120 · $0.00001 · 140ms
  ✗ TRUE POSITIVE (95%) [llm]: evil-pkg — DEPSEC-P002
    node_modules/evil-pkg/index.js:3 · $0.00912 · 3200ms

  Summary: 1 true positive, 1 false positive, 0 needs investigation
  Stages: 0 deterministic, 1 prefilter, 1 llm, 0 cache
  API cost: ~$0.0091 (2900 LLM tokens)
```

Stages: `deterministic` (scanner-verified, no model), `prefilter` (d1 cleared it), `llm` (full triage), `cache` (served from the local triage cache). The same fields (`stage`, `cost_usd`, `latency_ms`) are stored in the triage cache JSON.

## Eval: is d1 good enough?

`depsec triage-eval` runs d1 and the LLM on the same findings, bypassing the cache, and reports agreement, how many findings would still go to the LLM, any protected finding d1 marked FP, and cost. It is paid (both models are called for every finding) so it is never run in CI.

```sh
export OPENROUTER_API_KEY=sk-or-...
cargo build --release
./target/release/depsec triage-eval /path/to/project-with-node_modules --limit 200 --out eval.json
```

Pick a project with a big `node_modules` so the scanner produces at least 200 pattern findings. The command uses the auditor persona (all confidence levels) and skips deterministic rules. Protected malware and supply-chain findings are still sent to d1 so its errors can be measured. Secret-leak findings (`DEPSEC-S*`) are never sent to d1, not even here.

Pass bar (exit code 0 only when all three hold):

- `...LLM agrees FP` >= 90% of the findings the prefilter would clear
- `...LLM says TP` = 0 (no cleared finding that the LLM considers real)
- `protected marked FP by d1` = 0 (measured for information only; production never asks d1 about these)

Example output:

```
Prefilter eval
findings evaluated:            200
both models answered:          198
prefilter would clear (FP):    61
...LLM agrees FP:              58  (95.1%  pass bar >= 90%)
...LLM says TP:                0  (must be 0)
protected marked FP by d1:     0  (must be 0; never acted on)
raw 3-way agreement:           71.2%
still sent to LLM:             137
d1 cost:                       $0.00210  (p50 180 ms)
LLM cost:                      $1.1420  (p50 3100 ms)
verdict:                       PASS
```

`--out eval.json` writes the summary plus one row per finding (both verdicts, confidences, cost, latency) for inspection.
