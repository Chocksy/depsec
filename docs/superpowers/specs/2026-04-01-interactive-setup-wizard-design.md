# Interactive Setup Wizard

**Date:** 2026-04-01
**Status:** Approved

## Problem

`depsec setup` currently requires users to know which flags to pass. There's no guided onboarding, no persistent preferences, and sandbox protection requires an explicit `--sandbox` flag on every `depsec protect` call. The website and README list commands but don't walk users through a "get protected in 2 minutes" flow. Socket.dev's one-command `socket wrapper on` is simpler than our multi-step setup.

## Solution

Transform `depsec setup` (no flags) into an interactive checkbox wizard that configures all protections in one step, saves preferences globally, and makes sandbox the default for protected installs.

## Setup Wizard Flow

### Interactive Mode (TTY detected, no flags)

```
depsec v0.15.0 — Setup

◆ Select protections to install
  ❯ ● Shell protection    Wraps npm/yarn/pip/cargo with monitoring
    ● Pre-commit hook     Blocks secrets from being committed
    ● Sandbox by default  Sandboxes all protected installs
    ○ Network baseline    Initialize connection baseline for this project
    ○ Self-check          Verify depsec binary integrity

  ↑↓ move  space toggle  enter confirm
```

If "Pre-commit hook" is selected, a follow-up prompt:

```
◆ Pre-commit hook scope
  ❯ ● This project only   .git/hooks/pre-commit
    ○ Global (all repos)  git config --global core.hooksPath ~/.depsec/hooks
```

Then sandbox detection and install summary:

```
◆ Sandbox status
  ✓ sandbox-exec available (macOS built-in)

Installing...
  ✓ Shell protection added to ~/.zshrc
  ✓ Pre-commit hook installed at .git/hooks/pre-commit
  ✓ Sandbox enabled by default
  ✓ Config saved to ~/.depsec/config.toml

Restart your shell or run: source ~/.zshrc
```

### Non-Interactive Paths

| Invocation | Behavior |
|------------|----------|
| No TTY (LLM/CI/pipe) | Install defaults (shell + hook + sandbox) silently |
| `depsec setup --all` | Same as above, explicit flag |
| `depsec setup --hook --shell` | Only those specific items, no wizard |
| Individual flags | Keep working exactly as today (backward compat) |

### Checkbox Options

| Option | What it does | Default |
|--------|-------------|---------|
| Shell protection | Detects shell (zsh/bash/fish), appends `eval "$(depsec setup --shell)"` to RC file | **selected** |
| Pre-commit hook | Installs secret detection hook (project or global scope) | **selected** |
| Sandbox by default | Saves `sandbox = true` to global config | **selected** |
| Network baseline | Creates `.depsec/monitor-baseline.json` in current project | unselected |
| Self-check | Verifies depsec binary integrity (one-time) | unselected |

### Shell Profile Auto-Modification

When "Shell protection" is selected:

1. Detect shell from `$SHELL` env var
2. Determine RC file: `~/.zshrc` (zsh), `~/.bashrc` (bash), `~/.config/fish/config.fish` (fish)
3. Check if `depsec setup --shell` is already present (idempotent)
4. Append the eval line
5. Print which file was modified

No dry-run or confirmation — just do it.

### Global Pre-Commit Hook

When user picks "Global (all repos)":

1. Write `~/.depsec/hooks/pre-commit` with depsec's secret check
2. The hook script chains: runs depsec check first, then checks if a local `.git/hooks/pre-commit` exists and runs that too (preserves existing per-project hooks)
3. Run `git config --global core.hooksPath ~/.depsec/hooks`

## Config Layout

### Global: `~/.depsec/config.toml`

```toml
# Written by `depsec setup` — tracks installed protections
[setup]
shell_hook = true
hook_scope = "project"               # "project" or "global"
shell_profile = "/Users/user/.zshrc" # which file was modified

[protect]
sandbox = true                       # default sandbox for all `depsec protect` calls
```

### Per-Project Override: `depsec.toml` (existing, new section)

```toml
[protect]
sandbox = false  # override: disable sandbox for this specific project
```

### Priority Chain

```
CLI flag > project depsec.toml > global ~/.depsec/config.toml > built-in default (off)
```

## Protect Command Changes

### New Behavior

`depsec protect npm install foo` now reads config and sandboxes if enabled:

```
$ depsec protect npm install lodash
[depsec protect] Running preflight check...
  ✓ Preflight check passed
[depsec protect] Running sandboxed install (sandbox-exec)...
  ✓ Sandbox install passed (clean)
[depsec protect] Monitoring: npm install lodash
  ✓ Install completed cleanly
```

### New `--no-sandbox` Flag

Added for explicit opt-out. Existing `--sandbox` flag still works as force-on.

### Flag Resolution Logic

```
if --sandbox flag    → sandbox ON  (override everything)
if --no-sandbox flag → sandbox OFF (override everything)
else → read depsec.toml [protect].sandbox
else → read ~/.depsec/config.toml [protect].sandbox
else → OFF (backward compat default)
```

Backward compatibility: if no setup has been run and no config exists, behavior is identical to today.

## Idempotency

Running `depsec setup` again after initial setup:

- Wizard pre-selects options based on current config (reads `~/.depsec/config.toml`)
- Shell hook check: if `eval "$(depsec setup --shell)"` already in RC file, skip (don't duplicate)
- Pre-commit hook: overwrite with latest version (safe — it's our script)
- Config: merge new selections, don't lose existing settings

Running `depsec setup --all` when already set up: no-op with "Already configured" message for items that are already installed.

## New Dependency

`dialoguer = "0.11"` — for `MultiSelect` and `Select` widgets. Handles arrow keys, space toggle, enter confirm, colors. Well-maintained, 10M+ downloads.

## Files to Create/Modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add `dialoguer = "0.11"` |
| `src/commands/setup.rs` | Rewrite: interactive wizard + non-interactive fallback |
| `src/commands/protect.rs` | Read global/project config for sandbox default |
| `src/main.rs` | Add `--no-sandbox` flag, add `--all` flag to Setup |
| `src/config.rs` | Add global config reader (`~/.depsec/config.toml`), add `[protect]` section to project config |
| `src/shellhook.rs` | Add `install_to_profile()` function that writes to RC file |
| `README.md` | Update setup section with new wizard flow |
| `SKILL.md` | Update setup instructions |
