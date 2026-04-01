---
title: "feat: Interactive Setup Wizard"
type: feat
date: 2026-04-01
---

# feat: Interactive Setup Wizard

## Overview

Transform `depsec setup` (no flags) into an interactive checkbox wizard that configures all protections in one step, saves preferences to `~/.depsec/config.toml`, and makes sandbox the default for protected installs. Non-interactive fallback for LLMs/CI.

## Problem Statement

Users must know which flags to pass and manually edit shell profiles. There's no guided onboarding, no persistent preferences, and sandbox requires `--sandbox` on every `depsec protect` call. Socket.dev's `socket wrapper on` is one command — we need parity.

## Spec Reference

`docs/superpowers/specs/2026-04-01-interactive-setup-wizard-design.md`

## Design Decisions (from SpecFlow analysis)

| Question | Decision |
|----------|----------|
| Existing pre-commit hooks on project install | Back up to `.git/hooks/pre-commit.bak`, chain in depsec's hook |
| `[protect].sandbox = true` vs `[install].sandbox = "none"` | Boolean `true` maps to `"auto"` detection; `false` maps to `"none"` |
| Tri-state sandbox flag | `Option<bool>`: `Some(true)` = `--sandbox`, `Some(false)` = `--no-sandbox`, `None` = read config |
| Existing `core.hooksPath` set to non-depsec dir | Refuse with error, show current value, suggest `--force` |
| Ctrl+C during wizard | Print "Setup cancelled, no changes made", exit 0 |
| Shell RC file backup | Create `~/.zshrc.depsec-backup` before modifying |
| Non-interactive hook scope | Project-local if `.git/` exists, skip otherwise (with warning) |
| `--all` + individual flags | `--all` is a superset, individual flags alongside it are ignored |
| LLM pseudo-TTY detection | TTY check + `--non-interactive` flag escape hatch |
| RC file doesn't exist | Create it with just the eval line (common on fresh macOS) |
| Fish shell eval | Use `depsec setup --shell \| source` instead of `eval` |
| `~/.depsec/` directory | Create with `mkdir -p` equivalent on first write |
| Config file permissions | Set `0600` on `~/.depsec/config.toml` |

## Technical Approach

### Phase 1: Global Config System (`src/config.rs`)

Add a `GlobalConfig` struct separate from the existing `Config`:

```rust
// src/config.rs — new additions

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub setup: GlobalSetupConfig,
    pub protect: GlobalProtectConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalSetupConfig {
    pub shell_hook: bool,
    pub hook_scope: String,        // "project" or "global"
    pub shell_profile: String,     // path that was modified
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalProtectConfig {
    pub sandbox: bool,             // true = auto-detect, false = off
}
```

New functions:
- `load_global_config() -> GlobalConfig` — reads `~/.depsec/config.toml`, returns default if missing
- `save_global_config(config: &GlobalConfig) -> Result<()>` — writes to `~/.depsec/config.toml` with `0600` perms, creates `~/.depsec/` if needed
- `resolve_sandbox(cli_flag: Option<bool>, project: &Config, global: &GlobalConfig) -> bool` — implements the priority chain

**Files:**
- `src/config.rs:164-180` — add `load_global_config()` and `save_global_config()` alongside existing `load_config()`

### Phase 2: New Dependency + CLI Flags (`Cargo.toml`, `src/main.rs`)

**Cargo.toml:**
```toml
dialoguer = { version = "0.11", features = ["fuzzy-select"] }
```

**src/main.rs — Setup command changes (lines 141-160):**
```rust
Setup {
    /// Install pre-commit hook for secret detection
    #[arg(long)]
    hook: bool,
    /// Remove pre-commit hook
    #[arg(long)]
    unhook: bool,
    /// Initialize network baseline file
    #[arg(long)]
    baseline: bool,
    /// Print shell aliases for package manager monitoring
    #[arg(long)]
    shell: bool,
    /// Verify depsec's own integrity
    #[arg(long)]
    self_check: bool,
    /// Install all default protections (non-interactive)
    #[arg(long)]
    all: bool,
    /// Run non-interactively (for LLMs/CI)
    #[arg(long)]
    non_interactive: bool,
    /// Path to the project root
    #[arg(default_value = ".")]
    path: PathBuf,
},
```

**src/main.rs — Protect command changes (lines 101-120):**
```rust
Protect {
    #[arg(long)]
    json: bool,
    /// Force sandbox ON (override config)
    #[arg(long)]
    sandbox: bool,
    /// Force sandbox OFF (override config)
    #[arg(long)]
    no_sandbox: bool,
    #[arg(long)]
    learn: bool,
    #[arg(long)]
    strict: bool,
    #[arg(long)]
    preflight_only: bool,
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
},
```

### Phase 3: Setup Wizard (`src/commands/setup.rs`)

Complete rewrite. New flow:

```
pub fn run(opts: &SetupOpts) -> ExitCode
    ├── if any specific flag (--hook, --shell, etc.) → run_flagged(opts)  [backward compat]
    ├── if --all or --non-interactive or !is_tty() → run_defaults(opts)
    └── else → run_wizard(opts)
```

**`run_wizard()`:**
1. Load existing `GlobalConfig` for pre-selection
2. `dialoguer::MultiSelect` with 5 options (pre-selected from config)
3. If "Pre-commit hook" selected → `dialoguer::Select` for scope (project/global)
4. Print sandbox detection status
5. Execute each selected item with progress output
6. Save config, print summary

**`run_defaults()`:**
1. Install shell protection (detect shell, modify RC)
2. Install pre-commit hook (project-local if `.git/` exists)
3. Enable sandbox in config
4. Save config

**`run_flagged()`:**
1. Same as current behavior — each flag triggers its function
2. Also runs when `--all` combined with other flags

**Installation functions (called by all paths):**
- `install_shell_protection() -> Result<String>` — returns path modified
- `install_hook(scope: HookScope) -> Result<()>` — backs up existing, chains
- `enable_sandbox_default() -> Result<()>` — writes to global config
- `init_baseline(path) -> Result<()>` — existing function
- `run_self_check(path)` — existing function

**Files:**
- `src/commands/setup.rs` — full rewrite (~250 lines)

### Phase 4: Shell Profile Modification (`src/shellhook.rs`)

Add `install_to_profile()` alongside existing `generate_shell_hook()`:

```rust
pub fn install_to_profile() -> Result<InstallResult> {
    let shell = detect_shell();           // zsh, bash, fish, unknown
    let rc_path = rc_file_for(&shell);    // ~/.zshrc, ~/.bashrc, ~/.config/fish/config.fish
    let eval_line = eval_line_for(&shell); // eval "$(depsec setup --shell)" or | source

    // Idempotency: check if already present
    if rc_path.exists() {
        let content = std::fs::read_to_string(&rc_path)?;
        if content.contains("depsec setup --shell") {
            return Ok(InstallResult::AlreadyPresent(rc_path));
        }
        // Backup before modifying
        let backup = rc_path.with_extension("depsec-backup");
        std::fs::copy(&rc_path, &backup)?;
    }

    // Append (or create if doesn't exist)
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&rc_path)?;
    writeln!(file, "\n# depsec — supply chain protection")?;
    writeln!(file, "{eval_line}")?;

    Ok(InstallResult::Installed(rc_path))
}
```

**Shell detection:** use `$SHELL` env var, map to enum. Fall back to "unknown" with warning.

**Fish handling:** `depsec setup --shell | source` (not `eval`).

**XDG compliance for fish:** Check `$XDG_CONFIG_HOME` before defaulting to `~/.config/fish/`.

**Files:**
- `src/shellhook.rs` — add ~80 lines

### Phase 5: Hook Improvements (`src/commands/setup.rs`)

**Project-local hook install (updated):**
1. Check if `.git/hooks/pre-commit` exists
2. If exists and NOT a depsec hook (check for `# depsec pre-commit hook` marker), back up to `.pre-commit.bak`
3. Write new hook that runs depsec first, then chains to backup if it exists:

```bash
#!/bin/sh
# depsec pre-commit hook — blocks commits with hardcoded secrets
depsec scan --staged --checks secrets
DEPSEC_EXIT=$?
# Chain to original hook if it was backed up
if [ -f .git/hooks/pre-commit.bak ]; then
    .git/hooks/pre-commit.bak
    CHAIN_EXIT=$?
    [ $CHAIN_EXIT -ne 0 ] && exit $CHAIN_EXIT
fi
exit $DEPSEC_EXIT
```

**Global hook install:**
1. Check `git config --global core.hooksPath` — if set to non-depsec path, refuse with error
2. Write `~/.depsec/hooks/pre-commit` with depsec check + chain to `$GIT_DIR/hooks/pre-commit`
3. Run `git config --global core.hooksPath ~/.depsec/hooks`

**Global hook script:**
```bash
#!/bin/sh
# depsec global pre-commit hook
depsec scan --staged --checks secrets
DEPSEC_EXIT=$?
# Chain to per-project hook if it exists
if [ -f "$GIT_DIR/hooks/pre-commit" ]; then
    "$GIT_DIR/hooks/pre-commit"
    CHAIN_EXIT=$?
    [ $CHAIN_EXIT -ne 0 ] && exit $CHAIN_EXIT
fi
exit $DEPSEC_EXIT
```

**Unhook update:** Read `hook_scope` from global config to know whether to remove project or global hook.

**Files:**
- `src/commands/setup.rs` — hook functions within the rewrite

### Phase 6: Protect Command Config Integration (`src/commands/protect.rs`, `src/install_guard.rs`)

**`src/commands/protect.rs` changes:**
```rust
pub struct ProtectOpts {
    pub json: bool,
    pub sandbox: Option<bool>,  // was: bool — now tri-state
    pub learn: bool,
    pub strict: bool,
    pub preflight_only: bool,
}

pub fn run(command: &[String], opts: &ProtectOpts) -> ExitCode {
    let root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let config = config::load_config(&root);
    let global_config = config::load_global_config();

    // Resolve sandbox: CLI flag > project config > global config > off
    let use_sandbox = config::resolve_sandbox(
        opts.sandbox,
        &config,
        &global_config,
    );

    // ...pass use_sandbox to install_guard
}
```

**`src/install_guard.rs` line 70 changes:**
Replace the current sandbox detection:
```rust
// OLD:
let use_sandbox = sandbox_cli || config.mode == "sandbox" || config.sandbox != "none";

// NEW: sandbox decision already made by caller via resolve_sandbox()
let use_sandbox = sandbox_enabled;
```

**`src/main.rs` Protect dispatch changes:**
Convert the two bools (`--sandbox` / `--no-sandbox`) into `Option<bool>`:
```rust
Commands::Protect { sandbox, no_sandbox, .. } => {
    let sandbox_opt = if sandbox { Some(true) }
                      else if no_sandbox { Some(false) }
                      else { None };
    // ...
}
```

**Files:**
- `src/commands/protect.rs:1-68` — update ProtectOpts + run()
- `src/install_guard.rs:70-76` — simplify sandbox decision
- `src/main.rs:392-408` — convert bool pair to Option<bool>

### Phase 7: Documentation Updates

**README.md:**
- Replace the "Setup & Utilities" section with new "Get Protected" section
- Add the 2-minute setup flow prominently
- Update `depsec setup` help text

**SKILL.md:**
- Update Setup section with new wizard flow
- Add `depsec setup` (no flags) as the recommended approach

**Files:**
- `README.md:219-233` — rewrite setup section
- `SKILL.md:57-63` — update setup instructions

## Acceptance Criteria

### Functional

- [x] `depsec setup` (no flags, TTY) shows interactive checkbox wizard with 5 options
- [x] Pre-selected defaults: shell protection, pre-commit hook, sandbox
- [x] Hook scope sub-prompt appears when "Pre-commit hook" selected
- [x] Sandbox detection status printed during install
- [x] Config saved to `~/.depsec/config.toml` with 0600 permissions
- [x] Shell RC file modified with eval line (idempotent — no duplicates)
- [x] Shell RC file backed up before modification
- [x] Existing pre-commit hooks backed up and chained
- [x] Global hook via `core.hooksPath` works and chains to per-project hooks
- [x] `depsec setup --all` installs defaults non-interactively
- [x] No TTY (pipe/CI) installs defaults silently
- [x] `--non-interactive` flag forces non-interactive mode
- [x] `depsec setup --hook`, `--shell`, etc. still work (backward compat)
- [x] Re-running wizard pre-selects based on existing config
- [x] Ctrl+C during wizard prints "cancelled" and writes nothing

### Protect Integration

- [x] `depsec protect npm install foo` reads config and sandboxes if enabled
- [x] `--no-sandbox` flag overrides config to disable sandbox
- [x] `--sandbox` flag overrides config to enable sandbox
- [x] No config exists → behaves exactly as before (no sandbox)
- [x] Priority chain: CLI flag > project depsec.toml > global config > default off

### Edge Cases

- [x] No `.git/` directory → skip hook install with warning
- [x] RC file doesn't exist → create it
- [x] RC file is read-only → error with clear message
- [x] `core.hooksPath` already set to non-depsec path → refuse with error
- [x] No sandbox available on system → warn but proceed
- [x] Fish shell → uses `| source` syntax, respects `$XDG_CONFIG_HOME`
- [x] `$SHELL` not set → warn and skip shell protection

### Testing

- [x] Unit tests for `resolve_sandbox()` priority chain (all combinations)
- [x] Unit tests for `load_global_config()` / `save_global_config()` round-trip
- [x] Unit tests for shell detection and RC file path resolution
- [x] Unit tests for idempotency check (eval line already present)
- [x] Unit tests for hook backup detection (depsec marker vs third-party)
- [ ] Integration test: full wizard flow in tempdir with mock home
- [x] `cargo fmt && cargo clippy && cargo test` passes

## Implementation Order

1. **Phase 1** — Global config system (foundation, no visible changes)
2. **Phase 2** — Add dependency + CLI flags (compiles but no new behavior)
3. **Phase 3** — Setup wizard rewrite (the main feature)
4. **Phase 4** — Shell profile modification (called by wizard)
5. **Phase 5** — Hook improvements (called by wizard)
6. **Phase 6** — Protect command config integration
7. **Phase 7** — Docs update

Phases 1-2 have no dependencies. Phases 3-5 can be developed together. Phase 6 depends on Phase 1. Phase 7 is last.

## Files to Create/Modify

| File | Change | Phase |
|------|--------|-------|
| `Cargo.toml` | Add `dialoguer = "0.11"` | 2 |
| `src/config.rs` | Add `GlobalConfig`, `load_global_config()`, `save_global_config()`, `resolve_sandbox()` | 1 |
| `src/main.rs` | Add `--all`, `--non-interactive` to Setup; `--no-sandbox` to Protect; convert sandbox to `Option<bool>` | 2 |
| `src/commands/setup.rs` | Full rewrite: wizard + defaults + flagged paths | 3 |
| `src/shellhook.rs` | Add `install_to_profile()`, shell detection, RC file helpers | 4 |
| `src/commands/protect.rs` | Update `ProtectOpts.sandbox` to `Option<bool>`, load global config | 6 |
| `src/install_guard.rs` | Simplify sandbox decision (caller resolves) | 6 |
| `README.md` | New "Get Protected" section | 7 |
| `SKILL.md` | Updated setup instructions | 7 |

## References

- Design spec: `docs/superpowers/specs/2026-04-01-interactive-setup-wizard-design.md`
- `dialoguer` crate: https://docs.rs/dialoguer/0.11
- Current config system: `src/config.rs:164-180`
- Current setup: `src/commands/setup.rs:1-109`
- Current protect: `src/commands/protect.rs:1-68`
- Install guard sandbox logic: `src/install_guard.rs:69-76`
- Shell hook generation: `src/shellhook.rs:1-67`
- Sandbox detection: `src/sandbox.rs:36-73`
- CLI definitions: `src/main.rs:141-160` (Setup), `src/main.rs:101-120` (Protect)
