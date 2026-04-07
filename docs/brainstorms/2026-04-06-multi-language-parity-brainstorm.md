---
date: 2026-04-06
topic: multi-language-parity
---

# Sprint 7: Multi-Language Parity

## The Problem

JavaScript has ~9 AST detection features, full capability analysis (C1-C9 + 8 COMBO rules),
const propagation, and 29+ hornets nest tests. Python, Ruby, and Rust are far behind:

| Feature | JS | Python | Ruby | Rust |
|---------|:--:|:------:|:----:|:----:|
| AST enabled in scanner | Yes | Yes | Yes | **NO** (dead code) |
| Capability model | 9 caps + 8 combos | 0 | 0 | 0 |
| Network detection | AST+cap | regex only | regex only | regex only |
| Env var detection | P011+C5 | partial | no | no |
| Hornets nest tests | 29+ | 3-4 | 1 | 0 |

## Critical Bugs

1. **Rust AST gate is `_ => false`** — P040-P043 never execute during scanning
2. **Capabilities check hardcodes `node_modules`** — Python/Ruby/Rust deps never analyzed

## Implementation Plan

### Phase 1: Fix Rust AST Gate (5 min)

In `src/checks/patterns.rs` line 379, the `needs_ast` match has `_ => false`.
Add `Some(Lang::Rust)` arm with Rust-specific keyword triggers.

```rust
Some(crate::ast::Lang::Rust) => {
    content.contains("Command")
        || content.contains("unsafe")
        || content.contains("extern")
        || content.contains("include_bytes")
        || content.contains("include_str")
}
```

### Phase 2: Multi-Language Capability Model

Generalize `capabilities.rs` to scan Python, Ruby, and Rust deps alongside JS.

**Python capabilities:**
- Network: `requests`, `urllib`, `httpx`, `aiohttp`, `socket`, `http.client`
- FS read: `open(`, `pathlib`, `os.path`, `shutil`
- FS write: `open(.*w`, `shutil.copy`, `os.rename`
- Shell exec: `subprocess`, `os.system`, `os.popen`
- Env access: `os.environ`, `os.getenv`
- Dynamic load: `__import__`, `importlib`
- Install hook: `setup.py` with `cmdclass`
- Import detection: `import X` / `from X import Y`

**Ruby capabilities:**
- Network: `net/http`, `httparty`, `faraday`, `rest-client`, `typhoeus`, `open-uri`
- FS read: `File.read`, `File.open`, `IO.read`, `Pathname`
- FS write: `File.write`, `FileUtils.cp`, `FileUtils.mv`
- Shell exec: `system`, `exec`, `` ` ``, `Open3`, `IO.popen`
- Env access: `ENV[`, `ENV.fetch`
- Dynamic load: `require(var)`, `Kernel.load`
- Install hook: gemspec `extensions` / `Rakefile` with native ext
- Import detection: `require 'X'` / `require_relative`

**Rust capabilities:**
- Network: `reqwest`, `hyper`, `ureq`, `surf`, `std::net`
- FS read: `std::fs::read`, `File::open`, `std::io::Read`
- FS write: `std::fs::write`, `File::create`, `std::io::Write`
- Shell exec: `Command::new`, `std::process`
- Env access: `std::env`, `env::var`, `env::vars`
- FFI: `extern`, `libc`, `bindgen`
- Dynamic load: `libloading`, `dlopen`
- Import detection: `use X` / `extern crate`

### Phase 3: Generalize Capability Scanner

The current `scan_package()` hardcodes JS file extensions and `require()/from` import patterns.

**Approach:** Add language-aware capability detection functions:
- `detect_capabilities_python(content, caps)` — matches `import X` patterns
- `detect_capabilities_ruby(content, caps)` — matches `require 'X'` patterns
- `detect_capabilities_rust(content, caps)` — matches `use X` patterns
- Generalize `scan_package()` to walk all source files, dispatch by extension

**Generalize directory scanning:**
Instead of hardcoding `node_modules`, scan ALL dependency directories:
- `node_modules/` (JS/TS)
- `.venv/` or `venv/` (Python)
- `vendor/bundle/` (Ruby)
- For Rust: skip (crates not local), but scan project src/ for capability patterns

### Phase 4: Hornets Nest Multi-Language Tests

Add adversarial test packages for each language:

**Python evasion tests:**
- E-PY01: `import subprocess as sp; sp.Popen(cmd, shell=True)` (alias)
- E-PY02: `__import__('sub'+'process').call(cmd)` (string concat dynamic import)
- E-PY03: `exec(base64.b64decode(payload))` (encoded execution)
- E-PY04: Multi-file scatter: `utils.py` has `requests.post`, `main.py` has `os.environ`

**Ruby evasion tests:**
- E-RB01: `method(:system).call(cmd)` (method object dispatch)
- E-RB02: `` `#{cmd}` `` (interpolated backtick)
- E-RB03: `Kernel.send(:system, cmd)` (dynamic dispatch to shell)
- E-RB04: `open("|#{cmd}")` with interpolation

**Rust evasion tests:**
- E-RS01: `Command::new("sh").arg("-c").arg(cmd)` (basic)
- E-RS02: `unsafe { libc::system(ptr) }` (FFI shell exec)
- E-RS03: `std::net::TcpStream::connect` + `std::fs::read` (exfil combo)

### Files to Modify

- `src/checks/patterns.rs` — Add `Some(Lang::Rust)` to `needs_ast` gate
- `src/checks/capabilities.rs` — Generalize to multi-language
- `tests/hornets_nest/evasion_tests.rs` — Add Python/Ruby/Rust test vectors
- `tests/hornets_nest/scan_tests.rs` — Add multi-language scan tests

### Phase 5: Install Hook Detection

**Python:** Detect `setup.py` with `cmdclass` overrides (custom install commands)
**Ruby:** Detect gemspec `extensions` array (native extension compilation hooks)
**Rust:** Detect `build.rs` scripts (build-time code execution)

These are the equivalents of npm's `preinstall`/`postinstall` scripts.

## Key Design Decisions

- **Reuse existing `PackageCapabilities` struct** — same 9 capability flags work for all languages
- **Language-specific module lists** — separate constants per language
- **Same combination rules apply** — credential_read + network = exfil, regardless of language
- **Credential paths are language-neutral** — `.ssh`, `.aws`, `.env` are the same everywhere
- **Don't over-detect** — `subprocess` in Python is normal for build tools, same as `child_process` in JS. The dangerous part is the _combination_, not individual capabilities.

## Execution Status: COMPLETE (2026-04-06)

All phases implemented in a single session:
- [x] Phase 1: Fixed Rust AST gate + added Ruby `require(` to needs_ast
- [x] Phase 2: Multi-language capability model (Python/Ruby/Rust module lists)
- [x] Phase 3: Generalized capability scanner (scans .venv, vendor/bundle, not just node_modules)
- [x] Phase 4: 12 new hornets nest scan tests (4 Python + 4 Ruby + 4 Rust)
- [x] Phase 5: Install hook detection (setup.py cmdclass, build.rs, gemspec extensions)
- AST suggestion text for all P020-P043 rules
- 30+ new capability unit tests
- 497 tests total, 0 warnings, 0 clippy issues

### Updated Parity Table

| Feature | JS | Python | Ruby | Rust |
|---------|:--:|:------:|:----:|:----:|
| AST enabled in scanner | Yes | Yes | Yes | **Yes** (fixed) |
| Capability model | 9 caps + 8 combos | 9 caps + 8 combos | 9 caps + 8 combos | 9 caps + 8 combos |
| Network detection | AST + cap | cap (10 modules) | cap (9 modules) | cap (7 modules) |
| Env var detection | P011 + C5 | cap (os.environ, os.getenv) | cap (ENV[], ENV.fetch) | cap (std::env, env::var) |
| Install hook detection | package.json scripts | setup.py cmdclass | gemspec extensions | build.rs |
| Hornets nest tests | 22 | 6 | 5 | 4 |
