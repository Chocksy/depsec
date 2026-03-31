# LLM/Agent Integration & Website Accuracy

**Date:** 2026-03-31
**Status:** Decided

## What We're Building

Three deliverables to make depsec "vibe-coder friendly":

1. **Install script redirect** — `_redirects` file in depsec.dev so `curl depsec.dev/install | sh` works
2. **SKILL.md** — AgentSkills-spec file teaching LLMs to scan, interpret, fix, and setup
3. **AGENTS.md** — Universal agent instructions (read by Codex, Cursor, Windsurf, Gemini CLI)

## Why This Approach

- **No MCP server** — we have a CLI, agents can just shell out to it
- **SKILL.md is the standard** — supported by 30+ tools (Claude Code, Codex, Cursor, Gemini CLI, Goose, Amp, Roo Code, VS Code Copilot, etc.)
- **AGENTS.md is universal** — Codex reads it automatically, Cursor respects it, Windsurf uses it
- **Like desloppify** — they have a "copy this to your agent" model. We do the same but simpler (depsec is a CLI, not a Python package)

## Key Decisions

### Install Script
- **Decision:** Cloudflare Pages `_redirects` file
- **Why:** Single source of truth (install.sh stays in depsec repo), no CI copy step, no duplicate files
- **Implementation:** `depsec.dev/public/_redirects` with `/install → raw.githubusercontent.com/chocksy/depsec/main/install.sh 302`

### SKILL.md Design
- **Decision:** Super minimal, pasteable in README
- **Scope:** scan → interpret → fix → setup (hooks, aliases)
- **Pattern:** Frontmatter `name` + `description`, then concise markdown workflow
- **Key constraint:** Small enough to include as a README section "Add this to your AI coding tool"
- **Prerequisite check:** `command -v depsec` with install instructions if missing

### AGENTS.md Design
- **Decision:** Repo root, minimal markdown
- **Scope:** Same as SKILL.md core — when to run depsec, how to interpret output
- **Format:** No frontmatter, just markdown (AGENTS.md doesn't use AgentSkills format)

### What NOT to build
- No MCP server (CLI is sufficient)
- No per-tool overlays (CLAUDE.md, CODEX.md, etc.) — SKILL.md + AGENTS.md cover everything
- No `depsec update-skill` CLI command — just copy-paste or point to the file

## Website Accuracy Issues Found

These are for the user to fix in depsec.dev (separate from the depsec repo work):

| Issue | Current | Correct |
|-------|---------|---------|
| Test count | 317 | 352 |
| Version | v0.9.0 | v0.10.0 |
| Quick Start | `install-guard`, `hook install` | `protect`, `setup --hook` |
| Pattern rules | "17 rules" | 15 in array (P007/P009/P012/P016 missing) |
| Ecosystems | "8 ecosystems" | 9 lockfile formats / 5 ecosystems |
| Sandbox | `--sandbox` flag shown | Flag silently ignored in CLI |
| Shell hooks | Generate aliases | Use deprecated `install-guard` name |

## Open Questions

- Should the README section be "For AI Agents" or "For Vibe Coders" or just "Agent Integration"?
- Should we add a `depsec --llm-instructions` command that prints the SKILL.md content for easy piping?

## Research References

- **AgentSkills spec:** https://agentskills.io — supported by 30+ tools
- **Desloppify pattern:** `desloppify update-skill claude` installs SKILL.md per-tool. We skip this complexity.
- **Snyk approach:** Full 7-phase scan→fix→PR workflow skill at snyk/studio-recipes
- **Format:** YAML frontmatter (`name`, `description`) + markdown instructions
