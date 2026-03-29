# Brainstorm: Vibe Coder Output — Reachability Analysis & Smart Presentation

**Date:** 2026-03-30
**Status:** Draft
**Goal:** Make depsec output understandable and actionable for developers who don't know what `child_process` is.

---

## The Problem

Running `depsec scan .` on the POS project shows 139 pattern findings and grade F. A vibe coder sees:
- Wall of technical jargon (GHSA codes, DEPSEC-P001, child_process.exec)
- Grade F when the app is fine in production
- No way to tell what actually matters vs build tool noise
- Equal alarm for esbuild (build tool, expected) and a runtime library (suspicious)

**Result:** The tool gets ignored. A tool that's ignored provides zero security value.

---

## Key Insight: Reachability Changes Everything

Cross-referencing the POS project's **own source code imports** with flagged packages:

| | Count | Examples |
|---|---|---|
| 🔴 **Runtime** (your app imports these) | **2** | @electric-sql/pglite, @supabase/supabase-js |
| ⚪ **Build-only** (not in your app's code) | **21** | esbuild, detect-libc, playwright, rollup |

**21 out of 23 high-confidence findings are build tools that never reach production.** Only 2 need attention.

This is deterministic — no LLM needed. We already have tree-sitter. We just need to parse the app's own source files for import statements.

---

## What We're Building

### 1. Import Reachability Analysis

Parse the project's own source files (not node_modules) to build a set of **directly imported packages**. Tag each finding as `runtime` or `build-only`.

**How it works:**
1. Scan `src/`, `app/`, `lib/`, `packages/` (configurable) for `.js`, `.ts`, `.svelte`, `.vue`, `.jsx`, `.tsx` files
2. Extract `import ... from 'package'` and `require('package')` statements using tree-sitter
3. Build a set of package names the app directly imports
4. For each pattern finding, check if `finding.package` is in the import set
5. Tag as `runtime` (in import set) or `build-only` (not imported)

**Also check:**
- `package.json` `dependencies` vs `devDependencies` as a secondary signal
- A package in `devDependencies` AND not imported = very likely build-only

### 2. Split Output by Risk Level

**New output structure:**

```
depsec v0.4.0 — Supply Chain Security Scanner

Project: pos-app
Grade: B (7.5/10)          ← Score only counts runtime findings

🔴 ACTION REQUIRED (2 findings in packages your app uses)

  @electric-sql/pglite — Shell Execution (P001, confidence: high)
    Your app imports this package at: packages/shared-db/src/pglite.ts
    Found: child_process.exec() with variable arguments
    → This package runs shell commands at runtime in your app.
      Check if command inputs come from users.

  @supabase/supabase-js — Dynamic Code (P008, confidence: high)
    Your app imports this package at: src/lib/supabase.ts
    Found: new Function() with variable input
    → Supabase client constructs queries dynamically.
      This is expected behavior for a database client.

⚪ BUILD TOOLS (21 findings in packages not imported by your app)

  These packages are used during development/build but don't run
  in your deployed app. Lower risk — they can only affect your
  machine or CI, not your users.

  esbuild, detect-libc, playwright, rollup, jake, cross-spawn,
  update-browserslist-db, ejs, elementtree, foreground-child, ...
  (use --verbose to see details)

[Deps] 68 known vulnerabilities in dependencies
  → Run: npm audit fix (or see --verbose for details)

[Secrets] 3 leaked tokens found
  → Remove JWT tokens from committed files

[Hygiene] ✓ Good (lockfile committed, 2 minor suggestions)
```

### 3. Scoring Changes

**Current:** All findings count equally → Grade F
**Proposed:** Weight by reachability:
- Runtime findings: full weight (3x multiplier)
- Build-only findings: reduced weight (0.5x multiplier)
- Findings in packages not even in your dependency tree: 0 weight

This makes the grade meaningful. A project with only build-tool findings and no runtime issues should score B+ or A, not F.

### 4. "Where You Use It" Context

For runtime findings, show WHERE in the app's code the package is imported:

```
@electric-sql/pglite — Shell Execution
  Your app imports this at:
    packages/shared-db/src/pglite.ts:8
    packages/shared-db/src/sync.ts:3
```

This tells the vibe coder: "the problem is relevant to YOUR code at THESE files."

---

## Why This Approach

1. **Deterministic** — No LLM cost. tree-sitter parses imports in milliseconds.
2. **Actionable** — "2 things to fix" beats "139 things to review"
3. **Honest** — Build tools ARE flagged, just correctly categorized as lower risk
4. **The grade becomes meaningful** — B with 2 runtime issues is useful. F for build tools is not.

---

## Key Decisions

1. **Reachability via import analysis** — parse app source with tree-sitter, not just devDependencies check (more accurate: some devDeps are imported in app code, some deps are build-only)
2. **Split output into runtime/build-only sections** — clear visual separation
3. **Score weighted by reachability** — runtime = full weight, build-only = reduced
4. **Show import locations** for runtime findings — "Your app uses this at file:line"
5. **Collapse build-only findings** — show package names only, expandable with --verbose
6. **Collapse dep CVEs** — show count + "run npm audit fix" instead of 68 individual lines
7. **No LLM needed** — this is all deterministic, fast, free

---

## Open Questions

1. **How to handle transitive runtime deps?** If your app imports `@supabase/supabase-js` which depends on `node-fetch`, is `node-fetch` runtime? (Probably yes — transitive analysis is harder but valuable)
2. **Svelte/Vue file parsing?** tree-sitter-svelte exists but adds another grammar. Could use regex fallback for `<script>` blocks.
3. **Monorepo support?** POS has `apps/`, `packages/` — need to scan all workspace roots for imports.
4. **Should devDependencies in runtime code be a finding itself?** If you import a devDependency in production code, that's a bug.
