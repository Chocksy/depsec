---
title: "feat: Reachability Analysis and Vibe-Coder-Friendly Output"
type: feat
date: 2026-03-30
brainstorm: docs/brainstorms/2026-03-30-vibe-coder-output-brainstorm.md
---

# Reachability Analysis and Vibe-Coder-Friendly Output

## Overview

Add import reachability analysis that parses the project's own source code to determine which flagged packages are actually used at runtime vs build-only. Restructure the scan output into two clear sections: "Action Required" (runtime findings) and "Build Tools" (build-only, collapsed). Adjust scoring so build-only findings don't destroy the grade.

**Impact on POS project:** 139 pattern findings → **2 runtime findings that matter** + 21 build-only (collapsed). Grade improves from F to realistic.

## Problem Statement

A vibe coder runs `depsec scan .` and sees Grade F with 139 findings. Their app works fine in production. The tool cries wolf because:
- Build tools (esbuild, playwright, rollup) are flagged for exec() — they're supposed to do this
- All findings look equally alarming — no distinction between "your app does this" and "a build tool does this"
- The grade is meaningless — F for a healthy app = ignored tool

## Proposed Solution

### Phase 1: Import Scanner

**New file:** `src/reachability.rs`

Parse the project's own source files to build a set of directly imported packages:

```rust
pub fn scan_app_imports(root: &Path) -> HashSet<String> {
    // 1. Find source dirs: src/, app/, lib/, packages/
    // 2. Walk for .js, .ts, .svelte, .vue, .jsx, .tsx files
    // 3. For each file, extract import/require package names
    // 4. Return deduplicated set of package names
}
```

**Import extraction using tree-sitter** (JS/TS — already have the grammars):
- `import X from 'package'`
- `import { X } from 'package'`
- `const X = require('package')`
- `import('package')` (dynamic imports)

**Svelte files:** Extract `<script>` block content, then parse as JS/TS. Simple regex to find `<script>` tags — no need for tree-sitter-svelte grammar.

**Also check `package.json`** `dependencies` vs `devDependencies` as secondary signal.

### Phase 2: Tag Findings

In `PatternsCheck::run()`, after collecting findings:

```rust
let app_imports = reachability::scan_app_imports(ctx.root);

for finding in &mut findings {
    if let Some(pkg) = &finding.package {
        finding.reachable = app_imports.contains(pkg);
    }
}
```

Add `reachable: Option<bool>` to `Finding` struct:
- `Some(true)` = runtime (your app imports this)
- `Some(false)` = build-only (not imported)
- `None` = unknown (non-pattern findings, or no source to scan)

### Phase 3: Split Output

Restructure `render_human()` pattern section:

```
🔴 ACTION REQUIRED (2 findings in packages your app uses)

  @electric-sql/pglite — Shell Execution (P001)
    Your app imports this at: packages/shared-db/src/pglite.ts
    → This package runs shell commands at runtime in your app.

  @supabase/supabase-js — Dynamic Code (P008)
    Your app imports this at: src/lib/supabase.ts
    → Expected for database clients. Verify inputs are sanitized.

⚪ BUILD TOOLS (21 findings — not imported by your app)
  esbuild, detect-libc, playwright, rollup, jake, cross-spawn, ...
  (use --verbose to see details)
```

Non-pattern sections (Deps, Secrets, Hygiene, Workflows) render as today.

### Phase 4: Weighted Scoring

Adjust `compute_category_score()` to weight by reachability:

```rust
let multiplier = if finding.reachable == Some(true) {
    3.0  // Runtime: full impact
} else if finding.reachable == Some(false) {
    0.3  // Build-only: reduced impact
} else {
    1.0  // Unknown: standard impact
};
```

**Expected POS grade:** F (0.6) → C-B range (runtime issues + dep CVEs still count, but build-tool noise doesn't tank the score).

### Phase 5: Import Location Display

For runtime findings, show WHERE in the app's code the package is imported:

```
@electric-sql/pglite — Shell Execution (P001)
  Your app imports this at:
    packages/shared-db/src/pglite.ts:8
```

Store import locations in a `HashMap<String, Vec<(String, usize)>>` mapping package name to (file, line) pairs.

### Phase 6: Deps Section Cleanup

Collapse the 68 CVE lines into a summary:

```
[Deps]
  ⚠ 68 known vulnerabilities in 15 packages
    Critical: 0  High: 0  Medium: 68
    Top affected: tar (6), svelte (4), devalue (6), @sveltejs/kit (5)
    → Run: npm audit fix
    → Use --verbose for full advisory list
```

## Acceptance Criteria

- [ ] `scan_app_imports()` parses JS/TS/Svelte imports from project source
- [ ] Each pattern finding tagged as `runtime` or `build-only`
- [ ] Human output splits into "Action Required" and "Build Tools" sections
- [ ] Runtime findings show import locations from app source
- [ ] Scoring weights runtime findings higher than build-only
- [ ] POS project grade improves from F to C+ or better
- [ ] Deps section collapsed into summary with counts
- [ ] `--verbose` shows full details (all findings, all CVEs)
- [ ] JSON output includes `reachable` field on findings
- [ ] All existing tests pass + new tests for reachability

## Technical Considerations

- **Performance:** Import scanning adds ~1s (walking source files + tree-sitter parse). Acceptable.
- **Accuracy:** Direct imports only (not transitive). A package imported by your code that transitively depends on a flagged package is NOT considered runtime. This is a conservative simplification — can be improved later.
- **Svelte parsing:** Extract `<script>` blocks with regex, parse content as JS/TS. No new grammar needed.
- **Monorepo:** Scan all workspace roots found in `package.json` `workspaces` field.

## Files to Create/Modify

| File | Change |
|------|--------|
| `src/reachability.rs` | **NEW** — import scanner |
| `src/checks/mod.rs` | Add `reachable: Option<bool>` to Finding |
| `src/checks/patterns.rs` | Tag findings with reachability after scan |
| `src/output.rs` | Split output into runtime/build-only sections |
| `src/scoring.rs` | Weight scores by reachability |
| `src/main.rs` | Register reachability module |

## References

- Brainstorm: `docs/brainstorms/2026-03-30-vibe-coder-output-brainstorm.md`
- POS project analysis: 2 runtime out of 23 high-confidence findings
- Socket.dev's reachability feature (acquired Coana for this)
- Snyk's reachability analysis (proprietary)
- Current import scanner patterns: `src/ast/javascript.rs` (already parses imports for dangerous module detection)
