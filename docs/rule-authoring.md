# Rule Authoring Guide

Rules live in **`rules/scanner-rules.json`** — the single source of truth consumed by both the
Node engine (`src/scanner.js`) and the Python engine (`src/scanner.py`). Editing rules means
editing this file and nothing else; `rules/rules.js` is generated and must not be hand-edited.

## Rule structure

```json
{
  "id": "SHELL_EXECUTION",
  "category": "shell_execution",
  "severity": "high",
  "title": "Executes shell commands",
  "why": "Shell commands can run arbitrary code on the host.",
  "remediation": "Use a sandboxed runner or request explicit user approval.",
  "case_insensitive": true,
  "patterns": ["regex-string", "..."]
}
```

| Field | Semantics |
|---|---|
| `id` | `^[A-Z][A-Z0-9_]*$`, unique across the file. Used in reports, SARIF, `--disable-rule`. |
| `category` | One of `secret_access`, `shell_execution`, `suspicious_download`, `network_access`, `memory_modification`, `excessive_permissions`. |
| `severity` | `info` / `low` / `medium` / `high` / `critical`. Scores: info 0, low 4, medium 12, high 30, critical 60. |
| `title` | Short human-readable name (shown in reports). |
| `why` / `remediation` | Shown per finding; keep them concrete and actionable. |
| `case_insensitive` | If `true`, patterns are compiled with the case-insensitive flag. |
| `patterns` | ECMAScript regex strings (Python compiles the same strings). At least one. |

## How detection works

- A file matches a rule when **any** pattern matches. Each rule is scored **once per file**
  (deduplicated), with at most 3 evidence excerpts retained — repeated text cannot inflate a score.
- Evidence excerpts are redacted: anything that looks like a secret value is replaced with
  `[REDACTED]` in reports.
- A `critical` rule immediately lifts the overall risk to CRITICAL. Otherwise scores accumulate
  (0–100) and the highest-risk file decides the scan result.

## Writing patterns that don't false-positive

These are the hard-won lessons from the v0.2 accuracy rounds — read them before adding a rule:

1. **URL path segments are not shell.** `(?:^|[^/\w])zx\b` matches the `zx` tool but not the
   `/zx/` path segment in a URL. Always anchor with word boundaries or leading-context groups.
2. **Markdown structure is not evidence.** Table pipes `|` and inline backtick URLs must not
   match. Prefer context-sensitive patterns over bare tokens.
3. **32-bit hex is not a secret.** Exclude URL path segments before flagging hex tokens
   (article IDs on doc sites look like hashes).
4. **Business values are not permissions.** `"scope": "all_units"` is a data field, not a
   wildcard grant. Only exact wildcard values (`*`, `all`, `any`, `0.0.0.0/0`, …) should match.
5. **Superseded rules.** When a stricter rule covers a looser one (e.g. `DOWNLOAD_EXECUTE`
   supersedes `DOWNLOAD_COMMAND`), keep the looser rule visible but it no longer scores —
   declare this in the engine with the superseded-rule mechanism and mirror it in the corpus.
6. **Multi-line YAML.** `permissions:\n  - network: "*"` folds into `parent: value` for a
   second pass, so context-sensitive rules can hit folded lists.
7. **Zero-width characters.** Strip/ignore `\u200b`-family characters before matching so
   obfuscated patterns still hit.

## Workflow

```bash
# 1. Edit rules/scanner-rules.json
# 2. Validate structure (also runs in CI)
npm run check:rules
# 3. Regenerate the browser bundle and verify it is in sync (also runs in CI)
npm run build:rules
# 4. Test both engines
npm run test:all
```

## Adding a corpus fixture

Detection changes must be pinned by regression fixtures so "fixing one false positive does not
introduce two misses":

1. Create `examples/corpus/<name>/SKILL.md` with the exact scenario (one per concern).
2. Register it in `test/corpus.test.js` **and** `test/test_corpus.py` with the *exact* expected
   rule ids and the expected overall risk.
3. Both engines must agree — the CI cross-engine comparison is the final gate.
