# Agent Skill Scanner

A zero-dependency static security scanner for auditing `SKILL.md`, `skill.json`, MCP manifests, and related Markdown / JSON / YAML files **before** you install or run them.

**Dual engine, single rule source**: the Node engine (`src/scanner.js` — human review, CI, Web UI) and the Python engine (`src/scanner.py` — zero-dependency, agent-friendly) share one rule set in `rules/scanner-rules.json`. Both engines produce byte-identical output (verified across 15 skill directories).

## What it detects

- `.env`, SSH key, and broad environment-variable reads
- External network access and wildcard egress
- Shell / subprocess execution
- Persistent memory modification
- Excessive permissions (elevation, broad filesystem, destructive commands)
- Suspicious URLs, download commands, and pipe-to-interpreter patterns

Output is a `LOW / MEDIUM / HIGH / CRITICAL` risk level with a 0-100 score. Every hit includes the **why** (rationale) and a **remediation** suggestion; secrets in evidence are automatically redacted.

## Web UI

Requires Node.js 20+:

```bash
npm start
```

Open `http://127.0.0.1:4173`. Scanning happens entirely in your browser — the local server only serves static files and never receives or stores uploads.

## CLI

Node engine:

```bash
npm run scan -- ./SKILL.md
npm run scan -- ./my-skill --json
npm run scan -- ./my-skill --sarif
npm run scan -- ./my-skill --min-risk HIGH
npm run scan -- ./my-skill --disable-rule NETWORK_ACCESS --disable-rule SUSPICIOUS_URL
```

Python engine (no Node required):

```bash
python src/scanner.py ./SKILL.md
python src/scanner.py ./my-skill --json
python src/scanner.py ./my-skill --sarif
python src/scanner.py ./my-skill --disable-rule SECRET_BROAD_ENV
```

Exit codes are CI-friendly:

| Code | Meaning |
| --- | --- |
| `0` | LOW |
| `1` | MEDIUM |
| `2` | HIGH |
| `3` | CRITICAL |
| `64` | Input / runtime error |

## SARIF support

`--sarif` emits [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), compatible with GitHub Code Scanning and other SARIF consumers — e.g. upload with `actions/upload-sarif`.

## Tests

```bash
npm test          # Node engine (11 unit tests)
python test/test_scanner.py  # Python engine (11 unit tests, mirrored)
node --test test/corpus.test.js   # regression corpus (4 fixtures)
python test/test_corpus.py        # same corpus, Python side
npm run test:all  # unit tests both engines
```

The regression corpus (`examples/corpus/`) pins expected rule hits per fixture, guarding against both missed detections and false-positive regressions.

## Editing rules

Rules live in `rules/scanner-rules.json` (the single source of truth). Each rule has `id`, `category`, `severity`, `title`, `why`, `remediation`, `case_insensitive`, and `patterns`.

After editing, **regenerate the browser bundle and run both test suites**:

```bash
npm run build:rules   # regenerate rules/rules.js from the JSON
npm run test:all      # Node + Python unit tests
node --test test/corpus.test.js && python test/test_corpus.py  # corpus
```

The Node/Python engines read the JSON directly; the web UI (browsers have no filesystem) reads the generated `rules/rules.js`, kept in sync by `scripts/sync-rules.mjs`.

## Features added in 2026-08

- **Multi-line reconstruction** — command continuations (`curl ... |` + `bash` on the next line, backslash continuations, `&&` at EOL) are joined into logical lines before matching, so split-command obfuscation is detected.
- **YAML frontmatter awareness** — permission/tool declarations written as multi-line YAML lists (`permissions:\n  - network: "*"`) are folded with their parent key so context-sensitive rules can match them.
- **Regression corpus** — edge-case fixtures with pinned expectations (multiline pipes, frontmatter wildcards, backtick URL tables, SSH+env) in `examples/corpus/`, tested by both engines.
- **SARIF 2.1.0 output** — GitHub Code Scanning compatible.
- **`--disable-rule`** — turn off specific rules from the CLI (repeatable, comma-separated).
- **pre-commit hooks** — `.pre-commit-config.yaml` scans staged skill files and verifies the rules bundle stays in sync.

## Prior fixes

- `zx` false positive: `zx\b` matched URL path segments (e.g. `/zx/hd/sxjm/`); now `(?:^|[^/\w])zx\b` only flags real zx shell usage.
- `"scope": "all_units"` business data no longer flagged as a permission grant (values must exactly match `*` / `all` / `any` / `0.0.0.0/0`).
- Backtick URLs and compact JSON `command` keys covered by regression tests.

## Risk model

Each rule scores once, keeping at most three evidence lines, so repeated text cannot inflate the score. A CRITICAL rule raises the overall level to CRITICAL immediately; other signals accumulate. Multi-file scans take the highest-risk file and aggregate all findings.

This is heuristic static analysis, not a sandbox. Obfuscated code, indirect calls, and runtime behavior still warrant manual review.

## License

[MIT](LICENSE) © liuhaolin07
