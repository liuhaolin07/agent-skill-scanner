# Changelog

All notable changes to agent-skill-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-08-23

### Fixed
- Multi-root scans (`skill-scan skill-a skill-b`) no longer produce colliding report names:
  file names in JSON/SARIF output are now relative to the deepest common ancestor of all
  inputs, so `skill-a/SKILL.md` and `skill-b/SKILL.md` stay distinguishable
  (Node + Python engines, mirrored).
- `package.json` version synced to the release (`0.2.1`); removed `private: true` so the
  package metadata no longer blocks future npm publishing.

### Added
- CLI-level regression tests for both engines (`test/cli.test.js`, `test/test_cli.py`):
  multi-root JSON names, multi-root SARIF artifact URIs, single-directory and
  single-file naming.
- Rule file structural validation: `scripts/check-schema.mjs` + `rules/scanner-rules.schema.json`
  (run via `npm run check:rules`, enforced in CI).
- `docs/rule-authoring.md` — rule authoring guide.
- `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, Dependabot config, CodeQL workflow.

### Changed
- CI now runs on Ubuntu, Windows and macOS with Node 20/22 and Python 3.10/3.12;
  workflow gained `permissions: contents: read` and pinned action SHAs.

## [0.2.0] - 2026-08-22

### Added
- `--fail-on LEVEL` risk gate for CI exits.
- Evidence redaction (secrets shown as `[REDACTED]`).
- Per-file / per-scan byte and file-count limits.
- Rule split into dedicated IDs (SECRET_ENV_FILE / SECRET_SSH_KEY / SECRET_BROAD_ENV,
  DOWNLOAD_EXECUTE / DOWNLOAD_COMMAND / SUSPICIOUS_URL, URL_REFERENCE, PROCESS_SPAWN,
  UNPINNED_PACKAGE) with superseded-rule handling.
- pre-commit integration (`.pre-commit-config.yaml`).

### Fixed
- Pipe-to-shell / `zx` false positives on URL path segments.
- Markdown table pipes no longer flagged.
- 32-bit hex false positives on URL path segments.
- `scope`/`permission` business values (`all_units` etc.) no longer treated as wildcard grants.
- Browser-incompatible `Buffer.byteLength()` replaced in the web UI size check.

## [0.1.0] - 2026-08-20

### Added
- Dual-engine scanner: Node (`src/scanner.js`, `src/cli.js`) and Python (`src/scanner.py`)
  sharing a single rule source (`rules/scanner-rules.json`).
- 16 detection rules across 6 categories (secret access, shell execution, downloads,
  network access, memory modification, excessive permissions).
- LOW / MEDIUM / HIGH / CRITICAL risk model with 0–100 scoring.
- JSON and SARIF 2.1.0 output; `--disable-rule`.
- Multi-line command detection, YAML frontmatter awareness, zero-width character handling.
- MIT License.
