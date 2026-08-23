# Contributing

Thanks for helping improve agent-skill-scanner! This project is small on purpose — a
zero-dependency security scanner with two engines sharing one rule source. Please keep that
spirit: no new runtime dependencies without a strong reason.

## Development setup

```bash
git clone https://github.com/liuhaolin07/agent-skill-scanner.git
cd agent-skill-scanner
# No npm install needed — the Node engine and web UI have zero runtime dependencies.
# Python engine uses the standard library only (3.10+).
```

## Changing rules (the important workflow)

**The single source of truth is `rules/scanner-rules.json`.** Do not edit `rules/rules.js`
by hand — it is generated.

1. Edit `rules/scanner-rules.json` (see `docs/rule-authoring.md` for field semantics).
2. Validate: `npm run check:rules`.
3. Regenerate the browser bundle: `npm run build:rules` (CI also verifies it is in sync).
4. Run the full suite on **both engines**:
   ```bash
   npm run test:all    # Node --test + Python unittest (scanner, corpus, CLI)
   ```
5. If you added or changed detection behavior, add a corpus fixture under
   `examples/corpus/<name>/SKILL.md` and register it in both `test/corpus.test.js` and
   `test/test_corpus.py` with the exact expected rule IDs.

## Coding rules

- Both engines must produce **identical JSON/SARIF output** for the same input. If a change
  touches output shape, extend the cross-engine comparison in CI and verify locally:
  ```bash
  node src/cli.js examples --json > /tmp/node.json || true
  python src/scanner.py examples --json > /tmp/py.json || true
  # then diff the two files (ignoring scannedAt)
  ```
- New CLI behavior needs mirrored regression tests (`test/cli.test.js` and `test/test_cli.py`).
- Keep Python stdlib-only and Node dependency-free.

## Pull request checklist

- [ ] `npm run test:all` passes locally
- [ ] Rule changes include `npm run check:rules` + `npm run build:rules` (bundle committed)
- [ ] Behavior changes include mirrored Node/Python tests and a corpus fixture if detection changed
- [ ] CHANGELOG.md updated under [Unreleased]
- [ ] English is used in code comments and docs; user-facing reports stay English

## Commit style

Prefixes: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`. One logical change per
commit. Example: `fix: keep report names unique across multiple scan roots`.

## Code of conduct

Be constructive. This project is also a portfolio piece for its author — respectful reviews
are appreciated and harsh comments are not.
