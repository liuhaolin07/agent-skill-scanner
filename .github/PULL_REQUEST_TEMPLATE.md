## What does this PR do?

<!-- One or two sentences. Link the issue it closes, if any: Closes #123 -->

## Checklist

- [ ] `npm run test:all` passes locally (Node + Python engines)
- [ ] Rules changed? `npm run check:rules` and `npm run build:rules` ran, and `rules/rules.js`
      is committed in sync
- [ ] Detection behavior changed? Corpus fixture added in `examples/corpus/<name>/` and
      registered in BOTH `test/corpus.test.js` and `test/test_corpus.py`
- [ ] CLI behavior changed? Mirrored regression tests added (`test/cli.test.js` +
      `test/test_cli.py`)
- [ ] CHANGELOG.md updated under [Unreleased]
- [ ] README updated if user-facing behavior or output changed

## Notes for reviewers

<!-- Anything reviewers should pay attention to: cross-engine output shape, Windows behavior,
     scoring edge cases, superseded-rule interactions. -->
