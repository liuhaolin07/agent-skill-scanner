---
name: Bug report
about: Report a scanner bug — missed detection (漏报), false positive (误报), crash, or broken output
title: "[Bug] "
labels: bug
assignees: ''
---

**Scanner version & engine**
- Version: (e.g. v0.2.1, or commit SHA)
- Engine: Node / Python / both / web UI

**Describe the bug**
A clear and concise description. If it is a false positive, name the rule id it should NOT have
hit (or did not hit).

**Minimal fixture**
Paste the smallest skill snippet that reproduces the problem, or point to a fixture file:

```markdown
<!-- paste SKILL.md or the relevant excerpt here -->
```

**Expected vs. actual**
- Command run: `skill-scan <path> --json` (or equivalent)
- Expected output: (e.g. `SHELL_EXECUTION` should NOT appear)
- Actual output: (paste the JSON/SARIF excerpt)

**Environment**
- OS: (e.g. Windows 11 / Ubuntu 24.04 / macOS 15)
- Node version / Python version

**Additional context**
Anything else relevant — corpus fixtures used, `--disable-rule` flags, pre-commit hook usage, etc.
