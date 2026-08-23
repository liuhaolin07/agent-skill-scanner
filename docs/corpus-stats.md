# Corpus Statistics & False-Positive Analysis

Real-world corpus scan results for agent-skill-scanner, produced with
`python scripts/corpus-stats.py <dirs...>`.

## Corpora

| Corpus | Files | Source |
|---|---|---|
| Hermes agent skills | 445 | `D:\Hermes\skills` — 125 skills incl. SKILL.md, references, templates (real production skills) |
| 数模 (math modeling) projects | 315 | `C:\Users\haolin\cumcm_c`, `D:\work\hermes\cumcm_*` — normal project repos |

## Results (after v0.2.1 + exclude_patterns fix)

| Metric | Hermes skills | 数模 projects |
|---|---|---|
| Files scanned | 445 | 315 |
| Clean files | 195 (43.8%) | 310 (98.4%) |
| Flagged files | 250 (56.2%) | 5 (1.6%) |
| Total findings | 414 (0.93/file) | 5 (0.02/file) |
| Risk: LOW / MED / HIGH / CRIT | 305 / 33 / 80 / 27 | 315 / 0 / 0 / 0 |

### Rule distribution (Hermes skills)

| Rule | Count | Assessment |
|---|---|---|
| URL_REFERENCE | 201 | info-level, plain URL mentions (docs) — informational, not a risk signal |
| DOWNLOAD_COMMAND | 48 | mostly real download commands (`curl -fsSL … \| bash` patterns and install instructions) |
| SECRET_BROAD_ENV | 40 | env enumeration in ops skills — real capability, context-dependent |
| SECRET_ENV_FILE | 30 | `.env` reads — real capability for credential-managing skills |
| SHELL_EXECUTION | 16 | real shell execution in automation skills |
| PRIVILEGE_ESCALATION | 15 | sudo/root usage in system-admin skills — real |
| … (10 more rules, 74 findings total) | | |

## False positives found & fixed (this round)

Sampling flagged files revealed two well-understood false-positive classes;
both were fixed and pinned by corpus fixtures:

1. **Local loopback URLs flagged as suspicious downloads**
   - `curl -s http://127.0.0.1:8188/system_stats` (ComfyUI health check) hit
     SUSPICIOUS_URL's raw-IP pattern.
   - Fix: raw-IP pattern now excludes `127.*` / `0.*` (loopback).
   - Fixture: `examples/corpus/localhost-health-check/` (expects no SUSPICIOUS_URL).

2. **SSH key *generation* and public-key references flagged as credential access**
   - `ssh-keygen -f ~/.ssh/id_ed25519`, `ls ~/.ssh/id_*.pub`, `.ssh/config`
     troubleshooting docs hit SECRET_SSH_KEY.
   - Fix: engine gained optional `exclude_patterns` (negative patterns, both
     engines); SECRET_SSH_KEY excludes `ssh-keygen`, `*.pub`, `.ssh/config`.
   - Fixture: `examples/corpus/ssh-keygen/` (expects no SECRET_SSH_KEY).

Before → after on the Hermes corpus: **425 → 414 findings** (11 confirmed
false positives removed; the two classes above), with no corpus regression.

## False-positive rate estimate

- **info-level (URL_REFERENCE)**: informational by design; if counted as
  findings, they dominate. Excluding info, the flagged-file rate is ~40%.
- **medium+ findings**: sampled ~15 files across HIGH/CRITICAL; all had real
  contextual grounds (permissions, secrets, downloads, memory writes are the
  skills' actual functions). No additional false-positive class found after
  the two fixes above.
- Honest caveat: this is a heuristic estimate from sampling, not a labelled
  ground-truth benchmark.

## False-negative (漏报) coverage

True FNR needs a labelled corpus; instead we rely on the pinned regression
corpus: 6 fixtures in `examples/corpus/` covering every known dangerous
pattern class (pipe-to-shell, wildcard permissions, SSH+env exfiltration,
multiline obfuscation, frontmatter wildcards) — all must produce the exact
expected rule hits on both engines, and do so in CI. This guards against
"fixing a false positive, introducing a miss".

## Reproduce

```bash
python scripts/corpus-stats.py D:/Hermes/skills        # summary table
python scripts/corpus-stats.py D:/Hermes/skills --json # machine-readable
```
