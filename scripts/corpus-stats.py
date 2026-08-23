#!/usr/bin/env python3
"""Corpus statistics for agent-skill-scanner (stdlib only, Python 3.10+).

Scans one or more real-world skill directories, aggregates findings per
rule/severity/risk, and lists files grouped by outcome — the raw material
for estimating false-positive / false-negative rates across real corpora.

Usage:
  python scripts/corpus-stats.py <dir-or-file> [<dir-or-file> ...]
  python scripts/corpus-stats.py <dir> ... --json

The scan itself is performed by the shared Python engine (src/scanner.py);
this script only aggregates its output.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scanner import _find_files, scan_files  # noqa: E402


def main(argv: list[str]) -> int:
    inputs = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in argv
    if not inputs:
        print("Usage: python scripts/corpus-stats.py <dir-or-file> [...] [--json]")
        return 64

    files = []
    for raw in inputs:
        p = Path(raw)
        if not p.exists():
            print(f"skip missing: {raw}", file=sys.stderr)
            continue
        if p.is_file():
            files.append((p, p.stat().st_size, p.parent))
        else:
            files.extend((f, size, p) for f, size in _find_files(p))

    result = scan_files(
        [{"name": str(path), "content": path.read_text(encoding="utf-8", errors="replace")}
         for path, _, _ in files]
    )

    per_rule: Counter = Counter()
    per_severity: Counter = Counter()
    per_risk: Counter = Counter()
    clean_files = []
    flagged_files = []
    for report in result["reports"]:
        per_risk[report["risk"]] += 1
        if report["findings"]:
            flagged_files.append(report["file"])
            for f in report["findings"]:
                per_rule[f["id"]] += 1
                per_severity[f["severity"]] += 1
        else:
            clean_files.append(report["file"])

    stats = {
        "files": result["fileCount"],
        "clean_files": len(clean_files),
        "flagged_files": len(flagged_files),
        "total_findings": result["findingCount"],
        "risk_distribution": dict(per_risk),
        "severity_distribution": dict(per_severity),
        "rule_distribution": dict(per_rule.most_common()),
        "finding_rate_per_file": round(result["findingCount"] / max(result["fileCount"], 1), 2),
        "flag_rate_pct": round(100 * len(flagged_files) / max(result["fileCount"], 1), 1),
    }

    if as_json:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return 0

    print(f"files={stats['files']}  clean={stats['clean_files']}  flagged={stats['flagged_files']} "
          f"({stats['flag_rate_pct']}%)  findings={stats['total_findings']} "
          f"({stats['finding_rate_per_file']}/file)")
    print(f"risk: {stats['risk_distribution']}")
    print(f"severity: {stats['severity_distribution']}")
    print("\nby rule:")
    for rule, count in stats["rule_distribution"].items():
        print(f"  {rule:24s} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
