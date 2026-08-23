#!/usr/bin/env python3
"""
Agent Skill Scanner — Python engine.

Reads the shared rule set from rules/scanner-rules.json (same source as the
Node engine in scanner.js) and produces an identical risk report.

Detects:
  • .env / SSH key / broad environment access
  • External network access and wildcard egress
  • Shell / subprocess execution
  • Persistent memory modification
  • Excessive permissions (elevation, broad filesystem, destructive commands)
  • Suspicious URLs / downloads / pipe-to-interpreter

Outputs: LOW / MEDIUM / HIGH / CRITICAL with a 0-100 score.
Zero third-party dependencies (stdlib only). Compatible with Python 3.10+.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

RULES_JSON = Path(__file__).resolve().parent.parent / "rules" / "scanner-rules.json"
MAX_FILE_BYTES = 2_000_000
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_POINTS = {"info": 0, "low": 4, "medium": 12, "high": 30, "critical": 60}

CATEGORIES = [
    ("secret_access", "Secrets & SSH keys"),
    ("network_access", "External network"),
    ("shell_execution", "Shell execution"),
    ("memory_modification", "Memory changes"),
    ("excessive_permissions", "Permissions"),
    ("suspicious_download", "URLs & downloads"),
]

# ── Rule loading ────────────────────────────────────────────────────────────


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    title: str
    why: str
    remediation: str
    patterns: list = field(default_factory=list)  # compiled regexes


def _load_rules() -> list[Rule]:
    """Load and compile the shared rule set from rules/scanner-rules.json."""
    data = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    rules = []
    for entry in data:
        flags = re.IGNORECASE if entry.get("case_insensitive") else 0
        compiled = []
        for source in entry["patterns"]:
            try:
                compiled.append(re.compile(source, flags))
            except re.error as exc:
                raise ValueError(f"Bad regex in rule {entry['id']}: {source!r} -> {exc}") from exc
        rules.append(Rule(
            id=entry["id"],
            category=entry["category"],
            severity=entry["severity"],
            title=entry["title"],
            why=entry["why"],
            remediation=entry["remediation"],
            patterns=compiled,
        ))
    return rules


RULES = _load_rules()


# ── Scanning ────────────────────────────────────────────────────────────────


@dataclass
class Evidence:
    line: int
    excerpt: str


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    why: str
    remediation: str
    evidence: list = field(default_factory=list)


def excerpt(line: str, max_len: int = 180) -> str:
    clean = re.sub(r"\s+", " ", line.strip())
    return clean if len(clean) <= max_len else f"{clean[:max_len - 1]}…"


def mask_secrets(value: str) -> str:
    """Redact private-key headers and token-like assignments in evidence."""
    value = re.sub(r"(-----BEGIN [^-]+ PRIVATE KEY-----).*", r"\1 [REDACTED]", value, flags=re.I)
    value = re.sub(
        r"((?:token|secret|password|api[_-]?key)\s*[:=]\s*)[^\s,\"']+",
        r"\1[REDACTED]",
        value,
        flags=re.I,
    )
    return value


def collect_matches(text: str, rule: Rule, max_evidence: int = 3) -> list[Evidence]:
    """Collect up to max_evidence line-numbered matches for one rule."""
    evidence = []
    for index, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in rule.patterns):
            evidence.append(Evidence(line=index, excerpt=mask_secrets(excerpt(line))))
            if len(evidence) == max_evidence:
                break
    return evidence


def compute_risk(findings: list[Finding]) -> tuple[int, str]:
    """Score 0-100 and map to a risk level, mirroring the Node engine."""
    score = min(100, sum(SEVERITY_POINTS[f.severity] for f in findings))
    severities = {f.severity for f in findings}
    if "critical" in severities or score >= 80:
        level = "CRITICAL"
    elif "high" in severities or score >= 40:
        level = "HIGH"
    elif "medium" in severities or score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def validate_input(name: str, content: str) -> None:
    if not isinstance(name, str) or not name.strip():
        raise TypeError("A file name is required.")
    if not isinstance(content, str):
        raise TypeError("File content must be text.")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"File is larger than the {MAX_FILE_BYTES // 1_000_000} MB scan limit.")


def scan_text(name: str, content: str) -> dict[str, Any]:
    """Scan a single file's text. Returns the same report shape as the Node engine."""
    validate_input(name, content)

    findings = []
    for rule in RULES:
        evidence = collect_matches(content, rule)
        if evidence:
            findings.append(Finding(
                id=rule.id,
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                why=rule.why,
                remediation=rule.remediation,
                evidence=evidence,
            ))

    score, level = compute_risk(findings)
    severity_rank = ["info", "low", "medium", "high", "critical"]
    categories = {}
    for cat_id, label in CATEGORIES:
        cat_findings = [f for f in findings if f.category == cat_id]
        highest = "info"
        for finding in cat_findings:
            if severity_rank.index(finding.severity) > severity_rank.index(highest):
                highest = finding.severity
        categories[cat_id] = {
            "label": label,
            "status": "flagged" if cat_findings else "clear",
            "severity": highest,
            "count": len(cat_findings),
        }

    return {
        "schemaVersion": "1.0",
        "file": name,
        "scannedAt": __import__("datetime").datetime.now().isoformat() + "Z",
        "risk": level,
        "score": score,
        "summary": f"{len(findings)} security {'signal' if len(findings) == 1 else 'signals'} detected."
        if findings
        else "No known risky patterns detected.",
        "categories": categories,
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "why": f.why,
                "remediation": f.remediation,
                "evidence": [{"line": e.line, "excerpt": e.excerpt} for e in f.evidence],
            }
            for f in findings
        ],
        "disclaimer": "Static heuristic analysis can miss obfuscated or indirect behavior. Review high-impact skills manually before installation.",
    }


def scan_files(files: list[dict[str, str]]) -> dict[str, Any]:
    """Scan multiple {name, content} files; aggregate by highest risk."""
    if not isinstance(files, list) or not files:
        raise TypeError("At least one file is required.")
    reports = [scan_text(f["name"], f["content"]) for f in files]
    score = max((r["score"] for r in reports), default=0)
    risk = max((r["risk"] for r in reports), key=lambda r: LEVELS.index(r))
    return {
        "schemaVersion": "1.0",
        "risk": risk,
        "score": score,
        "fileCount": len(reports),
        "findingCount": sum(len(r["findings"]) for r in reports),
        "reports": reports,
    }


def scanner_metadata() -> dict[str, Any]:
    return {
        "acceptedNames": ["SKILL.md", "skill.json", "manifest.json", "mcp.json", "*.md", "*.json", "*.yaml", "*.yml"],
        "maxFileBytes": MAX_FILE_BYTES,
        "categories": [{"id": cid, "label": label} for cid, label in CATEGORIES],
        "ruleCount": len(RULES),
    }


# ── CLI ─────────────────────────────────────────────────────────────────────

EXIT_CODES = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ALLOWED_SUFFIXES = (".md", ".json", ".yaml", ".yml")


def _find_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    # Sort case-sensitively on the raw string to match the Node engine's
    # Array.prototype.sort() (Windows Path.__lt__ is normcase-insensitive).
    paths = [
        p for p in input_path.rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES
    ]
    return sorted(paths, key=str)


def _print_human(result: dict[str, Any]) -> None:
    print(f"[{result['risk']}] score {result['score']}/100 · {result['fileCount']} file(s) · {result['findingCount']} finding(s)")
    for report in result["reports"]:
        print(f"\n{report['file']} — {report['risk']}")
        if not report["findings"]:
            print("  No known risky patterns detected.")
        for finding in report["findings"]:
            print(f"  {finding['severity'].upper()} {finding['id']}: {finding['title']}")
            for item in finding["evidence"]:
                print(f"    line {item['line']}: {item['excerpt']}")
            print(f"    Fix: {finding['remediation']}")


def main(argv: Optional[list[str]] = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        print("Usage: python scanner.py <file-or-directory> [--json] [--min-risk LEVEL]")
        print("Exit codes: 0 LOW, 1 MEDIUM, 2 HIGH, 3 CRITICAL, 64 invalid input")
        return 0 if args else 64

    inputs = [a for a in args if not a.startswith("-")]
    if not inputs:
        print("Missing input path.", file=sys.stderr)
        return 64
    root = Path(inputs[0])
    if not root.exists():
        print(f"Error: '{root}' does not exist", file=sys.stderr)
        return 64

    paths = _find_files(root)
    if not paths:
        print("No Markdown, JSON, or YAML files found.", file=sys.stderr)
        return 64

    files = []
    for path in paths:
        try:
            files.append({
                "name": path.name if len(paths) == 1 else str(path.relative_to(root)),
                "content": path.read_text(encoding="utf-8", errors="replace"),
            })
        except OSError as exc:
            print(f"Scan failed: {exc}", file=sys.stderr)
            return 64

    result = scan_files(files)

    if "--json" in args:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_human(result)

    return EXIT_CODES.get(result["risk"], 64)


if __name__ == "__main__":
    sys.exit(main())
