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


# ── Multi-line reconstruction ──────────────────────────────────────────────
# Detect command continuations that split a risky pattern across physical
# lines (backslash continuations, `&&`/`|` at EOL, or a pipe line followed by
# an interpreter). Each logical line keeps the start line number of its first
# physical line so evidence still points at a useful location.
CONTINUATION_KEYS = re.compile(
    r"(?:curl|wget|fetch|Invoke-WebRequest|Invoke-RestMethod|requests|urllib|subprocess|child_process|execSync|spawnSync|os\.system)",
    re.I,
)
NEXT_IS_INTERPRETER = re.compile(r"^\s*(?:ba)?sh\b|^\s*python3?\b|^\s*powershell\b", re.I)
MAX_JOINED_LINES = 8
MAX_LOGICAL_LEN = 4000


def build_logical_lines(text: str) -> list[tuple[int, str]]:
    """Return [(start_line, logical_text), ...] with continuations joined."""
    physical = text.split("\n")
    logical = []
    index = 0
    while index < len(physical):
        start = index + 1
        joined = physical[index]
        next_index = index + 1
        joins = 0
        while next_index < len(physical) and joins < MAX_JOINED_LINES:
            tail = joined.rstrip()
            current_line = physical[index + joins]
            continuation = (
                tail.endswith("\\")
                or tail.endswith("&&")
                or (tail.endswith("|") and CONTINUATION_KEYS.search(current_line) is not None)
                or tail.endswith("|&")
                or (tail.endswith("|") and NEXT_IS_INTERPRETER.match(physical[next_index]) is not None)
            )
            if not continuation:
                break
            joined = f"{tail.rstrip().rstrip(chr(92))} {physical[next_index].lstrip()}"
            next_index += 1
            joins += 1
            if len(joined) > MAX_LOGICAL_LEN:
                break
        logical.append((start, joined))
        index = next_index
    return logical


def collect_matches(text: str, rule: Rule, max_evidence: int = 3) -> list[Evidence]:
    """Collect up to max_evidence line-numbered matches for one rule."""
    evidence = []
    lines = build_logical_lines(text)
    lines.extend(build_frontmatter_supplement(text))
    for line_no, logical_text in lines:
        if any(pattern.search(logical_text) for pattern in rule.patterns):
            evidence.append(Evidence(line=line_no, excerpt=mask_secrets(excerpt(logical_text))))
            if len(evidence) == max_evidence:
                break
    return evidence


# ── YAML frontmatter structural awareness ──────────────────────────────────
# SKILL.md files start with a `---` frontmatter block where permissions,
# tools, and similar keys are often declared as multi-line YAML lists:
#
#   permissions:
#     - network: "*"
#     - filesystem: "~"
#
# Line-oriented regex scanning misses the list items because the parent key
# lives on its own line. We fold list items into `<parent>: <value>` lines so
# context-sensitive rules (NETWORK_UNRESTRICTED, FILESYSTEM_BROAD, ...) can
# match them. The folded lines carry the original list-item line numbers and
# are scanned in addition to (never instead of) the raw logical lines.
KEY_VALUE = re.compile(r"^([\w.-]+):\s*(.*)$")
LIST_ITEM = re.compile(r"^-\s+(.+)$")


def build_frontmatter_supplement(text: str) -> list[tuple[int, str]]:
    """Return [(line_no, folded_text), ...] for YAML frontmatter list items."""
    lines = text.split("\n")
    if len(lines) < 3 or not lines[0].lstrip().startswith("---"):
        return []
    end = 1
    while end < len(lines) and not lines[end].lstrip().startswith("---"):
        end += 1
    if end >= len(lines):
        return []  # unterminated frontmatter — treat as body

    stack = []  # (indent, key)
    supplement = []
    for i in range(1, end):
        raw = lines[i]
        indent = len(raw) - len(raw.lstrip())
        trimmed = raw.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()

        list_match = LIST_ITEM.match(trimmed)
        if list_match:
            parent = stack[-1][1] if stack else ""
            supplement.append((i + 1, f"{parent}: {list_match.group(1)}"))
            continue
        kv_match = KEY_VALUE.match(trimmed)
        if kv_match:
            key, value = kv_match.group(1), kv_match.group(2)
            if value:
                supplement.append((i + 1, trimmed))
            stack.append((indent, key))
    return supplement


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


def scan_text(name: str, content: str, disabled_rules: Optional[list[str]] = None) -> dict[str, Any]:
    """Scan a single file's text. Returns the same report shape as the Node engine."""
    validate_input(name, content)

    disabled = set(disabled_rules or [])
    findings = []
    for rule in RULES:
        if rule.id in disabled:
            continue
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


def scan_files(files: list[dict[str, str]], disabled_rules: Optional[list[str]] = None) -> dict[str, Any]:
    """Scan multiple {name, content} files; aggregate by highest risk."""
    if not isinstance(files, list) or not files:
        raise TypeError("At least one file is required.")
    reports = [scan_text(f["name"], f["content"], disabled_rules) for f in files]
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


# ── SARIF 2.1.0 output ──────────────────────────────────────────────────────
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(result: dict[str, Any], tool_name: str = "agent-skill-scanner", tool_version: str = "1.0.0") -> dict[str, Any]:
    """Convert a scan_files() result into SARIF 2.1.0 (GitHub Code Scanning compatible)."""
    all_findings = [f for r in result["reports"] for f in r["findings"]]
    rule_ids = sorted({f["id"] for f in all_findings})

    rules = []
    for rid in rule_ids:
        sample = next((f for f in all_findings if f["id"] == rid), None)
        sev = SARIF_LEVEL.get(sample["severity"] if sample else "", "note")
        sec_sev = 9.0 if sev == "error" else 5.0 if sev == "warning" else 2.0
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": (sample or {}).get("title", rid)},
            "fullDescription": {"text": (sample or {}).get("why", "")},
            "help": {"text": (sample or {}).get("remediation", ""),
                     "markdown": f"**Fix:** {(sample or {}).get('remediation', '')}"},
            "properties": {"category": (sample or {}).get("category", ""),
                           "security-severity": str(sec_sev)},
        })

    results = []
    for report in result["reports"]:
        for finding in report["findings"]:
            results.append({
                "ruleId": finding["id"],
                "level": SARIF_LEVEL.get(finding["severity"], "note"),
                "message": {"text": f"{finding['title']} — {finding['why']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report["file"]},
                            "region": {"startLine": item["line"]},
                        }
                    }
                    for item in finding["evidence"]
                ],
                "properties": {"category": finding["category"]},
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/liuhaolin07/agent-skill-scanner",
                    "rules": rules,
                },
            },
            "results": results,
        }],
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

    result = scan_files(files, disabled_rules=_extract_disabled(args))

    if "--sarif" in args:
        print(json.dumps(to_sarif(result), indent=2, ensure_ascii=False))
    elif "--json" in args:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_human(result)

    return EXIT_CODES.get(result["risk"], 64)


def _extract_disabled(args: list[str]) -> list[str]:
    """Collect every value passed after --disable-rule (repeatable, comma-separated)."""
    values = []
    for i, arg in enumerate(args[:-1]):
        if arg == "--disable-rule" and not args[i + 1].startswith("-"):
            values.extend(s.strip() for s in args[i + 1].split(",") if s.strip())
    return values


if __name__ == "__main__":
    sys.exit(main())
