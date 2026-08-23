#!/usr/bin/env python3
"""
Regression corpus tests — mirrors test/corpus.test.js (Node engine).

Run: python test/test_corpus.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scanner import scan_files  # noqa: E402

# Regression corpus: each fixture's SKILL.md must produce exactly the listed
# rule IDs (and no others). This guards against both missed detections and
# false-positive regressions when rules change.
CORPUS = {
    "multiline-pipe": {
        "risk": "CRITICAL",
        # DOWNLOAD_COMMAND/URL_REFERENCE are superseded (shown, not scored)
        "findings": ["DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "URL_REFERENCE"],
    },
    "frontmatter-wildcard": {
        "risk": "HIGH",
        # PROCESS_SPAWN is superseded by UNPINNED_PACKAGE
        "findings": ["NETWORK_UNRESTRICTED", "PROCESS_SPAWN", "UNPINNED_PACKAGE"],
    },
    "backtick-url-table": {
        "risk": "LOW",  # plain URL references are info-level, not a finding signal
        "findings": ["URL_REFERENCE"],
    },
    "ssh-and-env": {
        "risk": "CRITICAL",
        "findings": [
            "SECRET_ENV_FILE", "SECRET_SSH_KEY", "SHELL_EXECUTION",
            "DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "SUSPICIOUS_URL",
            "URL_REFERENCE", "MEMORY_MODIFICATION",
        ],
    },
    # Localhost health checks must not trip SUSPICIOUS_URL (raw-IP rule).
    "localhost-health-check": {
        "risk": "LOW",
        "findings": ["URL_REFERENCE"],
    },
    # ssh-keygen / public keys are key *generation*, not secret access.
    "ssh-keygen": {
        "risk": "LOW",
        "findings": [],
    },
}

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "examples" / "corpus"


class TestCorpus(unittest.TestCase):
    def test_corpus(self):
        for name, expected in CORPUS.items():
            with self.subTest(name=name):
                dir_path = CORPUS_ROOT / name
                files = [
                    {"name": f.name, "content": f.read_text(encoding="utf-8")}
                    for f in sorted(dir_path.iterdir())
                    if f.suffix in (".md", ".json")
                ]
                result = scan_files(files)
                self.assertEqual(result["risk"], expected["risk"], f"risk mismatch for {name}")
                ids = sorted({f["id"] for r in result["reports"] for f in r["findings"]})
                self.assertEqual(ids, sorted(expected["findings"]), f"finding ids mismatch for {name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
