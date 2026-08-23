import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanFiles } from "../src/scanner.js";

// Regression corpus: each fixture's SKILL.md must produce exactly the listed
// rule IDs (and no others). This guards against both missed detections and
// false-positive regressions when rules change.
const CORPUS = {
  "multiline-pipe": {
    risk: "CRITICAL",
    // DOWNLOAD_COMMAND/URL_REFERENCE are superseded (shown, not scored)
    findings: ["DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "URL_REFERENCE"],
  },
  "frontmatter-wildcard": {
    risk: "HIGH",
    // PROCESS_SPAWN is superseded by UNPINNED_PACKAGE
    findings: ["NETWORK_UNRESTRICTED", "PROCESS_SPAWN", "UNPINNED_PACKAGE"],
  },
  "backtick-url-table": {
    risk: "LOW", // plain URL references are info-level, not a finding signal
    findings: ["URL_REFERENCE"],
  },
  "ssh-and-env": {
    risk: "CRITICAL",
    findings: ["SECRET_ENV_FILE", "SECRET_SSH_KEY", "SHELL_EXECUTION", "DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "SUSPICIOUS_URL", "URL_REFERENCE", "MEMORY_MODIFICATION"],
  },
};

const here = dirname(fileURLToPath(import.meta.url));
const corpusRoot = join(here, "..", "examples", "corpus");

for (const [name, expected] of Object.entries(CORPUS)) {
  test(`corpus: ${name}`, () => {
    const dir = join(corpusRoot, name);
    const files = readdirSync(dir).filter((f) => f.endsWith(".md") || f.endsWith(".json"));
    const result = scanFiles(files.map((f) => ({
      name: f,
      content: readFileSync(join(dir, f), "utf8"),
    })));
    assert.equal(result.risk, expected.risk, `risk mismatch for ${name}`);
    const ids = [...new Set(result.reports.flatMap((r) => r.findings.map((f) => f.id)))].sort();
    assert.deepEqual(ids, [...expected.findings].sort(), `finding ids mismatch for ${name}`);
  });
}
