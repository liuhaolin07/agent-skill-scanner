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
    findings: ["DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "NETWORK_ACCESS"],
  },
  "frontmatter-wildcard": {
    risk: "HIGH",
    findings: ["SHELL_EXECUTION", "NETWORK_UNRESTRICTED"],
  },
  "backtick-url-table": {
    risk: "MEDIUM",
    findings: ["NETWORK_ACCESS"],
  },
  "ssh-and-env": {
    risk: "CRITICAL",
    findings: ["SECRET_ENV_FILE", "SECRET_SSH_KEY", "SHELL_EXECUTION", "DOWNLOAD_EXECUTE", "DOWNLOAD_COMMAND", "SUSPICIOUS_URL", "NETWORK_ACCESS", "MEMORY_MODIFICATION"],
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
