#!/usr/bin/env node
import { readFile, stat, readdir } from "node:fs/promises";
import { resolve, basename, relative } from "node:path";
import process from "node:process";
import { LEVELS, scanFiles, toSarif } from "./scanner.js";

const ALLOWED = /(?:\.md|\.json|\.ya?ml)$/i;
// Directories never worth scanning (vendored deps, VCS metadata, build output).
const SKIP_DIRS = new Set([
  ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
  "__pycache__", ".tox", ".nox", "dist", "build", ".next", ".nuxt",
  ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage",
]);
const MAX_FILE_BYTES = 2_000_000; // per file
const MAX_TOTAL_BYTES = 50_000_000; // per scan
const MAX_FILES = 1_000; // per scan

function usage() {
  console.log(`Agent Skill Scanner\n\nUsage:\n  npm run scan -- <file-or-directory> [--json] [--sarif] [--fail-on LEVEL] [--disable-rule ID]\n  skill-scan <file-or-directory> [options]\n\nOptions:\n  --json            JSON report\n  --sarif           SARIF 2.1.0 report\n  --fail-on LEVEL   exit non-zero only if risk >= LEVEL (LOW|MEDIUM|HIGH|CRITICAL)\n  --disable-rule ID disable a rule (repeatable, comma-separated)\n\nExit codes: 0 LOW, 1 MEDIUM, 2 HIGH, 3 CRITICAL, 64 invalid input`);
}

// Parse --fail-on LEVEL; returns null when absent.
function failOnLevel(args) {
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--fail-on" && args[i + 1]) {
      const level = args[i + 1].toUpperCase();
      if (LEVELS.includes(level)) return level;
      throw new Error(`Invalid --fail-on level '${args[i + 1]}' (expected LOW|MEDIUM|HIGH|CRITICAL)`);
    }
  }
  return null;
}

async function findFiles(inputPath) {
  const absolute = resolve(inputPath);
  const info = await stat(absolute);
  if (info.isFile()) return [{ path: absolute, bytes: info.size }];
  if (!info.isDirectory()) throw new Error("Input must be a file or directory.");
  const entries = await readdir(absolute, { withFileTypes: true, recursive: true });
  const found = [];
  for (const entry of entries) {
    if (!entry.isFile() || !ALLOWED.test(entry.name)) continue;
    const path = resolve(entry.parentPath, entry.name);
    // Skip files under vendored/VCS/build directories.
    const relParts = relative(absolute, path).split(/[\\/]/);
    if (relParts.slice(0, -1).some((part) => SKIP_DIRS.has(part))) continue;
    const size = (await stat(path)).size;
    if (size > MAX_FILE_BYTES) {
      console.error(`skip ${relative(absolute, path)}: ${size} bytes exceeds ${MAX_FILE_BYTES} limit`);
      continue;
    }
    found.push({ path, bytes: size });
    if (found.length >= MAX_FILES) {
      console.error(`warning: file limit (${MAX_FILES}) reached; remaining files skipped`);
      break;
    }
  }
  const total = found.reduce((sum, f) => sum + f.bytes, 0);
  if (total > MAX_TOTAL_BYTES) {
    console.error(`warning: total ${total} bytes exceeds ${MAX_TOTAL_BYTES} limit`);
  }
  return found.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function printHuman(result) {
  const badge = `[${result.risk}]`;
  console.log(`${badge} score ${result.score}/100 · ${result.fileCount} file(s) · ${result.findingCount} finding(s)`);
  for (const report of result.reports) {
    console.log(`\n${report.file} — ${report.risk}`);
    if (!report.findings.length) console.log("  No known risky patterns detected.");
    for (const finding of report.findings) {
      console.log(`  ${finding.severity.toUpperCase()} ${finding.id}: ${finding.title}`);
      for (const item of finding.evidence) console.log(`    line ${item.line}: ${item.excerpt}`);
      console.log(`    Fix: ${finding.remediation}`);
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes("--help") || args.includes("-h")) {
    usage();
    process.exitCode = args.length ? 0 : 64;
    return;
  }
  const input = args.find((arg) => !arg.startsWith("-"));
  if (!input) throw new Error("Missing input path.");
  const paths = await findFiles(input);
  if (!paths.length) throw new Error("No Markdown, JSON, or YAML files found.");
  const root = resolve(input);
  const files = await Promise.all(paths.map(async ({ path }) => ({
    name: paths.length === 1 ? basename(path) : relative(root, path),
    content: await readFile(path, "utf8"),
  })));
  const result = scanFiles(files, { disabledRules: extractDisabled(args) });
  if (args.includes("--sarif")) {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else if (args.includes("--json")) console.log(JSON.stringify(result, null, 2));
  else printHuman(result);
  const failOn = failOnLevel(args);
  if (failOn) {
    // Gate semantics: non-zero only when the scan risk reaches the threshold.
    process.exitCode = LEVELS.indexOf(result.risk) >= LEVELS.indexOf(failOn)
      ? EXIT_CODES[result.risk]
      : 0;
  } else {
    process.exitCode = EXIT_CODES[result.risk];
  }
}

const EXIT_CODES = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

// Collect every value passed after --disable-rule (repeatable, comma-separated).
function extractDisabled(args) {
  const values = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--disable-rule" && args[i + 1] && !args[i + 1].startsWith("-")) {
      values.push(...args[i + 1].split(",").map((s) => s.trim()).filter(Boolean));
      i += 1;
    }
  }
  return values;
}

main().catch((error) => {
  console.error(`Scan failed: ${error.message}`);
  process.exitCode = 64;
});
