#!/usr/bin/env node
import { readFile, stat, readdir } from "node:fs/promises";
import { resolve, basename, relative } from "node:path";
import process from "node:process";
import { scanFiles, toSarif } from "./scanner.js";

const ALLOWED = /(?:\.md|\.json|\.ya?ml)$/i;

function usage() {
  console.log(`Agent Skill Scanner\n\nUsage:\n  npm run scan -- <file-or-directory> [--json]\n  skill-scan <file-or-directory> [--json]\n\nExit codes: 0 LOW, 1 MEDIUM, 2 HIGH, 3 CRITICAL, 64 invalid input`);
}

async function findFiles(inputPath) {
  const absolute = resolve(inputPath);
  const info = await stat(absolute);
  if (info.isFile()) return [absolute];
  if (!info.isDirectory()) throw new Error("Input must be a file or directory.");
  const entries = await readdir(absolute, { withFileTypes: true, recursive: true });
  return entries
    .filter((entry) => entry.isFile() && ALLOWED.test(entry.name))
    .map((entry) => resolve(entry.parentPath, entry.name))
    .sort();
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
  const files = await Promise.all(paths.map(async (path) => ({
    name: paths.length === 1 ? basename(path) : relative(root, path),
    content: await readFile(path, "utf8"),
  })));
  const result = scanFiles(files, { disabledRules: extractDisabled(args) });
  if (args.includes("--sarif")) {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else if (args.includes("--json")) console.log(JSON.stringify(result, null, 2));
  else printHuman(result);
  process.exitCode = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }[result.risk];
}

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
