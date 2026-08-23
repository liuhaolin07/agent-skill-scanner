#!/usr/bin/env node
/**
 * Structural validation for rules/scanner-rules.json (zero dependencies).
 * Mirrors the JSON Schema in rules/scanner-rules.schema.json; CI runs this so
 * malformed rule edits fail fast with readable messages.
 *
 * Usage: node scripts/check-schema.mjs   (or `npm run check:rules`)
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const rulesPath = join(here, "..", "rules", "scanner-rules.json");

const REQUIRED = ["id", "category", "severity", "title", "why", "remediation", "case_insensitive", "patterns"];
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const CATEGORIES = new Set([
  "secret_access", "shell_execution", "suspicious_download",
  "network_access", "memory_modification", "excessive_permissions",
]);

const errors = [];
let rules;
try {
  rules = JSON.parse(readFileSync(rulesPath, "utf8"));
} catch (error) {
  console.error(`rules/scanner-rules.json is not valid JSON: ${error.message}`);
  process.exit(1);
}

if (!Array.isArray(rules)) {
  errors.push("rules must be a JSON array");
} else {
  const ids = new Set();
  rules.forEach((rule, i) => {
    const at = `rules[${i}]`;
    if (typeof rule !== "object" || rule === null) {
      errors.push(`${at}: must be an object`);
      return;
    }
    for (const field of REQUIRED) {
      if (!(field in rule)) errors.push(`${at}: missing '${field}'`);
    }
    if (rule.id !== undefined) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(rule.id)) errors.push(`${at}: invalid id '${rule.id}' (expected ^[A-Z][A-Z0-9_]*$)`);
      if (ids.has(rule.id)) errors.push(`${at}: duplicate id '${rule.id}'`);
      ids.add(rule.id);
    }
    if (rule.category !== undefined && !CATEGORIES.has(rule.category)) {
      errors.push(`${at}: unknown category '${rule.category}'`);
    }
    if (rule.severity !== undefined && !SEVERITIES.has(rule.severity)) {
      errors.push(`${at}: invalid severity '${rule.severity}' (expected ${[...SEVERITIES].join("|")})`);
    }
    if (typeof rule.case_insensitive !== "boolean") {
      errors.push(`${at}: 'case_insensitive' must be a boolean`);
    }
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      errors.push(`${at}: 'patterns' must be a non-empty array`);
    } else {
      rule.patterns.forEach((pattern, j) => {
        if (typeof pattern !== "string") {
          errors.push(`${at}.patterns[${j}]: must be a string`);
          return;
        }
        try {
          new RegExp(pattern);
        } catch (error) {
          errors.push(`${at}.patterns[${j}]: invalid regex (${error.message})`);
        }
      });
    }
    if (rule.exclude_patterns !== undefined) {
      if (!Array.isArray(rule.exclude_patterns)) {
        errors.push(`${at}: 'exclude_patterns' must be an array`);
      } else {
        rule.exclude_patterns.forEach((pattern, j) => {
          if (typeof pattern !== "string") {
            errors.push(`${at}.exclude_patterns[${j}]: must be a string`);
            return;
          }
          try {
            new RegExp(pattern);
          } catch (error) {
            errors.push(`${at}.exclude_patterns[${j}]: invalid regex (${error.message})`);
          }
        });
      }
    }
  });
}

if (errors.length) {
  console.error(`rules/scanner-rules.json validation failed:\n${errors.map((e) => `  - ${e}`).join("\n")}`);
  process.exit(1);
}
console.log(`rules/scanner-rules.json OK (${rules.length} rules).`);
