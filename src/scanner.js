const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

const SEVERITY_POINTS = {
  info: 0,
  low: 4,
  medium: 12,
  high: 30,
  critical: 60,
};

const isNode = typeof process !== "undefined" && !!process.versions?.node;

const compile = (rule) => ({
  ...rule,
  patterns: rule.patterns.map((source) => new RegExp(source, rule.case_insensitive ? "i" : "")),
});

// Node (CLI/CI): read the JSON source of truth from disk.
// Browser (web UI): import the generated rules.js (filesystem is unavailable).
let RULES;
if (isNode) {
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const __dirname = dirname(fileURLToPath(import.meta.url));
  RULES = JSON.parse(readFileSync(join(__dirname, "..", "rules", "scanner-rules.json"), "utf8")).map(compile);
} else {
  const { RULES_DATA } = await import("../rules/rules.js");
  RULES = RULES_DATA.map(compile);
}

const CATEGORIES = [
  ["secret_access", "Secrets & SSH keys"],
  ["network_access", "External network"],
  ["shell_execution", "Shell execution"],
  ["memory_modification", "Memory changes"],
  ["excessive_permissions", "Permissions"],
  ["suspicious_download", "URLs & downloads"],
];

function excerpt(line, max = 180) {
  const clean = line.trim().replace(/\s+/g, " ");
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function maskSecrets(value) {
  return value
    .replace(/(-----BEGIN [^-]+ PRIVATE KEY-----).*/i, "$1 [REDACTED]")
    .replace(/((?:token|secret|password|api[_-]?key)\s*[:=]\s*)[^\s,"']+/gi, "$1[REDACTED]");
}

function collectMatches(text, rule) {
  const lines = text.split(/\r?\n/);
  const evidence = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (rule.patterns.some((pattern) => pattern.test(lines[index]))) {
      evidence.push({
        line: index + 1,
        excerpt: maskSecrets(excerpt(lines[index])),
      });
      if (evidence.length === 3) break;
    }
  }
  return evidence;
}

function computeRisk(findings) {
  const score = Math.min(100, findings.reduce((sum, finding) => sum + SEVERITY_POINTS[finding.severity], 0));
  const hasCritical = findings.some((finding) => finding.severity === "critical");
  const hasHigh = findings.some((finding) => finding.severity === "high");
  const hasMedium = findings.some((finding) => finding.severity === "medium");
  const level = hasCritical || score >= 80
    ? "CRITICAL"
    : hasHigh || score >= 40
      ? "HIGH"
      : hasMedium || score >= 20
        ? "MEDIUM"
        : "LOW";
  return { score, level };
}

function validateInput(name, content) {
  if (typeof name !== "string" || !name.trim()) throw new TypeError("A file name is required.");
  if (typeof content !== "string") throw new TypeError("File content must be text.");
  if (content.length > 2_000_000) throw new RangeError("File is larger than the 2 MB scan limit.");
}

export function scanText(name, content) {
  validateInput(name, content);
  const findings = RULES.flatMap((rule) => {
    const evidence = collectMatches(content, rule);
    return evidence.length ? [{
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      why: rule.why,
      remediation: rule.remediation,
      evidence,
    }] : [];
  });
  const risk = computeRisk(findings);
  const categories = Object.fromEntries(CATEGORIES.map(([id, label]) => {
    const categoryFindings = findings.filter((finding) => finding.category === id);
    const highest = categoryFindings.reduce((current, finding) => {
      const rank = ["info", "low", "medium", "high", "critical"];
      return rank.indexOf(finding.severity) > rank.indexOf(current) ? finding.severity : current;
    }, "info");
    return [id, { label, status: categoryFindings.length ? "flagged" : "clear", severity: highest, count: categoryFindings.length }];
  }));

  return {
    schemaVersion: "1.0",
    file: name,
    scannedAt: new Date().toISOString(),
    risk: risk.level,
    score: risk.score,
    summary: findings.length
      ? `${findings.length} security ${findings.length === 1 ? "signal" : "signals"} detected.`
      : "No known risky patterns detected.",
    categories,
    findings,
    disclaimer: "Static heuristic analysis can miss obfuscated or indirect behavior. Review high-impact skills manually before installation.",
  };
}

export function scanFiles(files) {
  if (!Array.isArray(files) || files.length === 0) throw new TypeError("At least one file is required.");
  const reports = files.map(({ name, content }) => scanText(name, content));
  const score = Math.min(100, reports.reduce((max, report) => Math.max(max, report.score), 0));
  const risk = reports.reduce((highest, report) => LEVELS.indexOf(report.risk) > LEVELS.indexOf(highest) ? report.risk : highest, "LOW");
  return {
    schemaVersion: "1.0",
    risk,
    score,
    fileCount: reports.length,
    findingCount: reports.reduce((sum, report) => sum + report.findings.length, 0),
    reports,
  };
}

export const scannerMetadata = Object.freeze({
  acceptedNames: ["SKILL.md", "skill.json", "manifest.json", "mcp.json", "*.md", "*.json", "*.yaml", "*.yml"],
  maxFileBytes: 2_000_000,
  categories: CATEGORIES.map(([id, label]) => ({ id, label })),
  ruleCount: RULES.length,
});
