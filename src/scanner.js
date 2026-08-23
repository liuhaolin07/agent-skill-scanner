const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export { LEVELS, maskSecrets };

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
    .replace(/((?:token|secret|password|api[_-]?key)\s*[:=]\s*)[^\s,"']+/gi, "$1[REDACTED]")
    // JSON / YAML quoted values: "api_key": "secret-value", api_key: "secret-value"
    .replace(/(["']?(?:api[_-]?key|token|secret|password|authorization|auth|access[_-]?key|secret[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["'])[^"']+/gi, "$1[REDACTED]")
    // HTTP auth headers: Authorization: Bearer abc...
    .replace(/(authorization\s*:\s*(?:bearer|basic|token)\s+)[^\s,;]+/gi, "$1[REDACTED]")
    // GitHub PATs (ghp_/gho_/ghu_/ghs_/ghr_), AWS access keys, generic sk- tokens
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/gi, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED]")
    // Credentials in URL query strings: ?token=abc&key=xyz
    .replace(/([?&](?:token|key|secret|password|api[_-]?key|access[_-]?key|sig|signature)=)[^&\s"']+/gi, "$1[REDACTED]");
}

function collectMatches(text, rule) {
  const evidence = [];
  const lines = buildLogicalLines(text);
  lines.push(...buildFrontmatterSupplement(text));
  for (const logical of lines) {
    if (rule.patterns.some((pattern) => pattern.test(logical.text))) {
      evidence.push({
        line: logical.line,
        excerpt: maskSecrets(excerpt(logical.text)),
      });
      if (evidence.length === 3) break;
    }
  }
  return evidence;
}

// ── Multi-line reconstruction ─────────────────────────────────────────────
// Detect command continuations that split a risky pattern across physical
// lines (backslash continuations, `&&`/`|` at EOL, or a pipe line followed by
// an interpreter). Each logical line keeps the start line number of its first
// physical line so evidence still points at a useful location.
const CONTINUATION_KEYS = /(?:curl|wget|fetch|Invoke-WebRequest|Invoke-RestMethod|requests|urllib|subprocess|child_process|execSync|spawnSync|os\.system)/i;
const MAX_JOINED_LINES = 8;
const MAX_LOGICAL_LEN = 4000;

function buildLogicalLines(text) {
  const physical = text.split(/\r?\n/);
  const logical = [];
  let index = 0;
  while (index < physical.length) {
    const start = index + 1;
    let joined = physical[index];
    let next = index + 1;
    let joins = 0;
    while (next < physical.length && joins < MAX_JOINED_LINES) {
      const tail = joined.trimEnd();
      const currentLine = physical[index + joins];
      const continuation =
        tail.endsWith("\\") ||
        tail.endsWith("&&") ||
        (tail.endsWith("|") && CONTINUATION_KEYS.test(currentLine)) ||
        tail.endsWith("|&") ||
        (tail.endsWith("|") && /^\s*(?:ba)?sh\b|^\s*python3?\b|^\s*powershell\b/i.test(physical[next]));
      if (!continuation) break;
      joined = `${joined.trimEnd().replace(/\\$/, "")} ${physical[next].trimStart()}`;
      next += 1;
      joins += 1;
      if (joined.length > MAX_LOGICAL_LEN) break;
    }
    logical.push({ line: start, text: joined });
    index = next;
  }
  return logical;
}

// ── YAML frontmatter structural awareness ────────────────────────────────
// SKILL.md files start with a `---` frontmatter block where permissions,
// tools, and similar keys are often declared as multi-line YAML lists:
//
//   permissions:
//     - network: "*"
//     - filesystem: "~"
//
// Line-oriented regex scanning misses the list items because the parent key
// lives on its own line. We fold list items into `<parent>: <value>` lines so
// context-sensitive rules (NETWORK_UNRESTRICTED, FILESYSTEM_BROAD, ...) can
// match them. The folded lines carry the original list-item line numbers and
// are scanned in addition to (never instead of) the raw logical lines.
function buildFrontmatterSupplement(text) {
  const lines = text.split(/\r?\n/);
  if (lines.length < 3 || !lines[0].trim().startsWith("---")) return [];
  let end = 1;
  while (end < lines.length && !lines[end].trim().startsWith("---")) end += 1;
  if (end >= lines.length) return []; // unterminated frontmatter — treat as body

  const stack = []; // { indent, key }
  const supplement = [];
  for (let i = 1; i < end; i += 1) {
    const raw = lines[i];
    const indent = (raw.match(/^\s*/) || [""])[0].length;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();

    const listMatch = trimmed.match(/^-\s+(.+)$/);
    if (listMatch) {
      const parent = stack.length ? stack[stack.length - 1].key : "";
      supplement.push({ line: i + 1, text: `${parent}: ${listMatch[1]}` });
      continue;
    }
    const kvMatch = trimmed.match(/^([\w.-]+):\s*(.*)$/);
    if (kvMatch) {
      const [, key, value] = kvMatch;
      if (value) supplement.push({ line: i + 1, text: trimmed });
      stack.push({ indent, key });
    }
  }
  return supplement;
}

function computeRisk(findings) {
  // Superseded findings still appear in the report but do not double-count
  // toward the score (e.g. `curl | bash` already flags DOWNLOAD_EXECUTE;
  // DOWNLOAD_COMMAND / SUSPICIOUS_URL / URL_REFERENCE are shown, not scored).
  const superseded = new Set();
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  for (const finding of findings) {
    const rule = RULES.find((r) => r.id === finding.id);
    if (rule?.supersedes) {
      for (const id of rule.supersedes) {
        if (byId.has(id)) superseded.add(id);
      }
    }
  }
  const score = Math.min(100, findings.reduce(
    (sum, finding) => sum + (superseded.has(finding.id) ? 0 : SEVERITY_POINTS[finding.severity]),
    0,
  ));
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
  // Byte-accurate limit (UTF-8), not character count — a CJK-heavy file can
  // be 3 bytes/char.
  if (Buffer.byteLength(content, "utf8") > 2_000_000) throw new RangeError("File is larger than the 2 MB scan limit.");
}

// Normalize Unicode (NFKC collapses lookalike/confusable characters) and drop
// zero-width characters used to hide risky tokens (e.g. c\u200Burl → curl).
function normalizeContent(content) {
  return content
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF\u2060]/g, "");
}

export function scanText(name, content, { disabledRules = [] } = {}) {
  validateInput(name, content);
  content = normalizeContent(content);
  const disabled = new Set(disabledRules);
  const findings = RULES
    .filter((rule) => !disabled.has(rule.id))
    .flatMap((rule) => {
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

export function scanFiles(files, { disabledRules = [] } = {}) {
  if (!Array.isArray(files) || files.length === 0) throw new TypeError("At least one file is required.");
  const reports = files.map(({ name, content }) => scanText(name, content, { disabledRules }));
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

// ── SARIF 2.1.0 output ─────────────────────────────────────────────────────
// Converts a scanFiles() result into SARIF so it can be uploaded to
// GitHub Code Scanning or other SARIF consumers.
const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };

export function toSarif(result, { toolName = "agent-skill-scanner", toolVersion = "1.0.0" } = {}) {
  const ruleIds = [...new Set(result.reports.flatMap((r) => r.findings.map((f) => f.id)))];
  const rules = ruleIds.map((id) => {
    const sample = result.reports.flatMap((r) => r.findings).find((f) => f.id === id);
    return {
      id,
      name: id,
      shortDescription: { text: sample?.title || id },
      fullDescription: { text: sample?.why || "" },
      help: { text: sample?.remediation || "", markdown: `**Fix:** ${sample?.remediation || ""}` },
      properties: { category: sample?.category || "", "security-severity": String(SARIF_LEVEL[sample?.severity] === "error" ? 9.0 : SARIF_LEVEL[sample?.severity] === "warning" ? 5.0 : 2.0) },
    };
  });

  const results = result.reports.flatMap((report) => report.findings.map((finding) => ({
    ruleId: finding.id,
    level: SARIF_LEVEL[finding.severity] || "note",
    message: { text: `${finding.title} — ${finding.why}` },
    locations: finding.evidence.map((item) => ({
      physicalLocation: {
        artifactLocation: { uri: report.file },
        region: { startLine: item.line },
      },
    })),
    properties: { category: finding.category },
  })));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: toolName,
          version: toolVersion,
          informationUri: "https://github.com/liuhaolin07/agent-skill-scanner",
          rules,
        },
      },
      results,
    }],
  };
}

export const scannerMetadata = Object.freeze({
  acceptedNames: ["SKILL.md", "skill.json", "manifest.json", "mcp.json", "*.md", "*.json", "*.yaml", "*.yml"],
  maxFileBytes: 2_000_000,
  categories: CATEGORIES.map(([id, label]) => ({ id, label })),
  ruleCount: RULES.length,
});
