# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

This project is a static scanner for agent skill definitions — it is not a service and holds no
secrets of its own. The main security-relevant surface is **rule accuracy**: a missed detection
(漏报) means a risky skill ships unflagged, and a false positive (误报) breaks legitimate skill
builders' CI.

Please report security issues privately using
[GitHub Private Vulnerability Reporting](https://github.com/liuhaolin07/agent-skill-scanner/security/advisories/new)
(preferred), or open a public issue only for non-sensitive bug reports.

**What to include:**

- The scanner version and engine (Node / Python) used
- A minimal skill fixture that triggers the problem (or the rule ID affected)
- Expected vs. actual output (JSON or SARIF snippet)
- If reporting a bypass: whether the risky pattern survives `--fail-on HIGH` and `--sarif`

We aim to acknowledge reports within 3 business days and release a fix in the next patch
version. Please do not disclose the issue publicly until a fix is released.

## Scanner safety boundaries

The scanner reads files given as CLI arguments and reports on their content. It never executes
skill commands, never sends file content anywhere, and never writes to the scanned paths.
Evidence excerpts are redacted (`[REDACTED]`) so secrets found in scanned files are not echoed
in reports.
