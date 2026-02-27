# npm-shield 🛡️

**Catch supply chain attacks before they reach production.**

npm-shield is a CLI security tool that scans Node.js project dependencies for supply chain attack indicators. It analyzes `package.json` and `node_modules` for typosquatting attempts, rogue Git hooks, credential-harvesting code, and suspicious MCP server installations — producing a structured risk report with severity scores and actionable remediation steps.

---

## Quick Start

```bash
# Install
pip install npm_shield

# Scan the current directory
npm-shield scan

# Scan a specific project
npm-shield scan /path/to/your/node-project

# Export a JSON report
npm-shield scan --output json --output-file report.json
```

That's it. npm-shield will analyze your project and print a color-coded risk report to the terminal.

---

## Features

- **Typosquatting detection** — Compares installed package names against popular packages using edit-distance heuristics to catch lookalike packages (e.g., `lod4sh` vs `lodash`).
- **Git hook inspection** — Scans `.git/hooks` for injected malicious scripts inserted by `postinstall` lifecycle hooks.
- **Credential harvesting detection** — Regex-scans package source files for environment variable exfiltration, network beaconing, and secret-harvesting patterns.
- **MCP server & rogue binary detection** — Flags unexpected executables in `node_modules/.bin` or packages declaring Model Context Protocol server entry points.
- **Structured risk reports** — Outputs findings as rich terminal tables, JSON, or HTML with per-package severity scores and step-by-step remediation guidance.

---

## Usage Examples

### Basic terminal scan

```bash
npm-shield scan /path/to/project
```

```
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package          ┃ Severity   ┃ Category ┃ Finding                              ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ lod4sh           │ HIGH       │ Typosquat│ Close match to popular package:      │
│                  │            │          │ lodash (edit distance: 1)            │
│ crossenv         │ CRITICAL   │ Known Bad│ Matches known malicious package DB   │
│ event-stream     │ CRITICAL   │ Known Bad│ Sandworm-style attack indicator      │
└──────────────────┴────────────┴──────────┴──────────────────────────────────────┘

Scan complete. 3 findings: 2 critical, 1 high.
```

### Scan with OSV.dev CVE enrichment

```bash
npm-shield scan --osv --min-severity high
```

### Export to JSON

```bash
npm-shield scan --output json --output-file report.json
```

```json
{
  "project": "/path/to/project",
  "scanned_at": "2024-11-01T12:00:00Z",
  "summary": { "critical": 2, "high": 1, "medium": 0, "low": 0 },
  "findings": [
    {
      "package": "crossenv",
      "severity": "critical",
      "category": "known_malicious",
      "description": "Matches known malicious package database.",
      "remediation": "Remove this package immediately and audit your environment for signs of compromise."
    }
  ]
}
```

### Export to HTML

```bash
npm-shield scan --output html --output-file report.html
```

### Programmatic usage

```python
from npm_shield import run_scan

findings = run_scan("/path/to/node-project")
for finding in findings:
    print(f"[{finding['severity'].upper()}] {finding['package']}: {finding['description']}")
```

---

## Project Structure

```
npm_shield/
├── pyproject.toml          # Project metadata, dependencies, CLI entry point
├── README.md
├── npm_shield/
│   ├── __init__.py         # Version and top-level public API
│   ├── cli.py              # Click-based CLI: scan and version commands
│   ├── scanner.py          # Orchestrates all detectors, aggregates findings
│   ├── detectors.py        # Individual detector functions (typosquat, hooks, etc.)
│   ├── patterns.py         # Static DB of malicious package names and regex signatures
│   ├── npm_utils.py        # Helpers: parse package.json, lockfiles, node_modules
│   ├── reporter.py         # Terminal (rich), JSON, and HTML report rendering
│   └── osv_client.py       # OSV.dev API client for CVE cross-referencing
└── tests/
    ├── test_detectors.py   # Unit tests for each detector function
    ├── test_scanner.py     # Integration tests with synthetic node_modules tree
    ├── test_reporter.py    # Report rendering and JSON export tests
    ├── test_npm_utils.py   # Filesystem parsing helper tests
    ├── test_osv_client.py  # OSV client tests (mocked network)
    ├── test_patterns.py    # Pattern database structure and regex tests
    └── fixtures/
        └── fake_project/
            └── package.json  # Fixture with benign and suspicious packages
```

---

## Configuration

All options are available as CLI flags. No config file is required.

| Flag | Default | Description |
|---|---|---|
| `--output` | `terminal` | Report format: `terminal`, `json`, or `html` |
| `--output-file` | _(stdout)_ | File path to write JSON or HTML report |
| `--osv` | `false` | Enrich findings with OSV.dev CVE data |
| `--min-severity` | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical` |

### Examples

```bash
# Only show critical and high findings, enriched with CVE data
npm-shield scan . --osv --min-severity high

# Save a full HTML report
npm-shield scan /my/project --output html --output-file security-report.html

# Print version
npm-shield version
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
