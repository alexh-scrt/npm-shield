# npm_shield

**npm_shield** is a CLI security tool that scans Node.js project dependencies for supply chain attack indicators. It analyzes `package.json` and `node_modules` for typosquatting attempts, suspicious MCP server installations, rogue Git hooks, unexpected network access patterns, and credential-harvesting code signatures.

## Features

- **Typosquatting detection** — Compares installed package names against a curated list of popular packages using edit-distance heuristics to catch lookalike packages.
- **Git hook inspection** — Scans `.git/hooks` for injected malicious scripts inserted by `postinstall` lifecycle hooks.
- **Credential harvesting detection** — Uses regex scanning of package source files to identify env-var exfiltration, network beaconing, and secret-harvesting patterns.
- **MCP server and rogue binary detection** — Flags unexpected executables registered in `node_modules/.bin` or packages declaring MCP server entry points.
- **Known-bad package signatures** — Cross-references installed packages against a built-in database of known malicious package names and patterns (including Sandworm-style attack indicators).
- **OSV.dev integration** — Optionally queries the OSV.dev public vulnerability database to enrich findings with CVE information.
- **Structured reports** — Outputs risk reports as rich terminal tables, JSON files, or HTML documents with per-package severity scores and step-by-step remediation advice.

## Installation

```bash
pip install npm_shield
```

Or install from source:

```bash
git clone https://github.com/example/npm_shield.git
cd npm_shield
pip install -e .
```

## Usage

### Basic scan

Run a full scan on your Node.js project directory:

```bash
npm-shield scan /path/to/your/node-project
```

If no path is provided, the current directory is scanned:

```bash
cd /path/to/your/node-project
npm-shield scan
```

### Export results to JSON

```bash
npm-shield scan --output json --output-file report.json
```

### Export results to HTML

```bash
npm-shield scan --output html --output-file report.html
```

### Scan with OSV.dev vulnerability cross-referencing

```bash
npm-shield scan --osv
```

### Show only findings above a severity threshold

```bash
npm-shield scan --min-severity medium
```

Severity levels (ascending): `info`, `low`, `medium`, `high`, `critical`

### Example terminal output

```
╔══════════════════════════════════════════════════════╗
║              npm_shield Security Report              ║
╚══════════════════════════════════════════════════════╝

Project: /home/user/my-app
Scanned: 2024-01-15 10:23:45
Packages analysed: 142

┌─────────────────────────┬──────────────┬──────────┬──────────────────────────────────────────┐
│ Package                 │ Detector     │ Severity │ Description                              │
├─────────────────────────┼──────────────┼──────────┼──────────────────────────────────────────┤
│ lod4sh                  │ Typosquatting│ HIGH     │ Possible typosquat of 'lodash'           │
│ expres                  │ Typosquatting│ HIGH     │ Possible typosquat of 'express'          │
│ event-stream@3.3.6      │ Known-Bad    │ CRITICAL │ Known malicious version (flatmap-stream) │
│ .git/hooks/post-checkout│ Git Hook     │ HIGH     │ Unexpected hook script injected          │
└─────────────────────────┴──────────────┴──────────┴──────────────────────────────────────────┘

Summary: 4 findings (1 CRITICAL, 2 HIGH, 1 MEDIUM)
```

## Remediation Guidance

### Typosquatting
1. Verify the intended package name in your `package.json`.
2. Remove the suspicious package: `npm uninstall <package-name>`
3. Install the correct package: `npm install <correct-package-name>`
4. Audit your `package-lock.json` for further anomalies.

### Git Hook Injection
1. Inspect the flagged hook file: `cat .git/hooks/<hook-name>`
2. If malicious, remove or restore it: `rm .git/hooks/<hook-name>`
3. Identify the package that injected the hook by reviewing `postinstall` scripts.
4. Remove the offending package and rotate any credentials that may have been exposed.

### Credential Harvesting
1. Review the flagged source file for the specific pattern reported.
2. Immediately rotate any credentials or secrets that may have been accessed.
3. Check your CI/CD environment variables for unexpected access.
4. Remove the offending package and audit its transitive dependencies.

### Known-Bad Packages
1. Immediately uninstall the flagged package: `npm uninstall <package-name>`
2. Check your system for indicators of compromise (unexpected processes, network connections).
3. Review the package's `postinstall` and `preinstall` scripts for executed payloads.
4. Rotate all secrets and credentials accessible from the affected environment.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

## License

MIT
