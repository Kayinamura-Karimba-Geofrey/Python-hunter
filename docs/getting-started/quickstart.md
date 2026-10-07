# Quickstart Guide

This guide walks you through the most common security workflows in **Python Hunter** in under 5 minutes.

---

## 1. Run a Unified Security Scan

To run a complete, multi-domain scan (SAST, Secrets, Dependencies/SCA, Malware, Taint Analysis) on your current directory:

```bash
python-hunter scan .
```

You can also target specific files or subdirectories:

```bash
python-hunter scan src/my_service/
```

### Scanning Remote GitHub Repositories
Python Hunter can clone, isolate, and scan remote repositories directly in an ephemeral sandbox without manual downloading:

```bash
python-hunter scan https://github.com/org/repo --branch main
```

---

## 2. Inspect Scan Results Interactively with the TUI

Instead of scrolling through terminal logs, launch the interactive curses-based Terminal User Interface:

```bash
python-hunter tui .
```

* **Navigation**: Use `Up` / `Down` (or `j` / `k`) to browse findings.
* **Categories**: Press `Tab` or `Left` / `Right` to switch between `All`, `Malware`, `Secrets`, `Supply-Chain`, and `SAST`.
* **Details Pane**: Press `Enter` or `Space` to inspect the source file, code snippet, attack path, and recommended remediation.
* **Quit**: Press `q`.

---

## 3. Export to CI/CD & Compliance Formats

Python Hunter produces industry-standard outputs for GitHub Code Scanning, SBOM compliance, and executive review:

```bash
# 1. GitHub Code Scanning (SARIF v2.1.0)
python-hunter scan . --format sarif -o results.sarif

# 2. Executive HTML Security Dashboard
python-hunter report . --format html -o security-report.html --organization "My Team"

# 3. CycloneDX 1.5 Software Bill of Materials (SBOM) with Vulnerabilities
python-hunter sbom . --format cyclonedx --include-vulns -o cyclonedx-sbom.json

# 4. SPDX 2.3 JSON Software Bill of Materials
python-hunter sbom . --format spdx -o spdx-sbom.json

# 5. Developer Markdown Summary
python-hunter report . --format markdown -o report.md
```

---

## 4. Automatically Fix Vulnerable Dependencies

When Python Hunter identifies vulnerable or unpinned packages in `requirements.txt`, `pyproject.toml`, or `package.json`, use the `fix` command to upgrade them safely:

```bash
# Preview proposed version bumps without changing files
python-hunter fix . --dry-run

# Apply version updates to your workspace
python-hunter fix .

# Open an automated GitHub Remediation Pull Request directly
python-hunter fix https://github.com/org/repo --create-pr --branch main
```

---

## 5. Disinfect Malware Artifacts

If your repository has been targeted by VS Code task-jacking or DPRK PolinRider malware campaigns:

```bash
# Disinfect local workspace (sanitizes tasks.json, removes droppers, restores .gitignore)
python-hunter clean .

# Scan and disinfect in a single pass
python-hunter scan . --clean
```

---

## 6. What's Next?

Dive deeper into Python Hunter's dedicated functional guides:
* [Unified Security Scan & Analysis](../commands/scan-and-analyze.md)
* [Targeted Malware Disinfection](../commands/malware-disinfection.md)
* [Software Bill of Materials (SBOM)](../commands/sbom.md)
* [Executive & Compliance Reporting](../commands/reporting.md)
* [Automated Dependency Fixes](../commands/dependency-fixes.md)
* [IDE Integrations (VS Code & JetBrains)](../commands/lsp-and-diagnostics.md)
