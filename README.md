# Python Hunter

**Enterprise Security, Malware Disinfection, Supply-Chain & Code Intelligence Platform**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests: 366 Passing](https://img.shields.io/badge/tests-366%20passing-brightgreen.svg)]()
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: MyPy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)
[![SARIF Compliant](https://img.shields.io/badge/SARIF-v2.1.0-blueviolet.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CycloneDX 1.5](https://img.shields.io/badge/CycloneDX-v1.5-blue.svg)](https://cyclonedx.org/)
[![SPDX 2.3](https://img.shields.io/badge/SPDX-v2.3-orange.svg)](https://spdx.dev/)
[![LSP 3.17](https://img.shields.io/badge/LSP-v3.17-blue.svg)](https://microsoft.github.io/language-server-protocol/)

---

## Overview

**Python Hunter** is an enterprise-grade Application Security & Code Intelligence Platform designed to protect repositories from malware campaigns, malicious package hooks, software supply-chain attacks, hardcoded secrets, software vulnerabilities, and compliance regressions.

Operating as a unified local CLI engine, a CI/CD security gatekeeper, a Language Server (LSP) for VS Code / JetBrains, and a multi-tenant REST service, Python Hunter consolidates **SAST, Secrets Detection, Software Composition Analysis (SCA), Malware Disinfection, and Enterprise SBOM Generation** into a seamless workflow.

---

## Key Capabilities

* **Unified Multi-Domain Pipeline (`python-hunter scan`):** Single-command security execution aggregating AST dataflow analysis, PolinRider / TasksJacker malware detection, secret leak scanning, and open-source dependency auditing.
* **Automated Dependency Vulnerability Fixes & Version Bumping (`python-hunter fix`):** Automatically upgrades vulnerable, unpinned, or compromised dependency versions across `requirements.txt`, `pyproject.toml`, and `package.json`, complete with `--create-pr` GitHub automation.
* **Interactive Terminal TUI Dashboard (`python-hunter tui`):** Rich curses-based terminal UI with keyboard navigation to inspect findings across domains (All, Malware, Secrets, Supply-Chain, SAST), examine exploitability evidence, and explore dependency risk scores.
* **Real-Time IDE Integrations (VS Code & JetBrains LSP 3.17):** Dedicated Language Server Protocol daemon (`python-hunter lsp`) and compiler diagnostics CLI (`python-hunter diagnostics`) powering real-time red squiggles, inline hovers, and one-click quick fixes.
* **Targeted Malware Disinfection (`python-hunter clean`):** Automated eradication of DPRK/PolinRider malware campaigns (sanitizing `.vscode/tasks.json`, deleting trojanized font binaries, neutralizing batch wipers, and restoring `.gitignore`).
* **Automated Remediation Pull Requests (`--create-pr`):** Clones remote Git repositories, cleans active threats, commits patches, and opens a GitHub Remediation PR automatically.
* **NPM & PyPI Supply-Chain Security:** Static AST inspection for dangerous `setup.py` `cmdclass` hooks, import-time process execution, dynamic base64/hex dynamic evaluation, C2 exfiltration webhooks, and typosquatting detection across ecosystems.
* **Enterprise SBOM Generation (`python-hunter sbom`):** Produces canonical **CycloneDX 1.5 JSON** and **SPDX 2.3 JSON** Software Bill of Materials with package URLs (`purl`), dependency DAGs, hashes, and embedded vulnerability telemetry.
* **Executive & Compliance Security Reporting (`python-hunter report`):** Generates standalone interactive HTML dashboards, Markdown summaries, and JSON audit packages with OWASP Top 10 compliance grades (A–F) and prioritized remediation roadmaps.
* **Universal CI/CD Export Standards:** Native support for **SARIF v2.1.0** (GitHub Code Scanning), CycloneDX 1.5, SPDX 2.3, HTML, Markdown, and CSV.

---

## Architecture

Python Hunter adheres strictly to **Clean Architecture** and **Domain-Driven Design (DDD)**:

```
src/python_hunter/
├── domain/                    # Pure Domain Models, Entities & Rules
│   ├── malware/               # PolinRider / TasksJacker detection & cleaners
│   ├── dependencies/          # SCA, semver, lockfiles, npm & pypi supply chain
│   │   └── sbom/              # CycloneDX 1.5, SPDX 2.3, PURL generators
│   ├── secrets/               # Entropy, regex patterns, placeholder filter
│   ├── ast/                   # AST visitor, sink detectors, taint analysis
│   ├── compliance/            # Frameworks (OWASP, NIST, CIS, SOC 2, ISO 27001)
│   └── reporting/             # Risk scoring, dashboard snapshot, metrics
├── application/               # Orchestration & Use Cases
│   ├── orchestrator/          # ScanOrchestrator (unified multi-domain pipeline)
│   └── use_cases/             # GenerateSBOM, GenerateReport, AnalyzeSecrets...
├── infrastructure/            # Git watchdog, repo cloning, parser engines
├── interfaces/cli/            # CLI Commands (scan, clean, sbom, report...)
└── presentation/              # Renderers (SARIF, CycloneDX, SPDX, HTML, CSV)
```

---

## Quickstart

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/python-hunter.git
cd python-hunter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## CLI Usage & Commands

### 1. Unified Security Scan (All-in-One: SAST + Secrets + SCA + Malware)
Run a unified scan on a local repository or remote Git URL:
```bash
python-hunter scan .
```

Scan a remote GitHub repository with live progress and watchdog protection:
```bash
python-hunter scan https://github.com/org/repo --branch main
```

Export results to **SARIF 2.1.0** for GitHub Code Scanning:
```bash
python-hunter scan . --ci --format sarif --output python-hunter.sarif --fail-on high
```

Export results to **CycloneDX 1.5** or **SPDX 2.3** directly from scan:
```bash
python-hunter scan . --format cyclonedx -o sbom.json
python-hunter scan . --format spdx -o spdx.json
```

Selective scanning controls:
```bash
python-hunter scan . --no-secrets        # Skip credential scanning
python-hunter scan . --no-dependencies   # Skip dependency rules
python-hunter scan . --offline           # Strictly offline execution
```

---

### 2. Malware Disinfection & Automated PRs
Scan and automatically disinfect detected malware threats:
```bash
python-hunter scan https://github.com/org/repo.git --clean
```

Disinfect an infected repository and open an automated remediation Pull Request:
```bash
python-hunter clean https://github.com/org/infected-repo --create-pr
```

Clean local workspace:
```bash
python-hunter clean .
```

---

### 3. Software Bill of Materials (SBOM) Generation
Generate **CycloneDX 1.5 JSON** SBOM:
```bash
python-hunter sbom . --format cyclonedx -o cyclonedx-sbom.json
```

Generate **SPDX 2.3 JSON** SBOM:
```bash
python-hunter sbom . --format spdx -o spdx-sbom.json
```

Embed matched vulnerability findings directly into the CycloneDX SBOM:
```bash
python-hunter sbom . --format cyclonedx --include-vulns -o sbom-vulns.json
```

---

### 4. Executive Security & Compliance Reporting
Generate an executive HTML dashboard report:
```bash
python-hunter report . --format html -o executive-report.html --organization "Acme Corp"
```

Generate a GitHub-ready Markdown summary:
```bash
python-hunter report . --format markdown -o security-summary.md
```

Benchmark compliance against standard security frameworks:
```bash
# OWASP Top 10 benchmark (default)
python-hunter report . --framework owasp-top-10 --format html -o owasp-report.html

# NIST Cybersecurity Framework benchmark
python-hunter report . --framework nist --format html -o nist-report.html

# SOC 2 Type II benchmark
python-hunter report . --framework soc-2 --format json -o soc2-audit.json
```

---

---

### 5. Automated Dependency Vulnerability Fixes & Version Bumping (`python-hunter fix`)
Automatically detect and bump vulnerable or unpinned dependencies in `requirements.txt`, `pyproject.toml`, and `package.json`:

```bash
# Preview proposed fixes without writing to disk
python-hunter fix . --dry-run

# Apply dependency fixes to workspace
python-hunter fix .

# Only pin unconstrained dependencies
python-hunter fix . --unpinned-only

# Only fix known CVE vulnerabilities
python-hunter fix . --vulns-only

# Commit changes, push remediation branch, and open a GitHub Pull Request
python-hunter fix https://github.com/org/repo --create-pr --branch main
```

---

### 6. Interactive Terminal TUI Dashboard (`python-hunter tui`)
Launch an interactive split-view terminal dashboard with keyboard navigation:

```bash
# Launch interactive curses dashboard
python-hunter tui .

# Headless snapshot output (for CI logs or non-interactive shells)
python-hunter tui . --snapshot
```

**Keyboard Controls**:
* `Tab` / `Left` / `Right`: Switch category tabs (`All`, `Malware`, `Secrets`, `Supply-Chain`, `SAST`)
* `Up` / `Down` / `j` / `k`: Navigate through findings list
* `Enter` / `Space`: Inspect finding evidence and remediation in detail pane
* `r`: Re-scan project workspace
* `q`: Exit dashboard

---

### 7. Real-Time IDE Plugin Integrations (VS Code & JetBrains)

#### Visual Studio Code (`contrib/vscode`)
1. Run Python Hunter as an in-editor Language Server:
   ```bash
   python-hunter lsp --stdio
   ```
2. Or use the turnkey VS Code extension located in [`contrib/vscode`](contrib/vscode/README.md) for inline squiggles and one-click quick fixes.

#### JetBrains (PyCharm / IntelliJ IDEA / WebStorm)
Configure `python-hunter diagnostics` as an **External Tool** or **File Watcher**:
```bash
# Emit compiler-style lint diagnostics for instant jump-to-line navigation
python-hunter diagnostics path/to/file.py --format gcc

# Emit Reviewdog Diagnostic JSON (rdjson)
python-hunter diagnostics . --format rdjson

# Emit GitLab / CodeClimate Quality format
python-hunter diagnostics . --format codeclimate
```
See the complete JetBrains configuration guide in [`contrib/jetbrains/README.md`](contrib/jetbrains/README.md).

---

### 8. Individual Domain Security Subcommands
Audit credentials and secret exposures:
```bash
python-hunter secrets . [--format text|json]
```

Inspect dependency trees and license policies:
```bash
python-hunter dependencies . --tree [--format text|json]
```

Query vulnerability database and CVE advisories:
```bash
python-hunter vulnerabilities . --details [--offline]
```

---

## CI/CD Pipeline Integration

Integrate Python Hunter into GitHub Actions (`.github/workflows/python-hunter.yml`):

```yaml
name: Python Hunter Security Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python Hunter
        run: pip install -e .

      - name: Run Unified Security Scan (SARIF)
        run: |
          python-hunter scan . --ci --format sarif --output results.sarif --fail-on high

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Generate CycloneDX SBOM
        run: |
          python-hunter sbom . --format cyclonedx --include-vulns -o cyclonedx-sbom.json

      - name: Generate Executive HTML Report
        run: |
          python-hunter report . --format html -o security-report.html

      - name: Archive Reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            security-report.html
            cyclonedx-sbom.json
```

---

## Testing & Quality Assurance

Python Hunter maintains a comprehensive automated test suite with **351+ unit tests**:

```bash
# Run full test suite
python3 -m unittest discover -s tests/unit

# Run specific domain test suites
python3 -m unittest tests/unit/test_unified_orchestrator.py
python3 -m unittest tests/unit/test_sbom_generator.py
python3 -m unittest tests/unit/test_report_generator.py
python3 -m unittest tests/unit/test_polinrider_detector.py
python3 -m unittest tests/unit/test_pypi_supply_chain.py
python3 -m unittest tests/unit/test_npm_supply_chain.py
```

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
