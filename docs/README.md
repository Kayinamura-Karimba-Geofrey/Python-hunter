# Python Hunter Documentation Hub

Welcome to the comprehensive technical documentation suite for **Python Hunter** — an enterprise-grade Application Security, Malware Disinfection, Software Supply-Chain, and Code Intelligence Platform.

---

## Documentation Navigation

```
docs/
├── README.md                                  # You are here
├── getting-started/
│   ├── installation.md                        # Prerequisites, Virtual Env, Dependencies, Verification
│   └── quickstart.md                          # First scan, CLI overview, Common Workflows
├── commands/
│   ├── scan-and-analyze.md                    # python-hunter scan & analyze (Full SAST, SCA, Secrets, Malware)
│   ├── malware-disinfection.md                # python-hunter clean (PolinRider, TasksJacker, Remediation PRs)
│   ├── sbom.md                                # python-hunter sbom (CycloneDX 1.5, SPDX 2.3, PURL, Vulns)
│   ├── reporting.md                           # python-hunter report (HTML, Markdown, JSON, OWASP, NIST, SOC2)
│   ├── dependency-fixes.md                    # python-hunter fix (Automated bumps, pin rules, PR generation)
│   ├── tui.md                                 # python-hunter tui (Terminal Dashboard, Keybindings, Inspector)
│   ├── lsp-and-diagnostics.md                 # python-hunter lsp & diagnostics (VS Code, JetBrains, GCC, RDJSON)
│   ├── secrets-hunting.md                     # python-hunter secrets (Active vs Git history, Entropy, Redaction)
│   ├── sca-and-vulnerabilities.md             # python-hunter dependencies & vulnerabilities (Graph, Advisories)
│   ├── taint-and-callgraph.md                 # python-hunter taint, callgraph & attack-paths
│   ├── ci-gate-and-baseline.md                # python-hunter ci, gate, baseline & diff
│   └── github-and-governance.md               # python-hunter github, governance, operations, integrations
├── core-engines/
│   ├── sast-and-ast.md                        # AST visitors, sink detectors, concurrency, dynamic execution
│   └── rules-catalog.md                       # Complete catalog of security rules and IDs
├── integration/
│   ├── ci-cd.md                               # GitHub Actions, GitLab CI, Jenkins, Azure DevOps
│   ├── ide-vscode-jetbrains.md                # Language Server Protocol, Extension configs, File Watchers
│   └── github-app.md                          # Webhooks, PR review automation, JWT tokens
├── reference/
│   ├── cli-reference.md                       # Comprehensive CLI cheat sheet with all flags and parameters
│   └── configuration.md                       # Environment variables (.env), settings, rule configs
├── architecture/
│   ├── current.md                             # Current Architecture Document & In-Memory Analysis
│   ├── target.md                              # Target Architecture (Redis, Celery, PostgreSQL, S3)
│   └── capacity.md                            # Capacity Planning & Scalability Targets
└── operations/
    └── runbook.md                             # Production Runbook, Incident Response & Observability
```

---

## 1. Getting Started

* **[Installation Guide](getting-started/installation.md)**: System prerequisites (Python 3.12+), virtual environment creation, editable development installations, and verifying your installation.
* **[Quickstart Guide](getting-started/quickstart.md)**: Run your first security scan, launch the interactive TUI, generate reports, and fix vulnerable packages in under 5 minutes.

---

## 2. Functionality & Command Guides

Detailed technical specifications and usage examples for every Python Hunter CLI command:

* **[Unified Security Scan & Analysis](commands/scan-and-analyze.md)**: Single-command multi-domain pipeline (`scan` & `analyze`), local vs. remote Git cloning, watchdog timeout controls, and output format choices (Terminal, SARIF, CycloneDX, SPDX, JSON, Markdown, HTML, CSV).
* **[Targeted Malware Disinfection](commands/malware-disinfection.md)**: Automated eradication of PolinRider and TasksJacker malware (`clean`), sanitizing `.vscode/tasks.json`, deleting trojanized font binaries and dropper scripts, and automated GitHub Remediation PRs (`--create-pr`).
* **[Software Bill of Materials (SBOM)](commands/sbom.md)**: Generating canonical **CycloneDX 1.5 JSON** and **SPDX 2.3 JSON** documents (`sbom`) with Package URLs (`purl`), dependency DAGs, cryptographic hashes, and embedded vulnerability findings.
* **[Executive & Compliance Reporting](commands/reporting.md)**: Generating standalone interactive HTML dashboards, Markdown summaries, and JSON audit packages (`report`) with OWASP Top 10, NIST CSF, and SOC 2 Type II compliance benchmarks and A–F letter grades.
* **[Automated Dependency Fixes](commands/dependency-fixes.md)**: Automatically upgrading and pinning vulnerable dependencies (`fix`) across `requirements.txt`, `pyproject.toml`, and `package.json`, complete with dry-run previews and `--create-pr` automation.
* **[Interactive Terminal TUI Dashboard](commands/tui.md)**: Rich terminal curses dashboard (`tui`) featuring split-view finding inspection, keyboard navigation across domains, and headless `--snapshot` mode.
* **[IDE Diagnostics & Language Server Protocol](commands/lsp-and-diagnostics.md)**: Real-time red squiggles, hover popups, and quick-fixes via Language Server Protocol daemon (`lsp`), plus compiler diagnostics (`diagnostics`) in GCC, RDJSON (Reviewdog), and CodeClimate formats.
* **[Credential & Secret Leak Hunting](commands/secrets-hunting.md)**: Shannon entropy analysis, 50+ service pattern matchers, placeholder whitelisting, and automatic secret redaction (`secrets`) across files and Git commit history.
* **[Software Composition Analysis (SCA) & Vulnerabilities](commands/sca-and-vulnerabilities.md)**: Dependency manifest parsing, ASCII dependency graph trees (`dependencies --tree`), and vulnerability intelligence with reachability analysis (`vulnerabilities`).
* **[Taint Analysis, Call Graphs & Attack Paths](commands/taint-and-callgraph.md)**: Interprocedural taint dataflow engine (`taint`), call graph generator (`callgraph`), attack path modeling (`attack-paths`), finding evidence explanation (`explain`), and safe verification testing (`verify`).
* **[CI/CD Quality Gate & Baseline Management](commands/ci-gate-and-baseline.md)**: Non-interactive CI scan runner (`ci`), policy gate evaluation (`gate`), cryptographic baseline snapshots (`baseline`), and scan comparison diffs (`diff`).
* **[GitHub App & Enterprise Governance](commands/github-and-governance.md)**: GitHub App webhook listener (`github`), multi-tenancy and RBAC governance (`governance`), continuous monitoring runbooks (`operations`), and enterprise tool integrations (`integrations`).

---

## 3. Core Engine Deep Dives

* **[SAST & AST Security Engine](core-engines/sast-and-ast.md)**: How Python Hunter parses Python source code without executing it, AST node visitor architecture, command injection sinks, unsafe deserialization (pickle, yaml), concurrency/TOCTOU analysis, and framework-specific rules (FastAPI, Django, Flask).
* **[Security Rules Catalog & Taxonomy](core-engines/rules-catalog.md)**: Complete catalog of all implemented security rule identifiers (`PYH-AST-*`, `PYH-TAINT-*`, `PYH-DEP-*`, `PYH-MAL-*`, `PYH-GIT-*`, `PYH-WEB-*`, `PYH-CONC-*`), severities, and CWE mappings.

---

## 4. Integration Guides

* **[CI/CD Pipeline Integration Templates](integration/ci-cd.md)**: Drop-in configuration templates for GitHub Actions, GitLab CI/CD, Jenkins, and Azure DevOps.
* **[IDE Integrations (VS Code & JetBrains)](integration/ide-vscode-jetbrains.md)**: Step-by-step setup guides for VS Code (LSP), JetBrains PyCharm/IntelliJ (External Tools & File Watchers), and Neovim (`nvim-lspconfig`).
* **[GitHub App Platform Setup](integration/github-app.md)**: Registering the GitHub App, configuring webhook listeners, private keys, and automated PR review checks.

---

## 5. Reference & Architecture

* **[CLI Command Reference](reference/cli-reference.md)**: Quick-reference cheat sheet for all commands, arguments, flags, and exit codes.
* **[Centralized Configuration Reference](reference/configuration.md)**: Environment variables (`PYH_APP_ENV`, `PYH_SECRET_KEY`, `PYH_LOG_LEVEL`), `.env` configuration, and scan engine limit controls.
* **[Current Architecture Document](architecture/current.md)**: In-depth technical breakdown of current in-memory components and architecture diagrams.
* **[Target Architecture Document](architecture/target.md)**: Scaled architecture specifications covering Redis, Celery, PostgreSQL, S3, and distributed workers.
* **[Capacity Planning](architecture/capacity.md)**: Resource estimates, throughput benchmarks, and horizontal scaling targets.
* **[Operations Runbook](operations/runbook.md)**: Operational procedures, health checks, metrics, and incident recovery steps.
