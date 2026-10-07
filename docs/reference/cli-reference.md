# CLI Command Reference Cheat Sheet

This document provides a quick reference for every command, argument, and flag available in the **Python Hunter** CLI.

---

## Master Command Index

| Command | Category | Summary |
| :--- | :--- | :--- |
| [`scan`](../commands/scan-and-analyze.md) | Pipeline | Unified multi-domain scan (SAST, Secrets, SCA, Malware). |
| [`analyze`](../commands/scan-and-analyze.md) | Engine | Fine-grained analytical engine with dataflow traces. |
| [`clean`](../commands/malware-disinfection.md) | Remediation | Targeted malware disinfection & automated PRs. |
| [`sbom`](../commands/sbom.md) | Compliance | Generate CycloneDX 1.5 and SPDX 2.3 SBOMs. |
| [`report`](../commands/reporting.md) | Reporting | Executive, compliance, and developer reports (HTML/MD/JSON). |
| [`fix`](../commands/dependency-fixes.md) | Remediation | Automated dependency upgrading and version bumping. |
| [`tui`](../commands/tui.md) | Interactive | Terminal curses dashboard with findings inspector. |
| [`lsp`](../commands/lsp-and-diagnostics.md) | IDE | Language Server Protocol (LSP 3.17) daemon. |
| [`diagnostics`](../commands/lsp-and-diagnostics.md) | IDE / Linter | Compiler-style diagnostics (GCC, RDJSON, CodeClimate). |
| [`secrets`](../commands/secrets-hunting.md) | Credential | Credential and secret leak scanning. |
| [`dependencies`](../commands/sca-and-vulnerabilities.md) | SCA | Dependency manifests and ASCII tree auditing. |
| [`vulnerabilities`](../commands/sca-and-vulnerabilities.md) | Intelligence | CVE/OSV advisory lookups with reachability checks. |
| [`taint`](../commands/taint-and-callgraph.md) | Static Dataflow | Interprocedural taint propagation analysis. |
| [`callgraph`](../commands/taint-and-callgraph.md) | Control Flow | Interprocedural Call Graph & CFG generator. |
| [`attack-paths`](../commands/taint-and-callgraph.md) | Threat Intel | End-to-end exploit path graph construction. |
| [`explain`](../commands/taint-and-callgraph.md) | Analytical | Plain-English explanation of vulnerability evidence. |
| [`verify`](../commands/taint-and-callgraph.md) | Verification | Safe exploitability verification testing. |
| [`ci`](../commands/ci-gate-and-baseline.md) | CI/CD | Non-interactive CI scan with artifact generation. |
| [`gate`](../commands/ci-gate-and-baseline.md) | Policy Gate | Evaluate repository against strict gate policies. |
| [`baseline`](../commands/ci-gate-and-baseline.md) | Tech Debt | Create cryptographic snapshot of accepted findings. |
| [`diff`](../commands/ci-gate-and-baseline.md) | Comparison | Compare two JSON scan outputs to see new/resolved issues. |
| [`github`](../commands/github-and-governance.md) | Integration | Manage GitHub App connection, repositories, and PRs. |
| [`rules`](../core-engines/rules-catalog.md) | Taxonomy | List and view details of registered security rules. |
| [`discover`](../commands/scan-and-analyze.md) | Discovery | Detect and classify Python project modules and structure. |
| [`config`](configuration.md) | System | Validate and print current active settings. |
| `version` | System | Print Python Hunter version and Python runtime. |

---

## Detailed Flag Quick Reference

### Pipeline & Scanning
```bash
# Scan with SARIF output and fail if HIGH or CRITICAL issues exist:
python-hunter scan . --ci --format sarif -o results.sarif --fail-on high

# Scan remote repository with branch selection and custom timeout:
python-hunter scan https://github.com/org/repo --branch main --timeout 120

# Scan skipping secrets and dependencies:
python-hunter scan . --no-secrets --no-dependencies --offline
```

### Remediation & Cleaners
```bash
# Clean PolinRider / TasksJacker and open a GitHub PR:
python-hunter clean https://github.com/org/repo --create-pr --branch main

# Preview dependency fixes without touching disk:
python-hunter fix . --dry-run

# Upgrade only packages matching known vulnerabilities:
python-hunter fix . --vulns-only
```

### SBOM & Compliance
```bash
# CycloneDX 1.5 with embedded vulnerability telemetry:
python-hunter sbom . --format cyclonedx --include-vulns -o cyclonedx-sbom.json

# SPDX 2.3 JSON:
python-hunter sbom . --format spdx -o spdx-sbom.json

# OWASP Top 10 Executive HTML Report:
python-hunter report . --format html --framework owasp-top-10 -o report.html
```

### IDE & Linters
```bash
# Start Language Server over standard input/output:
python-hunter lsp --stdio

# Emit GCC compiler diagnostics for JetBrains / PyCharm External Tools:
python-hunter diagnostics src/ --format gcc

# Emit Reviewdog diagnostic format for CI bots:
python-hunter diagnostics . --format rdjson
```

---

## Standard Exit Codes

| Code | Status | Description |
| :---: | :--- | :--- |
| `0` | **Success** | Scan completed successfully with no policy-violating findings. |
| `1` | **Security Failure** | One or more findings met or exceeded the `--fail-on` threshold. |
| `2` | **System / Syntax Error** | Command-line parsing error, missing target file, or unrecoverable error. |
