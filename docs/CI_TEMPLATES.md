# Python Hunter — CI/CD Integration & Reporting Templates

This document provides production-ready CI/CD configuration templates and exit code reference documentation for integrating **Python Hunter** into automated security pipelines.

---

## Exit Code Reference

| Exit Code | Meaning | Description |
|:---:|---|---|
| **`0`** | **PASSED** | Scan completed successfully; no policy violations detected. |
| **`1`** | **POLICY FAILED** | Security policy evaluation failed (e.g. Critical finding or risk threshold exceeded). |
| **`2`** | **ANALYSIS ERROR** | Technical scanner failure or unhandled exception during static analysis execution. |
| **`3`** | **CONFIG ERROR** | Policy configuration file parsing or schema validation error (`pyh_policy.yml`). |

---

## 1. GitHub Actions Workflow

Create `.github/workflows/python-hunter.yml` in your repository:

```yaml
name: Python Hunter Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-scan:
    name: Run Python Hunter Scan & Code Scanning SARIF
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Python Hunter
        run: |
          python -m pip install --upgrade pip
          pip install .

      - name: Execute Security Pipeline & Policy Gate
        run: |
          python-hunter ci . --output-dir artifacts

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: artifacts/report.sarif
          category: python-hunter

      - name: Archive Security Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: python-hunter-reports
          path: |
            artifacts/report.json
            artifacts/report.sarif
            artifacts/report.md
```

---

## 2. GitLab CI Configuration

Add the following job to `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

python_hunter_scan:
  stage: security
  image: python:3.11-slim
  script:
    - pip install --upgrade pip
    - pip install .
    - python-hunter ci . --output-dir public
  artifacts:
    when: always
    paths:
      - public/report.json
      - public/report.sarif
      - public/report.md
    reports:
      codequality: public/report.json
```

---

## 3. Generic CI (Jenkins, Azure DevOps)

Run `python-hunter ci .` non-interactively in any CI build shell script:

```bash
#!/usr/bin/env bash
set -e

# Run security analysis and produce report.json, report.sarif, report.md
python-hunter ci ./my-project --output-dir reports

STATUS=$?
if [ $STATUS -eq 0 ]; then
  echo "Security Gate Passed!"
else
  echo "Security Gate Failed with exit code $STATUS!"
  exit $STATUS
fi
```
