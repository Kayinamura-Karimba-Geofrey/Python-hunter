# CI/CD Quality Gate & Baseline Management (`ci`, `gate`, `baseline`, `diff`)

Python Hunter provides built-in mechanisms to gate CI/CD pipelines, prevent security regressions, and manage technical debt via cryptographic finding baselines.

---

## 1. Command: `python-hunter ci`

The `ci` command executes an automated, non-interactive security scan designed specifically for CI/CD pipeline workers. It generates standard build artifacts and evaluates failure criteria.

### Syntax
```bash
python-hunter ci [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory. |
| `--output-dir` | Directory path | `.` | Directory to save generated build artifacts. |
| `--no-artifacts` | Flag | `False` | Disable automated export of artifact files. |
| `--quiet` | Flag | `False` | Suppress banners; emit concise status summary only. |
| `--verbose` | Flag | `False` | Include analyzer timing and health metrics. |
| `--no-redact` | Flag | `False` | Disable automatic secret masking in output files. |

### Generated Artifacts
When executed, `ci` automatically exports three standard files to `--output-dir`:
1. **`report.sarif`**: SARIF 2.1.0 payload for native ingestion by GitHub Code Scanning / GitLab SAST.
2. **`report.md`**: Markdown summary for step summaries or PR comments.
3. **`report.json`**: Complete structured JSON telemetry for SIEM and security data lakes.

---

## 2. Command: `python-hunter gate`

The `gate` command evaluates your repository against predefined organizational security policies and rules:

```bash
python-hunter gate .
```

* **Policy Checks**:
  * No `CRITICAL` findings allowed under any circumstance.
  * No `HIGH` severity findings on default branch (`main` / `master`).
  * No active malware artifacts (e.g. PolinRider / TasksJacker).
  * No unredacted plaintext credentials.
* **Exit Code**: Returns `0` if all gate policies pass; returns `1` if any rule is violated.

---

## 3. Baseline Snapshots & Debt Management (`baseline` & `diff`)

### The Tech Debt Problem
In mature or legacy repositories, introducing a security scanner often surfaces hundreds of existing low/medium findings. Failing the CI build immediately frustrates developers and stops deployment velocity.

### The Baseline Solution
Python Hunter allows you to snapshot current findings as an accepted **baseline**. Future CI runs will only fail if **new** vulnerabilities are introduced.

### Creating a Baseline Snapshot
```bash
python-hunter baseline create . --output pyh_baseline.json
```

Commit `pyh_baseline.json` into your Git repository:
```bash
git add pyh_baseline.json
git commit -m "chore(security): initialize Python Hunter security baseline"
```

### Running Scan Against Baseline
During CI runs, pass the baseline file to evaluate only new findings:
```bash
python-hunter scan . --baseline pyh_baseline.json --fail-on high
```
* **Existing Issues in Baseline**: Tracked as `EXISTING` (do not fail the build).
* **Newly Introduced Issues**: Flagged as `NEW` (fail the build if severity >= threshold).
* **Resolved Issues**: Marked as `RESOLVED`.

---

## 4. Comparing Scans (`diff`)

To inspect what changed between two security audit runs (e.g. comparing the main branch scan against a pull request branch scan):

```bash
python-hunter diff baseline_scan.json pr_scan.json
```

Output:
```text
=== Python Hunter Scan Differential ===
New Findings Introduced : 2
  + [HIGH] PYH-TAINT-SQL-001 (src/api/users.py:42)
  + [MED]  PYH-AST-005 (utils/runner.py:12)

Findings Resolved        : 1
  - [CRITICAL] PYH-SEC-AWS-001 (config/aws.py:10)

Unchanged (Persistent)  : 14
```

---

## 5. Complete GitHub Actions Workflow Example

Save this to `.github/workflows/security.yml`:

```yaml
name: Python Hunter Security Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python Hunter
        run: pip install -e .

      - name: Run CI Security Suite
        run: |
          python-hunter ci . --output-dir artifacts

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: artifacts/report.sarif

      - name: Publish Markdown Summary
        if: always()
        run: cat artifacts/report.md >> $GITHUB_STEP_SUMMARY
```
