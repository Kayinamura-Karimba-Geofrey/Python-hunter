# Executive & Compliance Security Reporting (`report`)

The `report` command compiles multi-domain scan data, vulnerability telemetry, and compliance audits into professional, standalone **HTML dashboards**, **Markdown summaries**, and **JSON audit packages**.

---

## 1. Report Archetypes & Formats

### Archetypes (`--type`)

| Archetype | Target Audience | Primary Focus |
| :--- | :--- | :--- |
| **`executive`** (default) | CTOs, CISOs, Security Leadership | High-level risk score (0–100), letter grade (A–F), domain breakdown (Malware, Secrets, SCA, SAST), executive summary. |
| **`compliance`** | Audit & Compliance Teams, SOC 2 Assessors | Framework-aligned audit mapping (OWASP Top 10, NIST CSF, SOC 2 Type II, ISO 27001, CIS). |
| **`technical`** | Software Engineers, AppSec Analysts | Deep dive with line numbers, code snippets, attack path traces, and exact remediation instructions. |

### Formats (`--format`)

* **`html`**: Standalone, interactive HTML file with embedded styling, charts, collapsible findings, and filterable tables. Requires zero external web assets or CDNs.
* **`markdown`** / **`md`**: Optimized for GitHub Actions Job Summaries, Pull Request descriptions, and documentation repositories.
* **`json`**: Structured audit package suitable for SIEM, Datadog, Splunk, or long-term compliance storage.

---

## 2. Command: `python-hunter report`

### Syntax
```bash
python-hunter report [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory or repository. |
| `--type` | `executive`, `compliance`, `technical` | `executive` | Report archetype. |
| `-f`, `--format` | `html`, `markdown`, `json` | `html` | Output file format. |
| `--framework` | `owasp-top-10`, `nist`, `soc-2`, `iso27001`, `cis` | `owasp-top-10` | Compliance framework benchmark. |
| `-o`, `--output` | File path | *(derived or stdout)* | Output destination path. |
| `--organization`| String | `Enterprise Security` | Company, organization, or team name rendered in report banner. |
| `--title` | String | `None` | Custom report title. |

---

## 3. Risk Scoring & Letter Grade Rubric

Python Hunter calculates a deterministic **Security Health Score (0–100)**:

$$\text{Base Score} = 100$$
$$\text{Deductions} = (N_{\text{Critical}} \times 25) + (N_{\text{High}} \times 15) + (N_{\text{Medium}} \times 5) + (N_{\text{Low}} \times 1)$$
$$\text{Final Score} = \max(0, \text{Base Score} - \text{Deductions})$$

| Grade | Score Range | Posture Assessment |
| :---: | :---: | :--- |
| **A** | 90 – 100 | **Excellent**: No critical or high risks; minimal low-severity advisory findings. |
| **B** | 80 – 89 | **Good**: Repository contains moderate issues, but no verified critical threats. |
| **C** | 70 – 79 | **Fair**: Multiple medium-severity issues or a single unmitigated high-risk finding. |
| **D** | 60 – 69 | **Poor**: High concentration of vulnerabilities or compromised dependency pins. |
| **F** | < 60 | **Failing**: Active malware campaigns, exposed plaintext credentials, or critical RCE flaws detected. |

---

## 4. Usage Examples

### Example 1: Generate Standalone Interactive HTML Report
```bash
python-hunter report . \
  --format html \
  --organization "Acme Financial Services" \
  --title "Q3 Production Security Audit" \
  -o executive-security-report.html
```

Features included in the generated HTML dashboard:
* **Interactive Summary Cards**: Total findings, Critical/High counts, Security Score, and Letter Grade.
* **Domain Distribution**: SAST vs. Secrets vs. Supply-Chain vs. Malware breakdowns.
* **Prioritized Remediation Roadmap**: Ranked table detailing highest ROI fixes.
* **Full Finding Inspector**: Expandable drawers showing source code context, file paths, and rule identifiers.

### Example 2: Benchmark Against OWASP Top 10 (2021)
```bash
python-hunter report . \
  --type compliance \
  --framework owasp-top-10 \
  --format html \
  -o owasp-compliance.html
```
The report groups findings across the 10 standard categories:
* `A01:2021` - Broken Access Control
* `A02:2021` - Cryptographic Failures
* `A03:2021` - Injection (SQLi, Command, SSRF)
* `A05:2021` - Security Misconfiguration
* `A06:2021` - Vulnerable and Outdated Components

### Example 3: Generate GitHub Actions Markdown Summary
```bash
python-hunter report . \
  --format markdown \
  -o $GITHUB_STEP_SUMMARY
```

Rendered Markdown summary includes:
* Security score header and grade badge.
* Table of critical findings with file hyperlinks.
* Suggested CLI auto-fix commands.
