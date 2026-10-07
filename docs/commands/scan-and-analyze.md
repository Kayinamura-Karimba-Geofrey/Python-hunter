# Unified Security Scan & Analysis (`scan` & `analyze`)

The `scan` and `analyze` commands constitute the core multi-domain security evaluation pipeline of **Python Hunter**. They aggregate static application security testing (SAST), taint dataflow analysis, secret leak detection, Software Composition Analysis (SCA), and malware heuristics into a unified execution.

---

## 1. Overview & Comparison

| Command | Primary Use Case | Output Archetypes |
| :--- | :--- | :--- |
| `python-hunter scan` | High-level unified security pipeline with auto-remediation, remote Git cloning, and compliance exports. | Terminal, SARIF 2.1.0, CycloneDX, SPDX, JSON, Markdown, HTML, CSV. |
| `python-hunter analyze` | Fine-grained analytical engine with interprocedural taint tracing, rule filtering, callgraph depth tuning, and evidence proofs. | Terminal, JSON, SARIF, Markdown, HTML, CSV. |

---

## 2. Command: `python-hunter scan`

### Syntax
```bash
python-hunter scan [TARGET] [OPTIONS]
```

### Key Arguments & Options

| Option | Type / Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target local directory, single file, or remote Git URL (HTTP/HTTPS/SSH). |
| `--branch` | String | `""` | Git branch to clone and scan for remote repositories. |
| `--commit` | String | `""` | Specific Git commit SHA to checkout and audit. |
| `--format` | `terminal`, `json`, `sarif`, `markdown`, `html`, `csv`, `cyclonedx`, `spdx` | `terminal` | Export format. |
| `-o`, `--output` | File path | `stdout` | Write output to designated file path. |
| `--fail-on` | `critical`, `high`, `medium`, `low` | `high` | Severity threshold triggering non-zero exit code (for CI/CD gating). |
| `--ci` | Flag | `False` | Optimized CI execution mode (disables interactive spinners, emits clean summary). |
| `--clean` | Flag | `False` | Automatically disinfect detected malware threats (e.g. PolinRider / TasksJacker). |
| `--no-secrets` | Flag | `False` | Skip credential and entropy scanning. |
| `--no-dependencies`| Flag | `False` | Skip dependency manifest auditing and vulnerability matching. |
| `--offline` | Flag | `False` | Strictly offline execution (no external OSV/PyPI advisory lookups). |
| `--timeout` | Integer (seconds) | `None` | Total wall-clock timeout for remote Git clone operations. |
| `--idle-timeout` | Integer (seconds) | `45` | Abort stalled Git clones if no data is received within this window. |

### Practical Examples

#### 1. Local Workspace Scan
```bash
python-hunter scan .
```

#### 2. Remote GitHub Repository Scan with Custom Branch
```bash
python-hunter scan https://github.com/org/microservice.git --branch staging
```

#### 3. GitHub Code Scanning CI Integration (SARIF)
```bash
python-hunter scan . --ci --format sarif -o results.sarif --fail-on high
```

#### 4. Scan and Auto-Clean Malware in One Pass
```bash
python-hunter scan . --clean
```

---

## 3. Command: `python-hunter analyze`

The `analyze` command exposes low-level analyzer flags to control interprocedural taint propagation, callgraph recursion, and granular finding filters.

### Syntax
```bash
python-hunter analyze [TARGET] [OPTIONS]
```

### Advanced Analysis Options

| Option | Type / Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `--severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | `None` | Filter findings by minimum severity level. |
| `--category` | String | `None` | Filter by category (e.g. `INJECTION`, `SECRETS`, `MALWARE`, `SUPPLY_CHAIN`). |
| `--confidence` | `HIGH`, `MEDIUM`, `LOW` | `None` | Filter findings by detection confidence. |
| `--status` | `NEW`, `EXISTING`, `RESOLVED`, `REOPENED` | `None` | Filter findings by lifecycle tracking state. |
| `--details` | Flag | `False` | Print full code snippets, exploitability evidence, and remediation advice. |
| `--explain-flow` | Flag | `False` | Print step-by-step interprocedural dataflow propagation trace. |
| `--show-trace` | Flag | `False` | Print exact Source -> Intermediate Variables -> Sink call chain. |
| `--analysis-depth` | Integer | `10` | Maximum interprocedural call graph search depth. |
| `--max-paths` | Integer | `100` | Maximum interprocedural dataflow paths to explore per entrypoint. |
| `--dependencies` | Flag | `False` | Enable Software Composition Analysis (SCA) dependency checks. |
| `--dependencies-tree` | Flag | `False` | Print resolved ASCII dependency tree. |
| `--vulnerabilities`| Flag | `False` | Include matched CVE/GHSA advisories and reachability notes. |
| `--no-redact` | Flag | `False` | Disable automatic secret credential masking in output. |

### Advanced Examples

#### 1. Trace High-Severity Injections with Interprocedural Dataflow
```bash
python-hunter analyze . --severity HIGH --category INJECTION --show-trace --explain-flow
```

#### 2. Deep Interprocedural Callgraph Analysis
```bash
python-hunter analyze src/ --analysis-depth 15 --max-paths 250 --details
```

#### 3. Export Findings to Filterable JSON
```bash
python-hunter analyze . --format json -o audit-findings.json --details
```

---

## 4. Policy Engine & Exit Codes

Python Hunter integrates an automated policy engine to govern build and deployment pipelines:

| Exit Code | Meaning |
| :--- | :--- |
| `0` | **Success / Pass**: No findings matched or exceeded the `--fail-on` threshold. |
| `1` | **Security Failure**: One or more findings met or exceeded the threshold (e.g., HIGH or CRITICAL findings detected). |
| `2` | **Runtime / Configuration Error**: Invalid arguments, corrupted repository target, or unrecoverable scanner crash. |

### Threshold Configuration
```bash
# Strictly fail only on verified CRITICAL issues:
python-hunter scan . --fail-on critical

# Block builds on MEDIUM, HIGH, or CRITICAL vulnerabilities:
python-hunter scan . --fail-on medium
```
