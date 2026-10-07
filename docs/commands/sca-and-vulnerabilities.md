# Software Composition Analysis & Vulnerability Intelligence (`dependencies` & `vulnerabilities`)

Python Hunter incorporates an enterprise Software Composition Analysis (SCA) engine that audits open-source dependencies, inspects supply-chain risks, resolves transitive dependency trees, and checks against global vulnerability databases (CVE, OSV, GHSA).

---

## 1. Command: `python-hunter dependencies`

The `dependencies` command analyzes manifest files and lockfiles to detect configuration risks, missing hashes, unpinned releases, and package shadowing.

### Syntax
```bash
python-hunter dependencies [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory or dependency manifest file. |
| `--tree` | Flag | `False` | Render a formatted ASCII dependency graph showing direct and transitive relationships. |
| `--format` | `text`, `json` | `text` | Display format. |

### Supply-Chain Security Rules Evaluated

* **`PYH-DEP-001` (Unpinned Dependencies)**: Flags dependencies declared without exact version pins (`==`).
* **`PYH-DEP-002` (Broad Ranges)**: Detects unbounded operators (`>=`, `*`) that allow automatic upgrades to potentially broken or compromised major versions.
* **`PYH-DEP-003` (Conflicting Requirements)**: Identifies conflicting version requirements between multiple manifests or transitive constraints.
* **`PYH-DEP-004` (Lockfile Synchronization)**: Detects when `requirements.txt` or `pyproject.toml` has changed without updating `poetry.lock` or `Pipfile.lock`.
* **`PYH-SUPPLY-001` (Mutable VCS References)**: Flags Git dependencies referencing mutable branch names (e.g. `@main`, `@master`) instead of immutable commit SHAs.
* **`PYH-SUPPLY-002` (Direct URL Dependencies)**: Flags tarball or wheel URLs downloaded directly without package registry verification.
* **`PYH-SUPPLY-003` (Missing Integrity Hashes)**: Warns when lockfiles do not enforce `--hash` verification for downloaded artifacts.
* **`PYH-SUPPLY-004` (Package Shadowing / Namespace Squatting)**: Detects private internal packages vulnerable to public namespace confusion.
* **`PYH-SUPPLY-005` (Yanked Releases)**: Identifies installed package versions that have been yanked from PyPI/NPM due to critical bugs or malware.

### Example: Visualizing Dependency Trees (`--tree`)
```bash
python-hunter dependencies . --tree
```

Output:
```text
my-service (0.1.0)
├── fastapi (0.115.0) [pinned]
│   ├── pydantic (2.9.2) [pinned]
│   │   ├── annotated-types (0.7.0)
│   │   └── pydantic-core (2.23.4)
│   ├── starlette (0.38.6) [pinned]
│   │   └── anyio (4.4.0)
│   └── typing-extensions (4.12.2)
├── requests (unpinned) [!] WARN: PYH-DEP-001
└── urllib3 (1.25.10) [!] HIGH: CVE-2023-45803
```

---

## 2. Command: `python-hunter vulnerabilities`

The `vulnerabilities` command evaluates installed packages against vulnerability intelligence feeds and evaluates **vulnerability reachability**.

### Syntax
```bash
python-hunter vulnerabilities [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory or manifest file. |
| `--details` | Flag | `False` | Show full CVE advisories, CVSS v3.1 metrics, affected ranges, and reachability traces. |
| `--offline` | Flag | `False` | Run strictly from local cached vulnerability databases without querying external APIs. |
| `--fail-on` | `critical`, `high`, `medium`, `low` | `high` | Severity threshold triggering non-zero exit code. |
| `--format` | `text`, `json` | `text` | Display format. |

---

## 3. Vulnerability Reachability Analysis

Unlike traditional vulnerability scanners that alert on every CVE present in a lockfile, Python Hunter analyzes the **Abstract Syntax Tree (AST) and Call Graph** to determine if your application actually imports and calls the vulnerable function:

```text
┌─────────────────────────────────────────────────────────────┐
│                 Vulnerability Assessment                    │
├───────────────────┬─────────────────────────────────────────┤
│ Reachable (Active)│ Your code calls the vulnerable method.  │
│                   │ Status: CONFIRMED EXPLOITABLE           │
├───────────────────┼─────────────────────────────────────────┤
│ Unreachable (Dead)│ Library is installed, but vulnerable    │
│                   │ functions are never invoked.            │
│                   │ Status: POTENTIAL / LOW RISK            │
└───────────────────┴─────────────────────────────────────────┘
```

### Example: Checking Detailed Vulnerabilities with Reachability
```bash
python-hunter vulnerabilities . --details
```

Output:
```text
==========================================================
 Python Hunter Vulnerability Intelligence
==========================================================
Target: /home/kayi/Python-hunter
==========================================================

[!] HIGH VULNERABILITY (PYH-VULN-001)
    Package     : urllib3 (version: 1.25.10)
    CVE ID      : CVE-2023-45803 (GHSA-g4mx-q9vg-27p4)
    CVSS Score  : 7.5 (High)
    Reachability: CONFIRMED REACHABLE
    Trace       : src/api/client.py:24 -> urllib3.util.parse_url()
    Fixed In    : >= 1.26.19
    Description : Proxy-Authorization header leakage in cross-origin redirects.

Summary: 1 confirmed reachable vulnerability detected.
```
