# Security Rules Taxonomy & Catalog

This catalog documents the security rules implemented across Python Hunter's detection engines. Each rule is mapped to standard **Common Weakness Enumeration (CWE)** identifiers and **OWASP Top 10** categories.

---

## 1. Abstract Syntax Tree (AST) Rules (`PYH-AST`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-AST-001` | Dangerous Code Evaluation (`eval`) | **CRITICAL** | CWE-95 | Direct invocation of `eval()` with dynamic non-literal input. |
| `PYH-AST-002` | Arbitrary Code Execution (`exec`) | **CRITICAL** | CWE-95 | Invocations of `exec()` executing unvalidated code strings. |
| `PYH-AST-003` | Insecure Deserialization (`pickle`) | **CRITICAL** | CWE-502 | Deserialization of unverified data streams via `pickle.loads()`. |
| `PYH-AST-004` | Unsafe YAML Deserialization | **HIGH** | CWE-502 | `yaml.load()` executed without `SafeLoader` or `CSafeLoader`. |
| `PYH-AST-005` | Command Injection (`subprocess`) | **HIGH** | CWE-78 | `subprocess` process execution with `shell=True` and formatted arguments. |
| `PYH-AST-006` | Unsafe XML Parsing (XXE) | **MEDIUM** | CWE-611 | XML entity resolution without disabling external DTD entities. |
| `PYH-AST-007` | Insecure Temporary File Creation | **MEDIUM** | CWE-377 | Usage of `tempfile.mktemp()` vulnerable to symlink race conditions. |
| `PYH-AST-008` | Dynamic Import Manipulation | **HIGH** | CWE-829 | Invocations of `__import__()` with user-influenced module names. |
| `PYH-AST-009` | Hardcoded Credential in AST | **HIGH** | CWE-798 | Plaintext passwords, tokens, or private keys assigned to variables. |
| `PYH-AST-010` | Legacy Shell Process Execution | **HIGH** | CWE-78 | Invocations of `os.system()` or `os.popen()` invoking system shells. |

---

## 2. Static Taint & Dataflow Rules (`PYH-TAINT`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-TAINT-SQL-001` | SQL Injection via Untrusted Input | **CRITICAL** | CWE-89 | Untrusted input flows directly into database query execution sinks. |
| `PYH-TAINT-CMD-001` | Operating System Command Injection | **CRITICAL** | CWE-78 | User-controlled string reaches shell execution sinks without sanitization. |
| `PYH-TAINT-CODE-001`| Remote Code Execution via Tainted Code | **CRITICAL** | CWE-94 | Tainted strings reach dynamic code compilation or evaluation sinks. |
| `PYH-TAINT-PATH-001`| Path Traversal / Arbitrary File Read | **HIGH** | CWE-22 | Unsanitized file paths reaching filesystem read/write operations. |
| `PYH-TAINT-SSRF-001`| Server-Side Request Forgery (SSRF) | **HIGH** | CWE-918 | Unvalidated URLs reaching outbound HTTP request libraries (`requests`, `httpx`). |
| `PYH-TAINT-TEMPLATE-001`| Server-Side Template Injection (SSTI) | **HIGH** | CWE-1336 | User input concatenated into Jinja2/Mako template rendering calls. |

---

## 3. Dependency & Supply-Chain Rules (`PYH-DEP` & `PYH-SUPPLY`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-DEP-001` | Unpinned Dependency Version | **MEDIUM** | CWE-1104 | Package specified without exact version constraint (`==`). |
| `PYH-DEP-002` | Unbounded Version Range | **MEDIUM** | CWE-1104 | Open-ended wildcard or `>=` operator allowing unvetted major upgrades. |
| `PYH-DEP-003` | Conflicting Manifest Dependencies | **HIGH** | CWE-1104 | Conflicting version requirements between project manifests. |
| `PYH-DEP-004` | Lockfile Out-of-Sync | **HIGH** | CWE-1104 | Manifest updated without re-generating lockfiles. |
| `PYH-SUPPLY-001` | Mutable VCS Reference in Dependency | **HIGH** | CWE-829 | Git dependency pointing to branch ref (e.g. `@main`) instead of immutable SHA. |
| `PYH-SUPPLY-002` | Direct URL Dependency Download | **MEDIUM** | CWE-829 | Packages downloaded via raw URLs without hash verification. |
| `PYH-SUPPLY-003` | Missing Package Integrity Hashes | **MEDIUM** | CWE-353 | Lockfile missing cryptographic SHA-256 integrity hashes. |
| `PYH-SUPPLY-004` | Package Shadowing / Namespace Confusion | **HIGH** | CWE-427 | Internal packages susceptible to dependency confusion on public indices. |
| `PYH-SUPPLY-005` | Yanked Package Release | **CRITICAL** | CWE-1104 | Package release officially yanked by registry due to malware or critical flaws. |

---

## 4. Malware & Backdoor Rules (`PYH-MAL`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-MAL-001` | Install-Time Code Execution Hook | **CRITICAL** | CWE-506 | Suspicious process execution inside `setup.py` `cmdclass` or npm `postinstall`. |
| `PYH-MAL-002` | Credential & Environment Exfiltration | **CRITICAL** | CWE-200 | Outbound HTTP requests transmitting environment variables or SSH keys. |
| `PYH-MAL-003` | PolinRider / TasksJacker VS Code Hook | **CRITICAL** | CWE-506 | Malicious auto-run tasks configured in `.vscode/tasks.json`. |
| `PYH-MAL-004` | Trojanized Binary Font Asset | **CRITICAL** | CWE-506 | Encoded executable binaries concealed inside font files. |
| `PYH-MAL-005` | Git Hook Persistence Backdoor | **CRITICAL** | CWE-506 | Malicious commands injected into `.git/hooks/` execution scripts. |

---

## 5. Git Repository & Secret Rules (`PYH-GIT` & `PYH-SEC`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-GIT-001` | Historical Secret in Commit Log | **HIGH** | CWE-798 | Secret credential committed in past git revision. |
| `PYH-GIT-002` | Sensitive File Tracked in Git | **HIGH** | CWE-538 | Private keys (`.pem`, `.id_rsa`), `.env` files committed to repository. |
| `PYH-GIT-003` | Sensitive File Omitted from `.gitignore` | **MEDIUM** | CWE-538 | `.env` or credential files present without entry in `.gitignore`. |
| `PYH-GIT-004` | Embedded Credential in Remote URL | **HIGH** | CWE-798 | Plaintext tokens or passwords embedded in git remote URL. |
| `PYH-GIT-005` | CI/CD Workflow Script Injection | **HIGH** | CWE-78 | GitHub Actions workflow using un-sanitized `${{ github.event... }}` in `run:`. |
| `PYH-GIT-006` | Mutable Action Reference | **MEDIUM** | CWE-829 | GitHub Action referencing mutable branch (`@main`) instead of full commit SHA. |

---

## 6. Concurrency & Race Condition Rules (`PYH-CONC`)

| Rule ID | Title | Severity | CWE | Description |
| :--- | :--- | :---: | :--- | :--- |
| `PYH-CONC-001`| Potential Data Race on Shared State | **MEDIUM** | CWE-362 | Shared mutable module variable modified across async or threaded contexts. |
| `PYH-CONC-003`| TOCTOU File System Race Condition | **MEDIUM** | CWE-367 | Non-atomic check and open sequence on filesystem paths. |
| `PYH-CONC-004`| Potential Deadlock Lock Ordering | **HIGH** | CWE-833 | Multiple locks acquired in inconsistent ordering across concurrent functions. |
