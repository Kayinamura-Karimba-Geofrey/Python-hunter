# Taint Analysis, Call Graphs & Attack Paths (`taint`, `callgraph`, `attack-paths`, `explain`, `verify`)

Python Hunter features an interprocedural static dataflow engine that models control flow, tracks taint propagation from untrusted inputs to sensitive execution sinks, constructs attack paths, and validates exploitability.

---

## 1. Static Taint Analysis Engine (`taint`)

Taint analysis tracks untrusted user data across variables, function calls, and data structures to determine if it reaches a dangerous sink without adequate sanitization.

### Core Concepts

```
┌─────────────────┐       ┌──────────────────────┐       ┌─────────────────┐
│     Source      │ ----> │     Propagators      │ ----> │      Sink       │
│ (Untrusted Input│       │ (Assignments, Concat,│       │ (Dangerous Exec │
│  request.args)  │       │  Formatting, Returns)│       │  cursor.execute)│
└─────────────────┘       └──────────┬───────────┘       └─────────────────┘
                                     │
                             ┌───────▼───────┐
                             │   Sanitizer   │
                             │ (int(), quote,│ (Neutralizes Taint)
                             │  parameterize)│
                             └───────────────┘
```

* **Sources**: Entrypoints where attacker-controlled input enters the program (`request.args`, `request.json`, `sys.argv`, environment variables, socket data).
* **Propagators**: Operations that transfer taint (string concatenation, f-strings, dict lookups, list appends, function parameters, return values).
* **Sanitizers**: Defensive transformations that neutralize taint (`int()`, `shlex.quote()`, parameterized query tuples, HTML escaping).
* **Sinks**: Vulnerable functions where unsanitized input triggers compromise (SQL execution, OS command execution, dynamic `eval()`, path traversal, SSRF).

### Supported Taint Rules

| Rule ID | Category | Common Sinks |
| :--- | :--- | :--- |
| `PYH-TAINT-SQL-001` | SQL Injection | `cursor.execute()`, `db.engine.execute()`, raw ORM queries |
| `PYH-TAINT-CMD-001` | Command Injection | `subprocess.Popen()`, `os.system()`, `os.popen()` |
| `PYH-TAINT-CODE-001`| Code Injection | `eval()`, `exec()`, `compile()` |
| `PYH-TAINT-PATH-001`| Path Traversal | `open()`, `os.remove()`, `shutil.rmtree()`, `send_file()` |
| `PYH-TAINT-SSRF-001`| Server-Side Request Forgery | `requests.get()`, `urllib.request.urlopen()`, `httpx.get()` |
| `PYH-TAINT-TEMPLATE-001`| Server-Side Template Injection | `jinja2.Template().render()`, `render_template_string()` |

### Running Taint Analysis
```bash
python-hunter taint src/ --details
```

---

## 2. Call Graph Construction (`callgraph`)

The `callgraph` command builds an interprocedural call graph of your project, mapping relationships between callers and callees across modules:

```bash
python-hunter callgraph . --depth 5 --format text
```

Features:
* Resolves class methods, function pointers, and imported module symbols.
* Detects unreachable dead code and cyclic recursion loops.
* Identifies public API entrypoints and tracks calls downward into internal helpers.

---

## 3. Attack Path Graph Engine (`attack-paths`)

The `attack-paths` command stitches together the Call Graph, Taint Flow, and Permissions Model to construct end-to-end exploit trajectories:

```bash
python-hunter attack-paths . --format terminal
```

Output:
```text
[!] Attack Path Found: Web API Parameter to SQL Database
  1. Entrypoint : POST /api/v1/search (src/api/search.py:18)
  2. Input Source: request.args.get("q") [TAINTED]
  3. Propagator : query_builder(user_q) (src/domain/search.py:45)
  4. Intermediary: sql = f"SELECT * FROM items WHERE name LIKE '%{q}%'"
  5. Sink Exec  : db.cursor().execute(sql) (src/infra/db.py:88)
  Severity      : CRITICAL (Exploitability Likelihood: 92%)
```

---

## 4. Explaining Finding Evidence (`explain`)

When a developer or security analyst wants a comprehensive, plain-English breakdown of a specific finding:

```bash
python-hunter explain PYH-TAINT-SQL-001 --target .
```

The command generates:
* **Root Cause Analysis**: Why this code pattern is vulnerable.
* **Exploit Scenario**: How an attacker could construct a payload to trigger the flaw.
* **Dataflow Trace**: Exact variable state at each step.
* **Remediation Pattern**: Secure code snippets illustrating the correct defense.

---

## 5. Exploitability Verification (`verify`)

The `verify` command runs non-destructive, safe verification tests against suspect code paths to differentiate theoretical findings from confirmed vulnerabilities:

```bash
python-hunter verify src/api/search.py
```

Validation includes:
* AST-level sanitizer effectiveness verification (verifies whether sanitizers are bypassed by nested encoding).
* Contextual escaping analysis.
