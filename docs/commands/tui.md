# Interactive Terminal TUI Dashboard (`tui`)

The `tui` command launches a curses-based interactive terminal dashboard designed to explore scan results, investigate exploitability traces, and review remediation roadmaps without leaving your terminal.

---

## 1. Dashboard Layout & Architecture

The TUI splits your terminal window into high-density security panes:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ PYTHON HUNTER SECURITY DASHBOARD                    Score: 85/100 [Grade: B]│
├─────────────────────────────────────────────────────────────────────────────┤
│ [All (12)]   [Malware (0)]   [Secrets (2)]   [Supply-Chain (3)]   [SAST (7)]│
├──────────────────────────────────────┬──────────────────────────────────────┤
│ FINDINGS LIST                        │ FINDING EVIDENCE & REMEDIATION       │
│                                      │                                      │
│ > [HIGH] PYH-TAINT-SQL-001           │ Rule ID    : PYH-TAINT-SQL-001       │
│   src/api/users.py:42                │ Severity   : HIGH (Risk: 82/100)     │
│   SQL Injection via unescaped query  │ CWE        : CWE-89 (SQL Injection)  │
│                                      │ Location   : src/api/users.py:42     │
│   [MED]  PYH-SEC-002                 ├──────────────────────────────────────┤
│   config/database.py:15              │ CODE CONTEXT:                        │
│   Hardcoded API Token                │ 40 | user_id = request.args.get("id")│
│                                      │ 41 | query = "SELECT * FROM users "  │
│   [HIGH] PYH-DEP-001                 │ 42 > cursor.execute(query + user_id) │
│   requirements.txt:5                 ├──────────────────────────────────────┤
│   Vulnerable urllib3 (CVE-2023-45803)│ REMEDIATION:                         │
│                                      │ Parameterize SQL query using cursor  │
│   [LOW]  PYH-AST-005                 │ execute with variable tuple.         │
│   utils/runner.py:12                 │                                      │
│   Subprocess call with shell=True    │                                      │
├──────────────────────────────────────┴──────────────────────────────────────┤
│ [Tab] Switch Category | [↑/↓/j/k] Navigate | [r] Re-Scan | [q] Quit         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Command: `python-hunter tui`

### Syntax
```bash
python-hunter tui [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory or repository. |
| `--snapshot` | Flag | `False` | Print a formatted terminal snapshot and exit without initializing the curses interactive screen (ideal for CI/CD runners or scripting). |

---

## 3. Keyboard Controls & Shortcuts

| Keybinding | Action |
| :--- | :--- |
| `Tab` / `Right Arrow` | Advance to next domain category tab (`All` → `Malware` → `Secrets` → `Supply-Chain` → `SAST`). |
| `Left Arrow` | Return to previous domain category tab. |
| `Down Arrow` / `j` | Move selection down one finding. |
| `Up Arrow` / `k` | Move selection up one finding. |
| `Enter` / `Space` | Refresh and focus finding detail inspector pane. |
| `r` | Trigger an immediate live re-scan of the target directory. |
| `q` / `Ctrl + C` | Exit the dashboard and return to shell. |

---

## 4. Headless Snapshot Mode (`--snapshot`)

When running inside non-interactive shells, continuous integration runners, or remote SSH sessions without full terminal emulation, use `--snapshot`:

```bash
python-hunter tui . --snapshot
```

Output:
```text
=== Python Hunter Terminal Snapshot ===
Target: /home/kayi/Python-hunter
Overall Score: 85/100 (Grade B)
Active Findings: 12 (Critical: 0, High: 3, Medium: 4, Low: 5)

[HIGH] PYH-TAINT-SQL-001: SQL Injection vulnerability in src/api/users.py:42
[HIGH] PYH-SEC-002: Hardcoded API token in config/database.py:15
[HIGH] PYH-DEP-001: Vulnerable package urllib3 in requirements.txt:5
```
