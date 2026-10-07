# IDE Integrations & Diagnostics (`lsp` & `diagnostics`)

Python Hunter integrates directly into developer editors—including **VS Code**, **JetBrains PyCharm / IntelliJ**, **Neovim**, and **Emacs**—via the **Language Server Protocol (LSP 3.17)** and compiler-style diagnostic emitters.

---

## 1. Language Server Protocol Daemon (`lsp`)

The `lsp` command runs Python Hunter as an in-process or TCP Language Server. As developers type or save code, the server analyzes files incrementally and reports red squiggles, hover popups, and quick-fix suggestions.

### Syntax
```bash
python-hunter lsp [OPTIONS]
```

### Options Reference

| Option | Format / Default | Description |
| :--- | :--- | :--- |
| `--stdio` | Flag (`default: True`) | Run language server communication over standard input and standard output (used by VS Code, Neovim). |
| `--tcp` | `[HOST:]PORT` | Listen for incoming JSON-RPC connections over a TCP socket (e.g. `--tcp 127.0.0.1:2087`). |
| `--log-file` | File path | Path to record internal LSP wire messages and debug events. |

### Supported LSP Capabilities

* **`textDocument/publishDiagnostics`**: Pushes real-time inline warnings and errors directly to the editor's problems pane and gutter.
* **`textDocument/hover`**: Displays vulnerability descriptions, CWE links, severity metrics, and remediation guidance upon hovering over a flagged line.
* **`textDocument/codeAction`**: Offers automated quick-fixes (e.g., replacing `eval()` with `ast.literal_eval()`, or parameterizing SQL queries).

---

## 2. Compiler-Style Diagnostics CLI (`diagnostics`)

The `diagnostics` command executes lightweight, fast AST evaluation and formats results for non-LSP tools, external linters, and IDE File Watchers.

### Syntax
```bash
python-hunter diagnostics [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target Python file or directory. |
| `--format` | `gcc`, `lsp`, `json`, `codeclimate`, `rdjson` | `gcc` | Output diagnostic format. |
| `--fail-on` | `critical`, `high`, `medium`, `low`, `none` | `high` | Threshold to trigger non-zero exit code. |

### Diagnostic Output Formats

#### 1. GCC Compiler Format (`--format gcc`)
Standard Unix compiler format (`<file>:<line>:<col>: <level>: [<rule_id>] <message>`). Most IDEs (including JetBrains External Tools) automatically parse this format into clickable jump-to-line navigation:

```bash
python-hunter diagnostics src/service.py --format gcc
```

Output:
```text
src/service.py:42:15: error: [PYH-TAINT-SQL-001] Untrusted user input flows into cursor.execute()
src/service.py:78:4: warning: [PYH-AST-005] Subprocess executed with shell=True
```

#### 2. Reviewdog RDJSON (`--format rdjson`)
Standard diagnostic JSON format consumed by [Reviewdog](https://github.com/reviewdog/reviewdog) to post automated inline comments on GitHub Pull Requests:

```bash
python-hunter diagnostics . --format rdjson | reviewdog -f=rdjson -reporter=github-pr-review
```

#### 3. GitLab Code Quality (`--format codeclimate`)
Produces CodeClimate JSON ingested natively by GitLab CI/CD Merge Requests:

```bash
python-hunter diagnostics . --format codeclimate -o gl-code-quality-report.json
```

---

## 3. IDE Setup Guides

### Visual Studio Code
1. Install the Python Hunter VS Code extension from [`contrib/vscode/`](../../contrib/vscode/README.md).
2. Or configure an LSP client entry in your `.vscode/settings.json`:
```json
{
  "pythonHunter.enable": true,
  "pythonHunter.serverPath": "python-hunter",
  "pythonHunter.trace.server": "verbose"
}
```

### JetBrains PyCharm / IntelliJ IDEA
Configure Python Hunter as an **External Tool** for instant one-click audits:
1. Open **Settings / Preferences → Tools → External Tools → Add (+)**.
2. Fill in the tool parameters:
   * **Name**: `Python Hunter Diagnostics`
   * **Program**: `python-hunter` (or path to `.venv/bin/python-hunter`)
   * **Arguments**: `diagnostics "$FilePath$" --format gcc`
   * **Working directory**: `$ProjectFileDir$`
3. Set **Output filters** to:
   ```text
   $FILE_PATH$:$LINE$:$COLUMN$: $MESSAGE$
   ```
4. Double-click any line in the PyCharm terminal output to jump straight to the vulnerability.

### Neovim (`nvim-lspconfig`)
Add Python Hunter to your Neovim LSP configuration:
```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

if not configs.python_hunter then
  configs.python_hunter = {
    default_config = {
      cmd = { 'python-hunter', 'lsp', '--stdio' },
      filetypes = { 'python' },
      root_dir = lspconfig.util.root_pattern('pyproject.toml', 'setup.py', '.git'),
      settings = {},
    },
  }
end

lspconfig.python_hunter.setup({})
```
