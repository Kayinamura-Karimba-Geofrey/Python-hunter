# IDE Integration: VS Code & JetBrains

This guide explains how to configure real-time, in-editor security diagnostics for **Visual Studio Code**, **JetBrains PyCharm / IntelliJ**, and **Neovim**.

---

## 1. Visual Studio Code

Python Hunter provides real-time linting, inline red squiggles, and hover tooltips using the **Language Server Protocol (LSP 3.17)**.

### Option A: Install Extension from `contrib/vscode`
1. Navigate to the extension source located in [`contrib/vscode`](../../contrib/vscode/README.md).
2. Package the extension:
   ```bash
   cd contrib/vscode
   npm install
   npm run package
   ```
3. Install the generated `.vsix` into VS Code:
   ```bash
   code --install-extension python-hunter-1.0.0.vsix
   ```

### Option B: Generic LSP Client Configuration
If you use a generic LSP client extension in VS Code:
Add to `.vscode/settings.json`:
```json
{
  "pythonHunter.serverPath": "python-hunter",
  "pythonHunter.arguments": ["lsp", "--stdio"],
  "pythonHunter.trace.server": "verbose"
}
```

---

## 2. JetBrains (PyCharm / IntelliJ IDEA / WebStorm)

JetBrains IDEs can run Python Hunter directly using **External Tools** or **File Watchers**.

### Setting Up as an External Tool (On-Demand Audit)

1. Open **Settings / Preferences** (`Ctrl + Alt + S` / `Cmd + ,`).
2. Navigate to **Tools → External Tools**.
3. Click **Add (+)** and configure:
   * **Name**: `Python Hunter: Audit File`
   * **Description**: `Run Python Hunter AST and security analysis on current file`
   * **Program**: `python-hunter` (or absolute path: `$ProjectFileDir$/.venv/bin/python-hunter`)
   * **Arguments**: `diagnostics "$FilePath$" --format gcc`
   * **Working directory**: `$ProjectFileDir$`
4. Under **Advanced Options**, click **Output Filters → Add (+)**:
   * **Regular expression to match output**:
     ```text
     $FILE_PATH$:$LINE$:$COLUMN$: $MESSAGE$
     ```
5. Click **OK** and **Apply**.

Now right-click any Python file in PyCharm and select **External Tools → Python Hunter: Audit File**. Findings will appear in the Run console with clickable file links that jump straight to line numbers.

---

### Setting Up as a File Watcher (Continuous On-Save Linting)

1. Ensure the **File Watchers** plugin is enabled in PyCharm.
2. Open **Settings → Tools → File Watchers → Add (+)**.
3. Select **<custom>** template:
   * **File type**: `Python`
   * **Scope**: `Project Files`
   * **Program**: `python-hunter`
   * **Arguments**: `diagnostics "$FilePath$" --format gcc`
   * **Output paths to refresh**: `$FilePath$`
   * **Output filters**: `$FILE_PATH$:$LINE$:$COLUMN$: $MESSAGE$`
4. Uncheck *"Auto-save edited files to trigger the watcher"* to trigger only on manual save (`Ctrl + S`).

---

## 3. Neovim (Native LSP)

Add this block to your Neovim `init.lua`:

```lua
local lspconfig = require("lspconfig")
local configs = require("lspconfig.configs")

if not configs.python_hunter then
  configs.python_hunter = {
    default_config = {
      cmd = { "python-hunter", "lsp", "--stdio" },
      filetypes = { "python" },
      root_dir = lspconfig.util.root_pattern("pyproject.toml", "setup.py", ".git"),
      settings = {},
    },
  }
end

lspconfig.python_hunter.setup({
  on_attach = function(client, bufnr)
    -- Enable inline diagnostic virtual text
    vim.diagnostic.config({ virtual_text = true })
  end,
})
```
