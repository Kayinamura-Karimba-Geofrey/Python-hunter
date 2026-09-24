# Python Hunter VS Code Extension

Official Visual Studio Code extension for **Python Hunter** — Real-Time SAST, Secrets, Supply-Chain & Malware Security Linting.

## Features

- **Inline Security Diagnostics**: Real-time red squiggles and warnings for:
  - Dangerous Python AST constructs (`eval`, `exec`, `os.system`, `subprocess` with shell, unsafe `yaml.load`, `pickle`).
  - Leaked API keys, AWS credentials, JWT tokens, and private keys.
  - PolinRider / TasksJacker malware backdoors, fake font payloads, and VS Code `folderOpen` task hijacking.
  - Vulnerable or unpinned dependency versions in `requirements.txt`, `pyproject.toml`, and `package.json`.
- **One-Click Quick Fixes (Code Actions)**:
  - Automatically bump and pin vulnerable dependencies to secure releases.
  - Suppress false positives with `# noqa: python-hunter`.
- **Integrated Commands**:
  - `Python Hunter: Scan Current Workspace`
  - `Python Hunter: Auto-Fix Vulnerable & Unpinned Dependencies`
  - `Python Hunter: Open Interactive Security TUI Dashboard`

## Installation

### Prerequisites

Ensure `python-hunter` is installed in your Python environment or PATH:

```bash
pip install python-hunter
```

Verify that the LSP command is operational:

```bash
python-hunter lsp --help
```

### Developing & Testing Locally

1. Open this repository in VS Code:
   ```bash
   code /path/to/Python-hunter
   ```
2. Navigate to `contrib/vscode`:
   ```bash
   cd contrib/vscode
   npm install
   ```
3. Press `F5` in VS Code to launch the Extension Development Host window.
4. Open any Python file, `requirements.txt`, or `package.json` to see live inline diagnostics!

### Packaging into `.vsix`

To distribute the extension as a VSIX package:

```bash
npx @vscode/vsce package
code --install-extension python-hunter-vscode-1.0.0.vsix
```
