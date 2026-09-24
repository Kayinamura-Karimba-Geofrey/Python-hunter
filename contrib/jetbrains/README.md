# Python Hunter JetBrains Integration Guide

This guide covers setting up **Python Hunter** in JetBrains IDEs (PyCharm, IntelliJ IDEA Ultimate, WebStorm, CLion).

## Method 1: Language Server Protocol (LSP) Integration

*Supported natively in IntelliJ IDEA Ultimate 2023.2+ / PyCharm Professional 2023.2+, or Community editions via the LSP Support plugin.*

### Setup via Settings

1. Open **Settings** (or **Preferences** on macOS) -> **Languages & Frameworks** -> **Language Servers**.
2. Click **+ (Add)** and configure:
   - **Name**: `Python Hunter LSP`
   - **Executable**: `python-hunter`
   - **Arguments**: `lsp --stdio`
   - **Supported File Types**:
     - Python (`*.py`, `*.pyw`)
     - Requirements (`requirements*.txt`)
     - TOML (`pyproject.toml`)
     - JSON (`package.json`)
     - YAML (`.github/workflows/*.yml`)
3. Click **Apply** and **OK**.
4. Now any security finding will display inline highlights, hover explanations, and CodeAction quick fixes in PyCharm.

---

## Method 2: External Tools & File Watchers (Universal for Community & Pro)

You can run `python-hunter diagnostics` directly upon file save or via keybinding.

### 1. Configure External Tool

1. Open **Settings** -> **Tools** -> **External Tools**.
2. Click **+ (Add)**:
   - **Name**: `Python Hunter Security Lint`
   - **Program**: `python-hunter`
   - **Arguments**: `diagnostics "$FilePath$" --format gcc`
   - **Working directory**: `$ProjectFileDir$`
3. In **Advanced Options**:
   - Check **Synchronize files after execution**
   - Click **Output filters...** -> **Add...**:
     - **Regular expression to match output**:
       ```regex
       $FILE_PATH$:$LINE$:$COLUMN$: $SEVERITY$: \[(.*)\] $MESSAGE$
       ```
4. Click **OK**.

### 2. Configure File Watcher (Instant On-Save Feedback)

1. Open **Settings** -> **Tools** -> **File Watchers**.
2. Click **+ (Custom)**:
   - **Name**: `Python Hunter Security Scanner`
   - **File type**: `Any`
   - **Scope**: `Project Files`
   - **Program**: `python-hunter`
   - **Arguments**: `diagnostics "$FilePath$" --format gcc`
   - **Working directory**: `$ProjectFileDir$`
   - **Show console**: `On error`
3. Click **OK**. Now every time you press `Ctrl+S` (`Cmd+S`), Python Hunter audits the file in milliseconds and marks security risks directly in the JetBrains Run/Problems tool window!
