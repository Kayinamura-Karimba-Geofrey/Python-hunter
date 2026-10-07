# Installation & Setup Guide

This guide covers installing and verifying **Python Hunter** across development workstations, CI/CD runners, and enterprise container environments.

---

## 1. System Requirements

* **Python Version**: Python 3.12 or newer.
* **Operating Systems**:
  * Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+, Alpine 3.19+)
  * macOS (macOS 13 Ventura+, Apple Silicon & Intel)
  * Windows (Windows 11 / Windows Server 2022 via PowerShell or WSL2)
* **External Tools** (Optional but Recommended):
  * `git` (v2.30+ for remote repository cloning and history auditing)
  * `curl` / `wget`

---

## 2. Installation Options

### Option A: Install from Source (Development / Latest)

Recommended for development, testing, and contributors:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/python-hunter.git
cd python-hunter

# 2. Create and activate a clean Python 3.12+ virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Upgrade pip, setuptools, and wheel
pip install --upgrade pip setuptools wheel

# 4. Install Python Hunter in editable mode with development tooling
pip install -e ".[dev]"
```

### Option B: Minimal Standalone CLI Installation

For lightweight CI/CD agents or single-purpose security auditing:

```bash
# Minimal installation without testing dependencies
pip install -e .
```

### Option C: Enterprise / Production Environment

When deploying Python Hunter as an autonomous security service or API node:

```bash
# Install core package
pip install -e .

# Copy and configure the environment variables
cp .env.example .env
chmod 600 .env
```

---

## 3. Verifying Installation

Verify that the CLI binary is available in your `$PATH` and check the runtime version:

```bash
python-hunter --version
```

Expected output:
```text
Python Hunter version 1.0.0 (Python 3.12.x)
```

Validate the system configuration and default security scanner settings:

```bash
python-hunter config
```

Expected output:
```text
--- Python Hunter Configuration ---
Environment: development
Log Level: INFO (Format: text)
Max Scan File Size: 10 MB
Scan Timeout: 300 s
Min Severity Threshold: LOW
```

---

## 4. Environment Variables Configuration

Python Hunter supports centralized configuration via environment variables or a `.env` file at the project root.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PYH_APP_ENV` | `development` | Runtime environment (`development`, `test`, `production`). In production, a secure secret key is strictly required. |
| `PYH_SECRET_KEY` | *(empty in dev)* | Cryptographic signing secret. Must be 32+ characters in production. |
| `PYH_LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `PYH_LOG_FORMAT` | `text` | Log serialization: `text` (human-readable) or `json` (SIEM/Datadog ingestion). |
| `PYH_REDACT_SECRETS` | `true` | Automatically mask credential strings in logs, outputs, and terminal traces. |
| `PYH_MAX_FILE_SIZE_MB`| `10` | Maximum file size in megabytes to analyze during AST & static passes. |
| `PYH_SCAN_TIMEOUT_SEC`| `300` | Hard timeout ceiling in seconds for a repository analysis run. |
| `GITHUB_TOKEN` / `GH_TOKEN` | *(optional)* | Personal Access Token or GitHub App installation token for automated PR remediation. |

To generate a secure production secret key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 5. Troubleshooting Installation

### Issue: `python-hunter: command not found`
**Cause**: The virtual environment's `bin/` directory is not in your current `$PATH`.
**Solution**: Ensure your virtual environment is activated (`source .venv/bin/activate`), or run the module directly:
```bash
python3 -m python_hunter.interfaces.cli.main --version
```

### Issue: `Refusing to start in production with default PYH_SECRET_KEY`
**Cause**: `PYH_APP_ENV` is set to `production`, but `PYH_SECRET_KEY` is empty or using a default insecure placeholder.
**Solution**: Set a strong cryptographic key in your environment:
```bash
export PYH_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

---

## Next Steps

* Continue to the [Quickstart Guide](quickstart.md) to run your first security scan.
* Explore the full [CLI Command Reference](../reference/cli-reference.md).
