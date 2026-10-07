# Centralized Configuration Reference

Python Hunter features a centralized configuration engine managed via environment variables and `.env` files.

---

## 1. Configuration Architecture

Settings are validated on startup using typed dataclasses defined in `python_hunter.infrastructure.config.settings`. If an invalid setting or insecure secret is detected, startup aborts immediately with an actionable error message.

To inspect the currently active configuration:
```bash
python-hunter config
```

---

## 2. Environment Variables Reference

### Application Settings (`AppConfig`)

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `PYH_APP_ENV` | String | `development` | Runtime environment: `development`, `dev`, `local`, `test`, or `production`. |
| `PYH_SECRET_KEY` | String | `""` | Cryptographic secret for signing tokens. **Required in production (min 32 characters)**. |
| `PYH_DEBUG` | Boolean | `true` (dev) | Enable verbose debug output and runtime stack traces. |

> [!CAUTION]
> **Production Key Hardening**: Starting Python Hunter with `PYH_APP_ENV=production` while `PYH_SECRET_KEY` is empty or set to default placeholders will cause the application to raise `ConfigurationError` and refuse to boot.

---

### Logging Settings (`LogConfig`)

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `PYH_LOG_LEVEL` | String | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `PYH_LOG_FORMAT` | String | `text` | Serialization format: `text` (human-readable) or `json` (for SIEM, CloudWatch, Datadog). |
| `PYH_REDACT_SECRETS` | Boolean | `true` | Automatically mask credential strings in logs, outputs, and terminal traces. |

---

### Scanning Engine Limits (`ScanConfig`)

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `PYH_MAX_FILE_SIZE_MB` | Integer | `10` | Maximum file size in megabytes evaluated during static and AST passes. Files exceeding this limit are skipped to protect memory. |
| `PYH_SCAN_TIMEOUT_SEC` | Integer | `300` | Hard timeout ceiling in seconds for an entire repository scan. |
| `PYH_MAX_ARCHIVE_RATIO`| Integer | `10` | Maximum decompression ratio to prevent Zip-Bomb denial of service attacks. |
| `PYH_MIN_SEVERITY` | String | `LOW` | Minimum severity threshold to retain in scan results (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |

---

### GitHub Integration Settings

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `GITHUB_TOKEN` / `GH_TOKEN` | String | `""` | Personal Access Token or fine-grained token for opening automated remediation PRs. |
| `GITHUB_APP_ID` | Integer | `""` | GitHub App numerical ID for multi-tenant webhook integration. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | File path | `""` | Path to PEM private key file for GitHub App JWT generation. |

---

## 3. Sample `.env` Configuration File

Create a `.env` file at the root of your project:

```bash
# Environment
PYH_APP_ENV=development
PYH_DEBUG=true
PYH_SECRET_KEY=dev-secret-key-not-for-production-use

# Logging
PYH_LOG_LEVEL=INFO
PYH_LOG_FORMAT=text
PYH_REDACT_SECRETS=true

# Engine Limits
PYH_MAX_FILE_SIZE_MB=10
PYH_SCAN_TIMEOUT_SEC=300
PYH_MIN_SEVERITY=LOW

# GitHub Automation
GITHUB_TOKEN=ghp_exampleTokenForLocalTesting12345
```
