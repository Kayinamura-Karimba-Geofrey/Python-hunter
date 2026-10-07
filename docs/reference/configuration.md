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
| `PYH_ENV` | String | `development` | Runtime environment: `development`, `dev`, `local`, `test`, or `production`. |
| `PYH_SECRET_KEY` | String | `""` | Cryptographic secret for signing tokens. **Required in production (min 32 characters)**. |
| `PYH_DEBUG` | Boolean | `true` (dev) | Enable verbose debug output and runtime stack traces. |

> [!CAUTION]
> **Production Key Hardening**: Starting Python Hunter with `PYH_ENV=production` while `PYH_SECRET_KEY` is empty or set to default placeholders will cause the application to raise `ConfigurationError` and refuse to boot.

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
| `PYH_MAX_SCAN_FILE_SIZE_MB` | Integer | `10` | Maximum file size in megabytes evaluated during static and AST passes. Files exceeding this limit are skipped to protect memory. |
| `PYH_SCAN_TIMEOUT_SECONDS` | Integer | `300` | Hard timeout ceiling in seconds for an entire repository scan. |
| `PYH_MAX_ARCHIVE_RATIO`| Integer | `10` | Maximum decompression ratio to prevent Zip-Bomb denial of service attacks. |
| `PYH_MIN_SEVERITY` | String | `LOW` | Minimum severity threshold to retain in scan results (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |

---

### REST API Settings (`ApiConfig`)

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `PYH_API_USERNAME` | String | `""` | The single API user allowed to log in. Login returns `503` until both this and the hash are set. |
| `PYH_API_PASSWORD_HASH` | String | `""` | PBKDF2-SHA256 hash of the API password (see below). Plain-text passwords are never accepted. |
| `PYH_API_TOKEN_TTL_MINUTES` | Integer | `60` | Lifetime of bearer tokens issued by `/api/v1/auth/login`. Tokens are HS256 JWTs signed with `PYH_SECRET_KEY`. |
| `PYH_API_CORS_ORIGINS` | CSV | `http://localhost:5173` | Comma-separated browser origins allowed to call the API. `*` is rejected. |
| `PYH_API_WORKSPACE_ROOT` | Path | current directory | Every scan target submitted through the API must resolve inside this directory. |
| `PYH_API_ALLOW_REMOTE_TARGETS` | Boolean | `false` | Allow `https://` Git URLs as API scan targets. |
| `PYH_API_MAX_CONCURRENT_SCANS` | Integer | `2` | Size of the background scan worker pool. |
| `PYH_DATA_DIR` | Path | `~/.python-hunter` | Where scan records, PR analyses, GitHub installations, and the audit log are stored. Shared by the CLI and API. |

Generate the password hash with:

```bash
python -c "from getpass import getpass; from python_hunter.application.api.security import hash_password; print(hash_password(getpass()))"
```

> In development, an empty `PYH_SECRET_KEY` makes the API sign tokens with a random per-process key, so tokens stop working when the server restarts. Outside development, startup is refused without a real key.

---

### GitHub Integration Settings

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `PYH_WEBHOOK_SECRET` | String | `""` | GitHub webhook secret used to verify `X-Hub-Signature-256`. Deliveries are rejected until it is set. |
| `GITHUB_TOKEN` / `GH_TOKEN` | String | `""` | Personal Access Token or fine-grained token for opening automated remediation PRs. |
| `GITHUB_APP_ID` | Integer | `""` | GitHub App numerical ID for multi-tenant webhook integration. |
| `GITHUB_APP_PRIVATE_KEY_PATH` | File path | `""` | Path to PEM private key file for GitHub App JWT generation. |

---

## 3. Sample `.env` Configuration File

Create a `.env` file at the root of your project:

```bash
# Environment
PYH_ENV=development
PYH_DEBUG=true
PYH_SECRET_KEY=  # python -c 'import secrets; print(secrets.token_urlsafe(48))'

# Logging
PYH_LOG_LEVEL=INFO
PYH_LOG_FORMAT=text
PYH_REDACT_SECRETS=true

# Engine Limits
PYH_MAX_SCAN_FILE_SIZE_MB=10
PYH_SCAN_TIMEOUT_SECONDS=300
PYH_MIN_SEVERITY=LOW

# REST API
PYH_API_USERNAME=analyst
PYH_API_PASSWORD_HASH=  # output of hash_password(), see above
PYH_API_CORS_ORIGINS=http://localhost:5173
PYH_API_WORKSPACE_ROOT=/srv/repos

# GitHub Automation
GITHUB_TOKEN=ghp_exampleTokenForLocalTesting12345
PYH_WEBHOOK_SECRET=
```
