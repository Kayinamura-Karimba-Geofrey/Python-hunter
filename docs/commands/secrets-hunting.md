# Credential & Secret Leak Hunting (`secrets`)

The `secrets` command provides enterprise-grade secret detection, discovering exposed API tokens, cloud credentials, cryptographic keys, and database passwords across both active workspace files and historical Git commit logs.

---

## 1. Secret Detection Engine

Python Hunter combines three complementary detection strategies to maximize recall while maintaining low false-positive rates:

```
┌─────────────────────────────────────────────────────────────┐
│                 Input Code / Commit Stream                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       ▼                       ▼                       ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│ Shannon      │       │ Pattern      │       │ Placeholder  │
│ Entropy      │       │ Heuristics   │       │ Filter       │
│ Analysis     │       │ (Regex Engine│       │ (Whitelists) │
└──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       │                       │                       │
       └───────────────────────┼───────────────────────┘
                               │
                               ▼
               ┌──────────────────────────────┐
               │ Scored Finding & Redaction   │
               └──────────────────────────────┘
```

1. **High-Entropy Heuristics (Shannon Entropy)**: Calculates byte randomness distributions to detect randomly generated secrets, base64 tokens, and hex strings even when no known pattern matches.
2. **Signature & Regex Matchers**: Pre-built detection rules targeting 50+ enterprise services:
   * **Cloud Providers**: AWS (`AKIA...`, Secret Keys), GCP Service Account Keys, Azure Client Secrets.
   * **Developer Platforms**: GitHub Tokens (`ghp_`, `gho_`, `github_pat_`), GitLab Personal Tokens, NPM tokens.
   * **Payment Gateways**: Stripe Live Secret Keys (`sk_live_...`), Square Access Tokens.
   * **Communication & Collaboration**: Slack Bot Tokens (`xoxb-`), Slack Incoming Webhooks, Discord Tokens, SendGrid API keys.
   * **Cryptographic Keys**: RSA, EC, PGP, and OpenSSH private key headers (`-----BEGIN RSA PRIVATE KEY-----`).
   * **Database Connection Strings**: PostgreSQL, MySQL, MongoDB, Redis connection URIs with embedded passwords.
3. **Smart Placeholder & Test Filter**: Discards obvious dummy strings, unit test fixtures, and documentation templates (e.g. `your_token_here`, `dummy12345`, `example_secret`, `change_me_in_production`).

---

## 2. Command: `python-hunter secrets`

### Syntax
```bash
python-hunter secrets [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target directory or file to audit. |
| `--format` | `text`, `json` | `text` | Display output format. |

---

## 3. Usage Examples

### Example 1: Scan Workspace for Exposed Credentials
```bash
python-hunter secrets .
```

Terminal Output:
```text
==========================================================
 Python Hunter Credential Exposure Intelligence
==========================================================
Target Path            : /home/kayi/Python-hunter
Active Exposures       : 2
Historical Exposures   : 1
==========================================================

[!] CRITICAL SECRET DETECTED (PYH-SEC-AWS-001)
    Title       : AWS Access Key ID
    File/Line   : config/aws_uploader.py:12
    Fingerprint : sha256:4a8b...
    Evidence    : AKIA**************** (Redacted)
----------------------------------------------------------
[!] HIGH SECRET DETECTED (PYH-SEC-STRIPE-001)
    Title       : Stripe Live API Secret Key
    File/Line   : services/payments.py:34
    Fingerprint : sha256:7c9e...
    Evidence    : sk_live_51M************************* (Redacted)
----------------------------------------------------------
```

### Example 2: Export Secrets Audit to JSON
Ideal for automated security incident logging or SIEM pipeline ingest:

```bash
python-hunter secrets . --format json -o secrets-audit.json
```

Sample JSON Structure:
```json
{
  "workspace_path": "/home/kayi/Python-hunter",
  "active_secrets_count": 2,
  "historical_secrets_count": 1,
  "active_secrets": [
    {
      "rule_id": "PYH-SEC-AWS-001",
      "severity": "CRITICAL",
      "title": "AWS Access Key ID",
      "file_path": "config/aws_uploader.py",
      "line": 12,
      "fingerprint": "a3b9f482d8c1...",
      "evidence": "AKIA****************"
    }
  ]
}
```

---

## 4. Automatic Secret Redaction

To prevent sensitive credentials from leaking into CI/CD build logs, terminal recording sessions, or ticketing systems:
* Python Hunter automatically redacts sensitive substrings by default (e.g. `sk_live_51M*************************`).
* During full security scans (`python-hunter scan .`), secret masking is enabled by default. To disable masking in secure environments, pass `--no-redact`.
