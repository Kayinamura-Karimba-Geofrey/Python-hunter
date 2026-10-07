# GitHub App Integration & Enterprise Governance (`github`, `governance`, `operations`, `integrations`)

Python Hunter extends beyond local command-line analysis to operate as a centralized, multi-tenant security platform with continuous GitHub App automation, autonomous security operations, and enterprise governance.

---

## 1. GitHub App Platform Integration (`github`)

The `github` command manages integration with the official Python Hunter GitHub App to monitor repositories, process webhook events, and automate PR security reviews.

### Syntax
```bash
python-hunter github [ACTION]
```

### Supported Subcommands

| Subcommand | Description |
| :--- | :--- |
| `connect` | Verifies cryptographic authentication with the GitHub App using private key and App ID, generating an ephemeral JWT token. |
| `repositories` | Lists all monitored GitHub repositories along with their live Security Scores (0–100) and Risk Levels. |
| `prs` | Lists recent Pull Request security scan executions, policy outcomes (`PASSED`, `FAILED`), and score deltas. |
| `status` | Checks the status of the background webhook event processor and dead-letter queues. |

### Usage Examples

#### Verify Connection
```bash
python-hunter github connect
```
Output:
```text
Connected to GitHub App. JWT: eyJhbGciOiJS...
```

#### List Monitored Repositories & Posture
```bash
python-hunter github repositories
```
Output:
```text
Monitored GitHub Repositories (3):
  • acme/auth-service — Score: 92/100 [LOW RISK]
  • acme/payment-api  — Score: 68/100 [HIGH RISK]
  • acme/frontend-web — Score: 85/100 [MEDIUM RISK]
```

#### Inspect Pull Request Security Gates
```bash
python-hunter github prs
```
Output:
```text
Pull Request Security Scans (2):
  PR #104: feat: add stripe webhooks [PASSED] Score: 92/100 (Delta: +0)
  PR #105: fix: quick sql patch      [FAILED] Score: 55/100 (Delta: -37)
```

---

## 2. Enterprise Multi-Tenancy & Governance (`governance`)

Python Hunter implements strict **Tenant Isolation** and **Role-Based Access Control (RBAC)** across multi-team enterprise environments.

### Tenant Context & Data Isolation
* Every scan, finding, baseline, and audit report is bound to a verified `TenantContext` containing `organization_id`, `project_id`, and `user_id`.
* Zero cross-tenant data leakage: In-memory queues, SQLite databases, and report stores strictly partition entities by tenant key.

### Role-Based Access Control (RBAC) Matrix

| Role | Permissions |
| :--- | :--- |
| **Admin** | Full system control: manage organizations, rotate secrets, configure webhook listeners, modify tenant quotas. |
| **Security Engineer** | Configure scan rules, manage baselines, trigger remediation PRs, acknowledge/suppress findings, generate compliance reports. |
| **Developer** | Trigger on-demand scans, view findings for assigned repositories, run `fix` commands, preview TUI dashboards. |
| **Auditor** | Read-only access to compliance reports, historical scan diffs, and SBOM inventories. |

---

## 3. Autonomous Security Operations (`operations`)

The operations engine manages continuous monitoring and automated incident workflows:

* **Automated Webhook Ingestion**: Receives `push` and `pull_request` webhooks from GitHub/GitLab, enqueues asynchronous scan jobs via `SecurityJobQueue`, and updates commit statuses.
* **Dead-Letter Queue (DLQ)**: Stalled or failed webhook events are preserved in a persistent dead-letter queue for forensic replay without data loss.
* **Incident Lifecycle Automation**: Findings meeting critical thresholds (e.g. active malware or unredacted production database credentials) automatically trigger high-priority security incidents.

---

## 4. Ecosystem Integrations (`integrations`)

Python Hunter connects directly to standard enterprise tooling:

* **Ticketing & Issue Tracking**: Automatically opens prioritized issues in **Jira** or **GitHub Issues** with reproducible reproduction steps and suggested code patches.
* **ChatOps & Alerting**: Pushes real-time alerts to **Slack** or **Microsoft Teams** channels when critical vulnerabilities are introduced into protected branches.
* **SIEM & Observability**: Exports JSON telemetry to **Splunk**, **Datadog**, or **Elasticsearch** with structured fields for security analytics.
