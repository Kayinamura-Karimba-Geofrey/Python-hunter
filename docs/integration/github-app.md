# GitHub App Setup & Pull Request Security Review

This guide covers registering and configuring a GitHub App to enable automated repository monitoring, Pull Request checks, and auto-remediation workflows.

---

## 1. Registering the GitHub App

1. Go to **GitHub Settings → Developer Settings → GitHub Apps → New GitHub App**.
2. Set the basic configuration:
   * **GitHub App name**: `Python Hunter Security Platform` (or custom name)
   * **Homepage URL**: `https://github.com/your-org/python-hunter`
   * **Webhook URL**: `https://your-domain.com/api/v1/github/webhook` (or leave inactive for polling mode)
   * **Webhook secret**: Generate a secure random token (`openssl rand -hex 20`).

---

## 2. Required Permissions

Under **Repository Permissions**, configure the following minimum grants:

| Permission | Access Level | Reason |
| :--- | :--- | :--- |
| **Checks** | Read & Write | Required to create Check Runs on Pull Requests. |
| **Pull Requests** | Read & Write | Required to comment review findings and open remediation PRs. |
| **Repository Contents** | Read & Write | Read code for scanning; Write to push auto-fix branches. |
| **Commit Statuses** | Read & Write | Update commit pass/fail statuses. |

Under **Subscribe to events**, select:
* `Push`
* `Pull request`
* `Check run`

---

## 3. Cryptographic Credentials & Configuration

1. Under the newly created App's settings, scroll to **Private keys** and click **Generate a private key**.
2. Save the downloaded `.pem` file to a secure directory (e.g. `/etc/python-hunter/github-app.pem`).
3. Note your **App ID** (found near the top of the App settings page).
4. Configure your `.env` file:
   ```bash
   GITHUB_APP_ID=123456
   GITHUB_APP_PRIVATE_KEY_PATH=/etc/python-hunter/github-app.pem
   GITHUB_WEBHOOK_SECRET=yourWebhookSecretHex
   ```

---

## 4. Verifying App Authentication

Validate that Python Hunter can authenticate with the GitHub API using the private key and generate an ephemeral JSON Web Token (JWT):

```bash
python-hunter github connect
```

Expected output:
```text
Connected to GitHub App. JWT: eyJhbGciOiJS...
```

---

## 5. Automated Pull Request Security Workflow

Once installed on a GitHub organization or repository, the GitHub App automatically executes the following loop on every PR:

1. **Webhook Reception**: GitHub sends a `pull_request.opened` or `pull_request.synchronize` event.
2. **Analysis Execution**: Python Hunter evaluates the diff for newly introduced credentials, vulnerable dependencies, and AST injection flaws.
3. **Check Run Update**: Updates the GitHub Check Run with a Pass/Fail status.
4. **Interactive Comments**: Posts precise inline comments pointing to vulnerable lines with one-click fix suggestions.
