# Automated Dependency Fixes (`fix`)

The `fix` command automatically detects and remediates vulnerable, unpinned, or loosely constrained dependencies across Python and JavaScript ecosystems. It updates manifest files in-place or automatically generates GitHub Remediation Pull Requests.

---

## 1. Supported Ecosystems & Manifests

| Ecosystem | Manifest File | Upgrade Logic |
| :--- | :--- | :--- |
| **Python (pip)** | `requirements.txt`, `requirements/*.txt` | Replaces unconstrained or vulnerable specifiers (`requests`, `urllib3>=1.26.0`) with exact, secure pinned versions (`requests==2.32.3`). |
| **Python (PEP 621 / Poetry)** | `pyproject.toml` | Updates entries within `[project.dependencies]` and `[tool.poetry.dependencies]`. |
| **Node.js (npm / yarn)** | `package.json` | Resolves vulnerable package ranges in `dependencies` and `devDependencies` to secure semver pins. |

---

## 2. Command: `python-hunter fix`

### Syntax
```bash
python-hunter fix [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory, manifest file, or remote Git URL. |
| `--dry-run` | Flag | `False` | Preview proposed dependency upgrades without modifying files on disk. |
| `--unpinned-only` | Flag | `False` | Only pin unconstrained packages (e.g. packages without `==`). |
| `--vulns-only` | Flag | `False` | Only upgrade packages matching known CVE/GHSA vulnerability advisories. |
| `--create-pr` | Flag | `False` | Commit updates to a new branch, push to remote, and open a GitHub Pull Request. |
| `--branch` | String | `main` | Base branch for the Pull Request when using `--create-pr`. |
| `--format` | `terminal`, `json` | `terminal` | Output format. |

---

## 3. Usage Examples

### Example 1: Dry-Run Preview
Preview proposed fixes safely before writing any changes:

```bash
python-hunter fix . --dry-run
```

Terminal Output:
```text
==========================================================
 Python Hunter Automated Dependency Remediation
==========================================================
Target Path   : /home/kayi/Python-hunter
Mode          : DRY-RUN (no files modified)
==========================================================
Manifest: requirements.txt
  • urllib3: <1.26.5  -->  ==1.26.19 [CVE-2023-45803 High Severity]
  • requests: unpinned  -->  ==2.32.3 [Security Best Practice: Pin Exact Version]
  • cryptography: <42.0.0  -->  ==43.0.1 [Vulnerable Algorithm Deprecation]

Summary: 3 dependency updates proposed across 1 manifest.
```

---

### Example 2: Apply Updates In-Place
Apply the recommended version pins directly to your local files:

```bash
python-hunter fix .
```

Modified `requirements.txt` diff:
```diff
- urllib3>=1.25.0
+ urllib3==1.26.19
- requests
+ requests==2.32.3
- cryptography<42.0.0
+ cryptography==43.0.1
```

---

### Example 3: Selective Upgrade (Vulnerabilities Only)
When you only want to patch active security vulnerabilities without altering unpinned internal packages:

```bash
python-hunter fix . --vulns-only
```

---

### Example 4: Automated GitHub Pull Request Creation
To automate dependency patching in CI/CD or scheduled maintenance bots:

```bash
export GITHUB_TOKEN="ghp_yourTokenHere"

python-hunter fix https://github.com/my-org/my-app --create-pr --branch main
```

Automated workflow:
1. Clones `https://github.com/my-org/my-app` into an ephemeral workspace.
2. Identifies all vulnerable packages in `requirements.txt` and `pyproject.toml`.
3. Upgrades packages to their lowest safe patched versions.
4. Creates a Git branch: `fix/security-dependencies-<timestamp>`.
5. Pushes branch and opens a Pull Request on GitHub:
```text
 [✓] Pushed remediation branch: fix/security-dependencies-1727725900
 [✓] Created Pull Request: https://github.com/my-org/my-app/pull/42
```
