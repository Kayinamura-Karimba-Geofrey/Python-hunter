"""Pull Request Security Engine — BASE vs HEAD Security Delta & Risk Classifier."""

import logging
import re
from typing import Any, Dict, List, Set, Tuple

from python_hunter.domain.github.github_models import (
    PolicyResultStatus,
    PullRequestSecurityResult,
    PullRequestSecuritySummary,
)
from python_hunter.domain.policy.policy_evaluator import PolicyEngine

logger = logging.getLogger("python_hunter.pr_security")

# Security-relevant file patterns
SECURITY_RELEVANT_PATTERNS = [
    r"auth",
    r"security",
    r"login",
    r"token",
    r"session",
    r"middleware",
    r"permission",
    r"policy",
    r"route",
    r"api",
    r"config",
    r"docker",
    r"k8s",
    r"requirements",
    r"package\.json",
    r"poetry\.lock",
    r"yarn\.lock",
    r"pnpm-lock\.yaml",
]

DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


class SecretRedactor:
    """Ensures raw secrets are NEVER outputted to logs, comments, annotations, or API responses."""

    @staticmethod
    def redact_secret(val: str) -> str:
        if not val:
            return ""
        val_str = str(val)
        if len(val_str) <= 6:
            return "******"
        return f"{val_str[:3]}****{val_str[-3:]}"

    @classmethod
    def redact_finding_dict(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(finding)
        # Redact snippet or title if secret detected
        if "code_snippet" in redacted and redacted["code_snippet"]:
            snippet = redacted["code_snippet"]
            # Look for common secret patterns (tokens, API keys, passwords)
            snippet = re.sub(r'(?i)(api[_-]?key|secret|password|token|bearer)\s*=\s*["\']([^"\']+)["\']',
                             lambda m: f'{m.group(1)}="{cls.redact_secret(m.group(2))}"', snippet)
            redacted["code_snippet"] = snippet
        return redacted


class PullRequestSecurityEngine:
    """Analyzes security deltas between BASE target branch and HEAD PR branch."""

    def __init__(self) -> None:
        self.policy_engine = PolicyEngine()
        self.redactor = SecretRedactor()

    @staticmethod
    def classify_security_relevant_files(changed_files: List[str]) -> List[str]:
        """Identifies changes to authentication, authorization, middleware, routing, dependencies, infra."""
        relevant = []
        for file_path in changed_files:
            lower = file_path.lower()
            if any(re.search(pat, lower) for pat in SECURITY_RELEVANT_PATTERNS):
                relevant.append(file_path)
        return relevant

    def analyze_pull_request(
        self,
        pr_number: int,
        repository: str,
        base_sha: str,
        head_sha: str,
        base_findings: List[Dict[str, Any]],
        head_findings: List[Dict[str, Any]],
        base_attack_paths: List[Dict[str, Any]],
        head_attack_paths: List[Dict[str, Any]],
        changed_files: List[str],
        base_dependencies: List[Dict[str, Any]],
        head_dependencies: List[Dict[str, Any]],
    ) -> PullRequestSecurityResult:
        """Compares BASE snapshot against HEAD snapshot to derive exact security deltas."""
        base_by_id = {f["id"]: f for f in base_findings}
        head_by_id = {f["id"]: f for f in head_findings}

        base_ids = set(base_by_id.keys())
        head_ids = set(head_by_id.keys())

        # New findings introduced by PR (present in HEAD but not BASE)
        new_ids = head_ids - base_ids
        fixed_ids = base_ids - head_ids

        new_findings = [self.redactor.redact_finding_dict(head_by_id[fid]) for fid in new_ids]
        fixed_findings = [base_by_id[fid] for fid in fixed_ids]

        # Reopened findings (findings that were previously marked resolved but reappeared in head)
        reopened_findings = [
            self.redactor.redact_finding_dict(head_by_id[fid])
            for fid in new_ids
            if head_by_id[fid].get("status") == "REOPENED"
        ]

        # Attack paths delta
        base_ap_ids = {ap["id"] for ap in base_attack_paths}
        head_ap_ids = {ap["id"] for ap in head_attack_paths}
        new_ap = [ap for ap in head_attack_paths if ap["id"] not in base_ap_ids]
        fixed_ap = [ap for ap in base_attack_paths if ap["id"] not in head_ap_ids]

        # Dependency regressions
        dependency_regressions = self._detect_dependency_regressions(
            base_dependencies, head_dependencies, changed_files
        )

        # Secret regressions
        secret_regressions = [
            f for f in new_findings
            if "SECRET" in f.get("rule_id", "").upper() or "SECRET" in f.get("title", "").upper()
        ]

        # Score & Risk calculation
        base_score = self._calculate_score(base_findings)
        head_score = self._calculate_score(head_findings)
        score_delta = head_score - base_score

        base_risk = self._calculate_total_risk(base_findings)
        head_risk = self._calculate_total_risk(head_findings)
        risk_delta = round(head_risk - base_risk, 2)

        # Diff-aware prioritization
        relevant_files = self.classify_security_relevant_files(changed_files)

        # Risk classification
        if any(f.get("severity") == "CRITICAL" for f in new_findings) or secret_regressions:
            risk_classification = "CRITICAL"
        elif any(f.get("severity") == "HIGH" for f in new_findings) or dependency_regressions:
            risk_classification = "HIGH"
        elif any(f.get("severity") == "MEDIUM" for f in new_findings):
            risk_classification = "MEDIUM"
        else:
            risk_classification = "LOW"

        # Policy Gate Evaluation
        gate_res = self.policy_engine.evaluate_gate(head_findings, risk_score=head_risk, profile="strict")
        if gate_res.status.value == "FAIL":
            policy_result = PolicyResultStatus.FAIL
        elif gate_res.status.value == "WARN":
            policy_result = PolicyResultStatus.WARN
        else:
            policy_result = PolicyResultStatus.PASS

        return PullRequestSecurityResult(
            pr_number=pr_number,
            repository=repository,
            base_sha=base_sha,
            head_sha=head_sha,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            reopened_findings=reopened_findings,
            new_attack_paths=new_ap,
            fixed_attack_paths=fixed_ap,
            dependency_regressions=dependency_regressions,
            secret_regressions=secret_regressions,
            changed_files=changed_files,
            security_relevant_files=relevant_files,
            risk_delta=risk_delta,
            score_delta=score_delta,
            base_score=base_score,
            head_score=head_score,
            risk_classification=risk_classification,
            policy_result=policy_result,
            policy_violations=gate_res.violations,
        )

    def generate_summary(self, res: PullRequestSecurityResult, pr_info: Dict[str, Any]) -> PullRequestSecuritySummary:
        """Generates machine-readable and Human-readable markdown summary of PR security analysis."""
        pr_id = str(pr_info.get("id", f"pr-{res.pr_number}"))
        title = pr_info.get("title", f"Pull Request #{res.pr_number}")
        author = pr_info.get("author", "developer")
        base_branch = pr_info.get("base_branch", "main")
        head_branch = pr_info.get("head_branch", "feature")

        md = f"""### 🛡️ Python Hunter Security Analysis — PR #{res.pr_number}

**Security Gate Status:** `{res.policy_result.value}` | **Risk Level:** `{res.risk_classification}`

| Metric | Base (`{res.base_sha[:7]}`) | Head (`{res.head_sha[:7]}`) | Delta |
| :--- | :---: | :---: | :---: |
| **Security Score** | **{res.base_score}/100** | **{res.head_score}/100** | `{res.score_delta:+d}` |
| **Vulnerabilities** | {len(res.new_findings) + len(res.fixed_findings)} | {len(res.new_findings)} new | `+{len(res.new_findings)} / -{len(res.fixed_findings)}` |
| **Attack Paths** | {len(res.fixed_attack_paths)} | {len(res.new_attack_paths)} | `+{len(res.new_attack_paths)} / -{len(res.fixed_attack_paths)}` |

#### 📊 Finding Breakdown:
- **New Vulnerabilities Introduced:** `{len(res.new_findings)}`
- **Vulnerabilities Fixed:** `{len(res.fixed_findings)}`
- **Dependency Regressions:** `{len(res.dependency_regressions)}`
- **Secrets Detected:** `{len(res.secret_regressions)}`
"""
        if res.policy_violations:
            md += "\n#### ❌ Policy Gate Violations:\n"
            for v in res.policy_violations:
                md += f"- {v}\n"

        return PullRequestSecuritySummary(
            pr_id=pr_id,
            pr_number=res.pr_number,
            repository=res.repository,
            title=title,
            author=author,
            base_branch=base_branch,
            head_branch=head_branch,
            head_sha=res.head_sha,
            status=res.policy_result.value,
            security_score=res.head_score,
            score_delta=res.score_delta,
            risk_level=res.risk_classification,
            policy_result=res.policy_result,
            new_vulnerabilities_count=len(res.new_findings),
            fixed_vulnerabilities_count=len(res.fixed_findings),
            new_attack_paths_count=len(res.new_attack_paths),
            dependency_regressions_count=len(res.dependency_regressions),
            secrets_found_count=len(res.secret_regressions),
            summary_markdown=md,
        )

    def _detect_dependency_regressions(
        self,
        base_deps: List[Dict[str, Any]],
        head_deps: List[Dict[str, Any]],
        changed_files: List[str],
    ) -> List[Dict[str, Any]]:
        """Detects vulnerable dependency packages introduced by changed dependency files."""
        has_dep_change = any(f.lower() in DEPENDENCY_FILES or any(f.endswith(df) for df in DEPENDENCY_FILES) for f in changed_files)
        if not has_dep_change:
            return []

        base_vuln = {d["package_name"]: d for d in base_deps if d.get("vulnerability_status") == "VULNERABLE"}
        head_vuln = {d["package_name"]: d for d in head_deps if d.get("vulnerability_status") == "VULNERABLE"}

        regressions = []
        for pkg, dep in head_vuln.items():
            if pkg not in base_vuln:
                regressions.append(dep)
        return regressions

    @staticmethod
    def _calculate_score(findings: List[Dict[str, Any]]) -> int:
        score = 100
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev == "CRITICAL":
                score -= 15
            elif sev == "HIGH":
                score -= 8
            elif sev == "MEDIUM":
                score -= 3
            elif sev == "LOW":
                score -= 1
        return max(0, score)

    @staticmethod
    def _calculate_total_risk(findings: List[Dict[str, Any]]) -> float:
        return sum(f.get("risk_score", 5.0) for f in findings)
