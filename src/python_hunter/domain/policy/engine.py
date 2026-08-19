"""Security Policy and Gate Engine."""

from dataclasses import dataclass, field
from datetime import datetime
import logging
import os
from typing import Any
import json

from python_hunter.domain.common.enums import FindingLifecycleState, Severity
from python_hunter.domain.findings.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class SecurityPolicy:
    """Security policy configuration dataclass."""

    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    ignored_paths: list[str] = field(default_factory=lambda: ["tests/", "examples/", "fixtures/", "vendor/"])
    suppressions: list[dict[str, Any]] = field(default_factory=list)
    forbidden_dynamic_execution: bool = False
    forbidden_pickle: bool = False
    forbidden_dynamic_import: bool = False
    restricted_reflection: bool = False
    fail_on: Severity = Severity.HIGH
    max_critical: int = 0
    max_high: int = 5
    max_risk_score: float = 75.0



class SecurityPolicyEngine:
    """Evaluates security findings against project security policy and CI/CD security gates."""

    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        self.policy = policy or SecurityPolicy()

    @classmethod
    def from_config_file(cls, file_path: str) -> "SecurityPolicyEngine":
        """Load SecurityPolicyEngine from YAML or JSON policy file."""
        if not os.path.exists(file_path):
            return cls()
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Parse simple JSON or YAML key-values
                try:
                    data = json.loads(content)
                except Exception:
                    data = cls._parse_simple_yaml(content)
            
            policy = cls._build_policy(data)
            return cls(policy=policy)
        except Exception as e:
            logger.warning(f"Failed to load policy from {file_path}: {e}")
            return cls()

    @staticmethod
    def _parse_simple_yaml(content: str) -> dict[str, Any]:
        """Simple fallback YAML key-value parser without PyYAML dependency."""
        res: dict[str, Any] = {}
        curr_key = None
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if v:
                    res[k] = v
                else:
                    curr_key = k
                    res[curr_key] = []
            elif line.startswith("- ") and curr_key:
                val = line[2:].strip()
                if isinstance(res[curr_key], list):
                    res[curr_key].append(val)
        return res

    @staticmethod
    def _build_policy(data: dict[str, Any]) -> SecurityPolicy:
        policy_data = data.get("policy", data)
        sev_data = policy_data.get("severity", {})
        overrides = {}
        for r_id, sev_str in sev_data.items():
            try:
                overrides[r_id] = Severity(sev_str.upper())
            except ValueError:
                pass

        fail_on_str = policy_data.get("gate", {}).get("fail_on", "HIGH")
        try:
            fail_on_sev = Severity(fail_on_str.upper())
        except ValueError:
            fail_on_sev = Severity.HIGH

        return SecurityPolicy(
            severity_overrides=overrides,
            ignored_paths=policy_data.get("ignore", {}).get("paths", ["tests/", "examples/", "vendor/"]),
            suppressions=policy_data.get("suppressions", []),
            fail_on=fail_on_sev,
            max_critical=policy_data.get("limits", {}).get("critical", 0),
            max_high=policy_data.get("limits", {}).get("high", 5),
            max_risk_score=float(policy_data.get("limits", {}).get("max_risk_score", 75.0)),
        )

    def evaluate(self, findings: list[Finding], project_risk_score: float = 0.0) -> tuple[bool, list[str]]:
        """Evaluate findings and return (policy_passed, violations)."""
        violations: list[str] = []
        now = datetime.utcnow().strftime("%Y-%m-%d")

        for f in findings:
            # 1. Apply Severity Overrides
            if f.rule_id in self.policy.severity_overrides:
                f.severity = self.policy.severity_overrides[f.rule_id]

            # 2. Check Suppressions
            for supp in self.policy.suppressions:
                rule_match = supp.get("rule_id") is None or supp.get("rule_id") == f.rule_id
                fp_match = supp.get("fingerprint") is None or supp.get("fingerprint") == f.fingerprint
                file_match = supp.get("file") is None or supp.get("file") in f.file_path

                exp = supp.get("expires_at")
                not_expired = True
                if exp:
                    not_expired = now <= exp

                if rule_match and fp_match and file_match and not_expired:
                    f.lifecycle_state = FindingLifecycleState.SUPPRESSED
                    f.secondary_evidence.append(f"Suppressed by policy rule: {supp.get('reason', 'Policy Exception')}")
                    break

        # Active active findings (exclude suppressed)
        active_findings = [f for f in findings if f.lifecycle_state != FindingLifecycleState.SUPPRESSED]

        # 3. Security Gate Evaluation
        fail_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.5,
        }
        min_fail_weight = fail_weights.get(self.policy.fail_on, 7.5)

        for f in active_findings:
            if fail_weights.get(f.severity, 0.0) >= min_fail_weight:
                violations.append(
                    f"Finding [{f.rule_id}] '{f.title}' exceeds failure threshold ({self.policy.fail_on.value})"
                )

        crit_count = sum(1 for f in active_findings if f.severity == Severity.CRITICAL)
        if crit_count > self.policy.max_critical:
            violations.append(f"Critical findings count ({crit_count}) exceeds limit ({self.policy.max_critical})")

        high_count = sum(1 for f in active_findings if f.severity == Severity.HIGH)
        if high_count > self.policy.max_high:
            violations.append(f"High findings count ({high_count}) exceeds limit ({self.policy.max_high})")

        if project_risk_score > self.policy.max_risk_score:
            violations.append(
                f"Overall Project Risk Score ({project_risk_score}) exceeds limit ({self.policy.max_risk_score})"
            )

        passed = len(violations) == 0
        return passed, violations
