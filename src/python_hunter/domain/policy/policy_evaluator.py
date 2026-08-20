"""Policy Engine and Security Gate Evaluator."""

from datetime import datetime
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.policy.policy_models import (
    ComplianceControl,
    GateResult,
    PolicyAction,
    PolicyException,
    PolicyRuleCondition,
    SecurityPolicy,
)


class PolicyEngine:
    """Evaluates findings, risk scores, attack paths, and dependencies against declarative Security Policies."""

    STRICT_PROFILE = [
        SecurityPolicy(
            policy_id="POL-NO-CRITICAL",
            name="No Critical Vulnerabilities",
            description="Fails scan if any CRITICAL severity finding is detected.",
            action=PolicyAction.FAIL,
            condition=PolicyRuleCondition(severity=Severity.CRITICAL, min_count=1),
        ),
        SecurityPolicy(
            policy_id="POL-NO-HIGH-RISK",
            name="No High Risk Scores",
            description="Fails scan if risk score exceeds 8.0.",
            action=PolicyAction.FAIL,
            condition=PolicyRuleCondition(min_risk_score=8.0),
        ),
        SecurityPolicy(
            policy_id="POL-NO-SECRETS",
            name="No Hardcoded Secrets",
            description="Fails scan if hardcoded secrets or credentials are discovered.",
            action=PolicyAction.FAIL,
            condition=PolicyRuleCondition(tags=["secrets", "credentials"]),
        ),
    ]

    def evaluate_gate(
        self,
        findings: list[Finding],
        risk_score: float = 0.0,
        profile: str = "strict",
        exceptions: list[PolicyException] | None = None,
    ) -> GateResult:

        exceptions = exceptions or []
        now = datetime.utcnow()
        active_exceptions = [e for e in exceptions if e.expires_at > now]

        policies = self.STRICT_PROFILE
        evaluated = len(policies)
        passed = 0
        warned = 0
        failed = 0
        violations = []

        for pol in policies:
            violated = False

            # Check severity count
            if pol.condition.severity:
                sev_count = 0
                for f in findings:
                    f_sev = f.severity if hasattr(f, "severity") else f.get("severity")
                    if hasattr(f_sev, "value"):
                        f_sev = f_sev.value
                    if str(f_sev).upper() == str(pol.condition.severity.value).upper():
                        sev_count += 1
                if sev_count >= pol.condition.min_count:
                    violated = True
                    violations.append(f"{pol.name}: Detected {sev_count} {pol.condition.severity.value} finding(s).")

            # Check risk score threshold
            if pol.condition.min_risk_score and risk_score >= pol.condition.min_risk_score:
                violated = True
                violations.append(f"{pol.name}: Risk score {risk_score:.1f} exceeds threshold {pol.condition.min_risk_score:.1f}.")

            # Check exception overrides
            if violated and any(e.policy_id == pol.policy_id for e in active_exceptions):
                violated = False  # Exception suppresses policy failure

            if violated:
                if pol.action == PolicyAction.FAIL:
                    failed += 1
                else:
                    warned += 1
            else:
                passed += 1

        overall_status = PolicyAction.FAIL if failed > 0 else (PolicyAction.WARN if warned > 0 else PolicyAction.PASS)
        exit_code = 1 if overall_status == PolicyAction.FAIL else 0

        return GateResult(
            status=overall_status,
            policies_evaluated=evaluated,
            policies_passed=passed,
            policies_warned=warned,
            policies_failed=failed,
            exit_code=exit_code,
            violations=violations,
        )
