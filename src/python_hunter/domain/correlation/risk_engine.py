"""Risk Scoring and Security Posture Engine."""

import logging
from typing import Any

from python_hunter.domain.common.enums import (
    AssetCriticality,
    Category,
    Confidence,
    ExposureType,
    FindingLifecycleState,
    ReachabilityType,
    Severity,
)
from python_hunter.domain.correlation.models import (
    AttackPath,
    RiskScoreExplanation,
    SecurityPosture,
)
from python_hunter.domain.findings.finding import Finding

logger = logging.getLogger(__name__)


class RiskEngine:
    """Calculates numerical risk scores and project-level security posture."""

    def __init__(self, critical_paths: list[str] | None = None) -> None:
        self.critical_paths = critical_paths or ["auth", "security", "payment", "api", "infra"]

    def score_findings(self, findings: list[Finding]) -> None:
        """Calculate and assign 0-100 numerical risk score to each finding in-place."""
        for f in findings:
            exp = self.evaluate_finding_risk(f)
            f.risk_score = exp.final_score
            f.metadata["risk_explanation"] = exp.to_dict()

    def evaluate_finding_risk(self, finding: Finding) -> RiskScoreExplanation:
        """Evaluate transparent risk score breakdown for a single finding."""
        base_scores = {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 30.0,
            Severity.MEDIUM: 20.0,
            Severity.LOW: 10.0,
            Severity.INFO: 2.0,
        }
        base_score = base_scores.get(finding.severity, 10.0)
        mult = finding.confidence.multiplier

        # Calculate bonuses
        reach_bonus = 0.0
        if finding.reachability == ReachabilityType.REACHABLE:
            reach_bonus = 20.0
        elif finding.reachability == ReachabilityType.STATIC_REACHABILITY:
            reach_bonus = 15.0
        elif finding.reachability == ReachabilityType.UNREACHABLE:
            reach_bonus = -10.0

        exp_bonus = 0.0
        if finding.exposure == ExposureType.INTERNET_FACING:
            exp_bonus = 20.0
        elif finding.exposure == ExposureType.AUTHENTICATED:
            exp_bonus = 10.0
        elif finding.exposure == ExposureType.INTERNAL:
            exp_bonus = 5.0

        taint_bonus = 0.0
        if finding.category in (Category.TAINT, Category.INJECTION, Category.CODE_INJECTION) or (finding.source and finding.sink):
            taint_bonus = 15.0

        asset_bonus = 0.0
        if any(cp in finding.file_path.lower() for cp in self.critical_paths):
            asset_bonus = 10.0

        subtotal = (base_score * mult) + reach_bonus + exp_bonus + taint_bonus + asset_bonus
        final_score = max(0.0, min(100.0, round(subtotal, 1)))

        return RiskScoreExplanation(
            base_severity_score=base_score,
            confidence_multiplier=mult,
            reachability_bonus=reach_bonus,
            exposure_bonus=exp_bonus,
            taint_context_bonus=taint_bonus,
            asset_criticality_bonus=asset_bonus,
            final_score=final_score,
        )

    def calculate_posture(
        self,
        findings: list[Finding],
        attack_paths: list[AttackPath],
        policy_passed: bool = True,
        policy_violations: list[str] | None = None,
    ) -> SecurityPosture:
        """Calculate overall project security posture."""
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        new_cnt = sum(1 for f in findings if f.lifecycle_state == FindingLifecycleState.NEW)
        exist_cnt = sum(1 for f in findings if f.lifecycle_state == FindingLifecycleState.EXISTING)
        supp_cnt = sum(1 for f in findings if f.lifecycle_state == FindingLifecycleState.SUPPRESSED)
        res_cnt = sum(1 for f in findings if f.lifecycle_state == FindingLifecycleState.RESOLVED)
        reop_cnt = sum(1 for f in findings if f.lifecycle_state == FindingLifecycleState.REOPENED)

        # Calculate project overall risk score (weighted top risks)
        sorted_scores = sorted([f.risk_score for f in findings if f.lifecycle_state != FindingLifecycleState.SUPPRESSED], reverse=True)
        if sorted_scores:
            top_5 = sorted_scores[:5]
            project_risk = min(100.0, round(top_5[0] * 0.5 + sum(top_5[1:]) * 0.125, 1))
        else:
            project_risk = 0.0

        return SecurityPosture(
            total_findings=len(findings),
            project_risk_score=project_risk,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            new_count=new_cnt,
            existing_count=exist_cnt,
            suppressed_count=supp_cnt,
            resolved_count=res_cnt,
            reopened_count=reop_cnt,
            attack_path_count=len(attack_paths),
            policy_passed=policy_passed,
            policy_violations=policy_violations or [],
        )
