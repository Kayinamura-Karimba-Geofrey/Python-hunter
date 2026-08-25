"""Intelligent Risk Prioritization Engine using contextual organizational evidence."""

from typing import List
from python_hunter.domain.ai.models import (
    AIConfidence, AssetCriticality, EnvironmentType, InternetExposure, RiskAssessment, SecurityContext
)
from python_hunter.domain.findings.finding import Finding


class IntelligentPrioritizationEngine:
    """Ranks and prioritizes security findings according to actual organizational risk rather than raw severity alone."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 90.0,
        "HIGH": 70.0,
        "MEDIUM": 40.0,
        "LOW": 10.0,
        "INFO": 0.0
    }

    def prioritize(self, finding: Finding, context: SecurityContext) -> RiskAssessment:
        base_sev = finding.severity.value if hasattr(finding, 'severity') and hasattr(finding.severity, 'value') else "MEDIUM"
        base_score = self.SEVERITY_WEIGHTS.get(base_sev.upper(), 50.0)

        multiplier = 1.0

        # Exposure multiplier
        if context.internet_exposure == InternetExposure.INTERNET_FACING:
            multiplier += 0.4
        elif context.internet_exposure == InternetExposure.INTERNAL:
            multiplier -= 0.1

        # Asset criticality multiplier
        if context.asset_criticality == AssetCriticality.CRITICAL:
            multiplier += 0.3
        elif context.asset_criticality == AssetCriticality.HIGH:
            multiplier += 0.2
        elif context.asset_criticality == AssetCriticality.LOW:
            multiplier -= 0.2

        # Environment awareness
        if context.environment == EnvironmentType.PRODUCTION or context.is_production:
            multiplier += 0.3

        adjusted_score = min(100.0, round(base_score * multiplier, 1))

        # Determine adjusted priority rank
        if adjusted_score >= 85.0:
            priority = "P1_URGENT"
        elif adjusted_score >= 65.0:
            priority = "P2_HIGH"
        elif adjusted_score >= 40.0:
            priority = "P3_MEDIUM"
        else:
            priority = "P4_LOW"

        why = (
            f"Evaluated original {base_sev} severity against organizational context. "
            f"Asset Criticality: {context.asset_criticality.value}, "
            f"Exposure: {context.internet_exposure.value}, "
            f"Environment: {context.environment.value}. "
            f"Adjusted risk score: {adjusted_score}/100."
        )

        loc_desc = f"{finding.location.file_path}:{finding.location.start_line}" if finding.location else "global"
        evidence = [
            f"Scanner Finding: {finding.rule_id} ({finding.title})",
            f"Location: {loc_desc}",
            f"Target Repository: {context.repository}",
            f"Environment: {context.environment.value}"
        ]

        return RiskAssessment(
            finding_id=getattr(finding, 'id', 'f-1'),
            original_severity=base_sev,
            contextual_priority=priority,
            adjusted_score=adjusted_score,
            why_high_risk=why,
            evidence_used=evidence,
            confidence=AIConfidence.HIGH
        )
