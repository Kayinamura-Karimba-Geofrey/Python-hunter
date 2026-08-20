"""Remediation Engine for safe dependency upgrades and breaking-change evaluation."""

from dataclasses import dataclass
from typing import Any, Dict, Optional
from python_hunter.domain.dependencies.models import Dependency
from python_hunter.domain.dependencies.semver_engine import SemVerEngine
from python_hunter.domain.dependencies.vulnerability_intel import Advisory


@dataclass
class RemediationRecommendation:
    package_name: str
    current_version: str
    recommended_version: str
    action: str  # UPGRADE, DOWNGRADE, MITIGATE
    breaking_change_risk: str  # NONE, LOW, HIGH
    reason: str
    mitigation_guidance: str


class RemediationEngine:
    """Calculates minimal safe upgrade paths and mitigation recommendations."""

    @staticmethod
    def generate_recommendation(dependency: Dependency, advisory: Advisory) -> RemediationRecommendation:
        curr_ver = dependency.version or "0.0.0"
        patched_ver = advisory.patched_versions or ""

        if not patched_ver:
            return RemediationRecommendation(
                package_name=dependency.name,
                current_version=curr_ver,
                recommended_version=curr_ver,
                action="MITIGATE",
                breaking_change_risk="NONE",
                reason=f"No known patched version available for advisory {advisory.identifier}.",
                mitigation_guidance="Apply network isolation, input sanitization, or temporary policy suppression until vendor patch is released.",
            )

        t_curr = SemVerEngine.parse_version_tuple(curr_ver)
        t_patch = SemVerEngine.parse_version_tuple(patched_ver)

        is_major_bump = t_patch[0] > t_curr[0]
        risk = "HIGH" if is_major_bump else "LOW"

        return RemediationRecommendation(
            package_name=dependency.name,
            current_version=curr_ver,
            recommended_version=patched_ver,
            action="UPGRADE",
            breaking_change_risk=risk,
            reason=f"Upgrade package '{dependency.name}' from {curr_ver} to patched version {patched_ver} to remediate {advisory.identifier}.",
            mitigation_guidance=f"Run test suite after upgrading to {patched_ver} to verify compatibility (Major version bump risk: {risk}).",
        )
