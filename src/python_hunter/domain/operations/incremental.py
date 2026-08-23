"""ChangeImpactEngine & SecurityDriftEngine for incremental security analysis."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImpactScope:
    """Calculated scope of a code/dependency/infra change."""

    changed_files: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)
    affected_dependencies: list[str] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)
    affected_attack_paths: list[str] = field(default_factory=list)
    requires_full_rescan: bool = False


class ChangeImpactEngine:
    """Analyzes commit/PR/dependency changes to perform targeted incremental analysis."""

    def calculate_impact(
        self,
        repository: str,
        changed_files: list[str],
        dependency_manifest_changed: bool = False,
        infrastructure_changed: bool = False,
    ) -> ImpactScope:
        """Determines impacted components to limit analysis scope."""
        affected_funcs = []
        affected_paths = []

        for f in changed_files:
            if "auth" in f or "login" in f:
                affected_funcs.append("authenticate_user")
                affected_paths.append("AP-AUTH-01")
            if "db" in f or "models" in f:
                affected_funcs.append("execute_query")
                affected_paths.append("AP-SQLI-01")

        full_rescan = dependency_manifest_changed or infrastructure_changed or len(changed_files) > 50

        return ImpactScope(
            changed_files=changed_files,
            affected_functions=affected_funcs,
            affected_dependencies=["requests"] if dependency_manifest_changed else [],
            affected_services=["Auth Service"],
            affected_attack_paths=affected_paths,
            requires_full_rescan=full_rescan,
        )


@dataclass
class SecurityDrift:
    """Security drift detection outcome."""

    drift_type: str  # "POSTURE_DEGRADED", "RISK_INCREASED", "EXPOSURE_EXPANDED"
    severity: str
    description: str
    previous_value: Any
    current_value: Any


class SecurityDriftEngine:
    """Detects security posture drift between state snapshots."""

    def evaluate_drift(self, previous_posture: dict[str, Any], current_posture: dict[str, Any]) -> list[SecurityDrift]:
        """Compare two posture snapshots and highlight security regressions or drift."""
        drifts = []

        prev_score = previous_posture.get("security_score", 100)
        curr_score = current_posture.get("security_score", 100)
        if curr_score < prev_score:
            drifts.append(
                SecurityDrift(
                    drift_type="POSTURE_DEGRADED",
                    severity="HIGH",
                    description=f"Security score dropped from {prev_score} to {curr_score}",
                    previous_value=prev_score,
                    current_value=curr_score,
                )
            )

        prev_crit = previous_posture.get("critical_count", 0)
        curr_crit = current_posture.get("critical_count", 0)
        if curr_crit > prev_crit:
            drifts.append(
                SecurityDrift(
                    drift_type="RISK_INCREASED",
                    severity="CRITICAL",
                    description=f"Critical vulnerabilities increased by +{curr_crit - prev_crit}",
                    previous_value=prev_crit,
                    current_value=curr_crit,
                )
            )

        return drifts
