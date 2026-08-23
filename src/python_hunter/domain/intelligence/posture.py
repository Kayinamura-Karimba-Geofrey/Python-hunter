"""Security Posture tracking, Posture Comparison, and Report Generation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from python_hunter.domain.intelligence.remediation import RemediationItem


@dataclass
class SecurityPosture:
    """Security Posture state snapshot."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    security_score: float = 100.0
    current_risk_score: float = 0.0
    critical_vulnerabilities_count: int = 0
    high_vulnerabilities_count: int = 0
    attack_paths_count: int = 0
    verified_vulnerabilities_count: int = 0
    overdue_sla_count: int = 0
    unresolved_findings_count: int = 0


class SecurityPostureTracker:
    """Calculates security posture snapshots, compares historical posture, and generates reports."""

    def __init__(self) -> None:
        self.snapshots: list[SecurityPosture] = []

    def capture_posture(
        self,
        items: list[RemediationItem],
        attack_paths_count: int = 0,
        security_score: float = 85.0,
    ) -> SecurityPosture:
        """Capture and record a new Security Posture snapshot."""
        crit_count = sum(1 for i in items if i.severity.value == "CRITICAL" and not i.resolved_at)
        high_count = sum(1 for i in items if i.severity.value == "HIGH" and not i.resolved_at)
        verified_count = sum(1 for i in items if i.is_verified and not i.resolved_at)
        overdue_count = sum(1 for i in items if i.is_overdue)
        unresolved_count = sum(1 for i in items if not i.resolved_at)
        tot_risk = sum(i.risk_score for i in items if not i.resolved_at)

        posture = SecurityPosture(
            timestamp=datetime.now(timezone.utc),
            security_score=security_score,
            current_risk_score=round(tot_risk, 2),
            critical_vulnerabilities_count=crit_count,
            high_vulnerabilities_count=high_count,
            attack_paths_count=attack_paths_count,
            verified_vulnerabilities_count=verified_count,
            overdue_sla_count=overdue_count,
            unresolved_findings_count=unresolved_count,
        )
        self.snapshots.append(posture)
        return posture

    def compare_posture(self, current: SecurityPosture, previous: SecurityPosture) -> dict[str, Any]:
        """Compare current posture vs previous posture."""
        score_diff = current.security_score - previous.security_score
        risk_diff = current.current_risk_score - previous.current_risk_score

        trend = "stable"
        if risk_diff > 5.0 or score_diff < -5.0:
            trend = "risk_increasing"
        elif risk_diff < -5.0 or score_diff > 5.0:
            trend = "risk_decreasing"

        return {
            "trend": trend,
            "security_score_change": round(score_diff, 2),
            "risk_score_change": round(risk_diff, 2),
            "critical_change": current.critical_vulnerabilities_count - previous.critical_vulnerabilities_count,
            "overdue_change": current.overdue_sla_count - previous.overdue_sla_count,
        }

    def generate_executive_summary(self, posture: SecurityPosture) -> dict[str, Any]:
        """Generate high-level executive report without exposing sensitive raw source code."""
        return {
            "title": "Executive Security Summary",
            "security_score": posture.security_score,
            "risk_status": "HIGH_RISK" if posture.critical_vulnerabilities_count > 0 else "LOW_RISK",
            "critical_risks": posture.critical_vulnerabilities_count,
            "major_attack_paths": posture.attack_paths_count,
            "sla_breaches": posture.overdue_sla_count,
            "verified_vulnerabilities": posture.verified_vulnerabilities_count,
            "timestamp": posture.timestamp.isoformat(),
        }

    def generate_technical_summary(self, posture: SecurityPosture, items: list[RemediationItem]) -> dict[str, Any]:
        """Generate detailed technical report for security engineers."""
        return {
            "title": "Detailed Technical Security Intelligence Report",
            "posture": posture,
            "unresolved_items": [
                {
                    "id": i.id,
                    "vuln_id": i.vulnerability_id,
                    "repo": i.repository,
                    "severity": i.severity.value,
                    "reachable": i.is_reachable,
                    "verified": i.is_verified,
                    "overdue": i.is_overdue,
                }
                for i in items
                if not i.resolved_at
            ],
        }
