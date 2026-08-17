"""Correlation, Attack Path, and Security Posture Domain Models."""

from dataclasses import dataclass, field
import uuid
from typing import Any

from python_hunter.domain.common.enums import (
    AttackPathType,
    Confidence,
    FindingRelationType,
    FindingStatus,
    Severity,
)
from python_hunter.domain.findings.finding import Finding


@dataclass
class FindingRelationship:
    """Relationship link between two security findings."""

    source_finding_id: str
    target_finding_id: str
    relation_type: FindingRelationType
    description: str = ""


@dataclass
class RiskScoreExplanation:
    """Detailed breakdown of factors contributing to a finding's risk score."""

    base_severity_score: float
    confidence_multiplier: float
    reachability_bonus: float = 0.0
    exposure_bonus: float = 0.0
    taint_context_bonus: float = 0.0
    asset_criticality_bonus: float = 0.0
    data_sensitivity_bonus: float = 0.0
    final_score: float = 0.0

    def to_dict(self) -> dict[str, float]:
        """Return factor dictionary for transparent display."""
        return {
            "Base Severity Score": self.base_severity_score,
            "Confidence Multiplier": self.confidence_multiplier,
            "Reachability Bonus": self.reachability_bonus,
            "Exposure Bonus": self.exposure_bonus,
            "Taint Context Bonus": self.taint_context_bonus,
            "Asset Criticality Bonus": self.asset_criticality_bonus,
            "Data Sensitivity Bonus": self.data_sensitivity_bonus,
            "Final Risk Score": self.final_score,
        }


@dataclass
class AttackPathNode:
    """Single node along a multi-step security attack path."""

    step_number: int
    label: str
    file_path: str
    line_number: int = 0
    node_type: str = "INTERMEDIATE"  # ENTRY, TAINT_SOURCE, CALL_SITE, SINK
    code_snippet: str = ""


@dataclass
class AttackPath:
    """Correlated attack path chain exposing high-risk security paths."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: AttackPathType = AttackPathType.REMOTE_CODE_EXECUTION
    title: str = ""
    entry_point: str = ""
    target_sink: str = ""
    nodes: list[AttackPathNode] = field(default_factory=list)
    associated_finding_ids: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: Confidence = Confidence.HIGH
    explanation: str = ""


@dataclass
class SecurityPosture:
    """Overall project-level security posture summary."""

    total_findings: int = 0
    project_risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    new_count: int = 0
    existing_count: int = 0
    suppressed_count: int = 0
    resolved_count: int = 0
    reopened_count: int = 0
    attack_path_count: int = 0
    policy_passed: bool = True
    policy_violations: list[str] = field(default_factory=list)
