"""Security Knowledge Base and CWE / SAST Rule Intelligence."""

from dataclasses import dataclass, field
from typing import Any

from python_hunter.domain.intelligence.models import VulnerabilityRecord


@dataclass
class CWENode:
    """CWE Weakness representation."""

    cwe_id: str  # e.g., "CWE-89"
    name: str  # e.g., "SQL Injection"
    description: str = ""
    category: str = "Web Security"
    parent_cwe: str | None = None


@dataclass
class RemediationKnowledge:
    """Remediation recommendation details."""

    remediation_type: str  # "upgrade", "configuration_change", "code_change", "permission_reduction", "architecture_change"
    description: str
    recommended_version: str | None = None
    priority_score: float = 0.0
    effort_level: str = "low"  # low, medium, high


class SecurityKnowledgeBase:
    """Central Security Knowledge Base linking Vulnerabilities <-> CWE <-> SAST Rules <-> Remediation Knowledge."""

    def __init__(self) -> None:
        self._vulnerabilities: dict[str, VulnerabilityRecord] = {}
        self._cwes: dict[str, CWENode] = {}
        self._rule_cwe_map: dict[str, str] = {}  # rule_id -> cwe_id
        self._remediations: dict[str, RemediationKnowledge] = {}
        self._init_default_cwes()

    def _init_default_cwes(self) -> None:
        """Populate baseline CWE entries."""
        defaults = [
            CWENode("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", category="Injection"),
            CWENode("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('Command Injection')", category="Injection"),
            CWENode("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", category="Web Security"),
            CWENode("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", category="File Security"),
            CWENode("CWE-502", "Deserialization of Untrusted Data", category="Object Handling"),
            CWENode("CWE-798", "Use of Hard-coded Credentials", category="Secrets"),
            CWENode("CWE-1104", "Use of Unmaintained Third Party Components", category="SCA"),
        ]
        for c in defaults:
            self._cwes[c.cwe_id] = c

    def register_vulnerability(self, record: VulnerabilityRecord) -> None:
        """Register vulnerability record in knowledge base."""
        self._vulnerabilities[record.vulnerability_id] = record
        for alias in record.aliases:
            self._vulnerabilities[alias] = record

    def map_rule_to_cwe(self, rule_id: str, cwe_id: str) -> None:
        """Associate a SAST rule with a CWE identifier."""
        self._rule_cwe_map[rule_id] = cwe_id

    def get_cwe_for_rule(self, rule_id: str) -> CWENode | None:
        """Retrieve CWE node for a SAST rule."""
        cwe_id = self._rule_cwe_map.get(rule_id)
        if cwe_id:
            return self._cwes.get(cwe_id)
        return None

    def get_remediation_for_vulnerability(self, vuln_id: str) -> RemediationKnowledge | None:
        """Build remediation guidance for a given vulnerability."""
        vuln = self._vulnerabilities.get(vuln_id)
        if not vuln:
            return None

        if vuln.fixed_versions:
            rec_ver = vuln.fixed_versions[-1]
            return RemediationKnowledge(
                remediation_type="upgrade",
                description=f"Upgrade package to safe version {rec_ver} or higher.",
                recommended_version=rec_ver,
                priority_score=9.0 if vuln.severity.value in ("CRITICAL", "HIGH") else 5.0,
                effort_level="low",
            )
        return RemediationKnowledge(
            remediation_type="configuration_change",
            description="No direct fixed version available. Apply compensating controls or network isolation.",
            priority_score=6.0,
            effort_level="medium",
        )
