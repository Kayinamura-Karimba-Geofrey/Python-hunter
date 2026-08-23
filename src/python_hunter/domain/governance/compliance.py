"""Security Control Mapping and Compliance Framework models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ComplianceFramework(str, Enum):
    """Supported security compliance frameworks."""

    OWASP_TOP_10 = "OWASP Top 10"
    CWE_TOP_25 = "CWE Top 25"
    NIST_SP_800_53 = "NIST SP 800-53"
    ISO_27001 = "ISO 27001"
    SOC_2 = "SOC 2"


class ComplianceStatus(str, Enum):
    """Compliance evaluation status."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class SecurityControl:
    """Security Control mapping definition."""

    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    mapped_cwes: list[str] = field(default_factory=list)


@dataclass
class ComplianceEvidence:
    """Compliance Evidence collected from security scans."""

    evidence_id: str
    organization_id: str
    control_id: str
    finding_id: str
    status: ComplianceStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)


class ComplianceEngine:
    """Maps findings and CWEs to compliance frameworks and generates evidence reports."""

    DEFAULT_CONTROLS = [
        SecurityControl("A01:2021", ComplianceFramework.OWASP_TOP_10, "Broken Access Control", "Restrict unauthorized access.", ["CWE-285", "CWE-862"]),
        SecurityControl("A03:2021", ComplianceFramework.OWASP_TOP_10, "Injection", "Prevent SQL, OS, and Code Injection.", ["CWE-89", "CWE-78"]),
        SecurityControl("CC6.1", ComplianceFramework.SOC_2, "Logical Access Controls", "Manage credentials and identity.", ["CWE-798"]),
    ]

    def map_finding_to_compliance(self, organization_id: str, finding_id: str, cwe_id: str) -> list[ComplianceEvidence]:
        """Map a finding's CWE to matching compliance controls and record evidence."""
        evidences = []
        for ctrl in self.DEFAULT_CONTROLS:
            if cwe_id in ctrl.mapped_cwes:
                ev = ComplianceEvidence(
                    evidence_id=f"EVD-{finding_id}-{ctrl.control_id}",
                    organization_id=organization_id,
                    control_id=ctrl.control_id,
                    finding_id=finding_id,
                    status=ComplianceStatus.FAIL,
                )
                evidences.append(ev)
        return evidences
