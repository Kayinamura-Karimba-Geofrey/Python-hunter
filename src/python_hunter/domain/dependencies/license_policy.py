"""License Intelligence, License Policy Engine, and Tamper Detection."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from python_hunter.domain.dependencies.models import Dependency


class LicenseAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


@dataclass
class LicensePolicyRule:
    allowed_licenses: Set[str] = field(default_factory=lambda: {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Unlicense", "CC0-1.0"})
    prohibited_licenses: Set[str] = field(default_factory=lambda: {"GPL-3.0", "AGPL-3.0", "SSPL-1.0"})
    review_required_licenses: Set[str] = field(default_factory=lambda: {"GPL-2.0", "LGPL-3.0", "MPL-2.0", "EPL-2.0"})


@dataclass
class LicenseEvaluationResult:
    dependency_name: str
    license: str
    action: LicenseAction
    reason: str


class LicensePolicyEngine:
    """Evaluates software dependencies against organizational open-source license policies."""

    def __init__(self, rule: Optional[LicensePolicyRule] = None) -> None:
        self.rule = rule or LicensePolicyRule()

    def evaluate_dependency(self, dep: Dependency) -> LicenseEvaluationResult:
        lic = dep.license.strip()
        if not lic or lic.upper() == "UNKNOWN":
            return LicenseEvaluationResult(
                dependency_name=dep.name,
                license="UNKNOWN",
                action=LicenseAction.REVIEW_REQUIRED,
                reason=f"License for dependency '{dep.name}' is unknown and requires manual review.",
            )

        upper_lic = lic.upper()

        for prohibited in self.rule.prohibited_licenses:
            if prohibited.upper() in upper_lic:
                return LicenseEvaluationResult(
                    dependency_name=dep.name,
                    license=lic,
                    action=LicenseAction.DENY,
                    reason=f"License '{lic}' for dependency '{dep.name}' violates organizational policy (Prohibited copyleft license).",
                )

        for review in self.rule.review_required_licenses:
            if review.upper() in upper_lic:
                return LicenseEvaluationResult(
                    dependency_name=dep.name,
                    license=lic,
                    action=LicenseAction.REVIEW_REQUIRED,
                    reason=f"License '{lic}' for dependency '{dep.name}' requires legal/security compliance review.",
                )

        for allowed in self.rule.allowed_licenses:
            if allowed.upper() in upper_lic:
                return LicenseEvaluationResult(
                    dependency_name=dep.name,
                    license=lic,
                    action=LicenseAction.ALLOW,
                    reason=f"License '{lic}' for dependency '{dep.name}' is compliant with policy.",
                )

        return LicenseEvaluationResult(
            dependency_name=dep.name,
            license=lic,
            action=LicenseAction.REVIEW_REQUIRED,
            reason=f"Unrecognized license '{lic}' for dependency '{dep.name}' requires evaluation.",
        )


class TamperDetectionEngine:
    """Detects suspicious lockfile hash mismatches and unexpected dependency origins."""

    @staticmethod
    def inspect_dependency(dep: Dependency) -> List[Dict[str, Any]]:
        warnings = []
        if dep.source and dep.source.url and "http://" in dep.source.url:
            warnings.append({
                "package": dep.name,
                "type": "UNENCRYPTED_SOURCE",
                "severity": "HIGH",
                "message": f"Dependency '{dep.name}' downloaded over unencrypted HTTP protocol ({dep.source.url}).",
            })

        if dep.integrity_hash and not (dep.integrity_hash.startswith("sha256-") or dep.integrity_hash.startswith("sha512-") or len(dep.integrity_hash) >= 32):
            warnings.append({
                "package": dep.name,
                "type": "SUSPICIOUS_INTEGRITY_HASH",
                "severity": "MEDIUM",
                "message": f"Dependency '{dep.name}' has malformed or weak integrity checksum.",
            })

        return warnings
