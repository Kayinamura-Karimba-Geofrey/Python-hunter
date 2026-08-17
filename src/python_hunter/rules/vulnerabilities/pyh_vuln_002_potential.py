"""PYH-VULN-002: Potentially Affected Dependency Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import VulnerabilityMatch, VulnerabilityStatus


class PYHVuln002Potential:
    """Detector for dependencies with unpinned version constraints overlapping affected vulnerability ranges."""

    id = "PYH-VULN-002"
    name = "Potentially Affected Dependency"
    category = Category.VULNERABLE_DEPENDENCY
    confidence = Confidence.MEDIUM

    def evaluate_match(self, match: VulnerabilityMatch) -> Finding | None:
        if match.status != VulnerabilityStatus.POTENTIALLY_AFFECTED:
            return None

        vuln = match.vulnerability
        dep = match.dependency
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))

        # Adjust severity: medium/high potential vulnerability
        severity = Severity.MEDIUM if vuln.severity in (Severity.LOW, Severity.INFO) else Severity.HIGH

        return Finding(
            rule_id=self.id,
            severity=severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Potentially Vulnerable Dependency Range: {dep.name} ({vuln.id})",
            description=(
                f"Dependency '{dep.name}' constraint '{dep.version_constraint}' overlaps with affected range for {vuln.id} ({vuln.summary}). "
                "Exact installed version is unpinned or unknown, so vulnerability status cannot be fully confirmed."
            ),
            file_path=dep.manifest_path,
            location=loc,
            evidence=f"Package: {dep.name}{dep.version_constraint} | Advisory: {vuln.id}",
            remediation="Pin exact dependency version or update constraint to exclude vulnerable version ranges.",
        )
