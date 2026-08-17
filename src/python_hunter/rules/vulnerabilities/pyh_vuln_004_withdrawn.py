"""PYH-VULN-004: Withdrawn Vulnerability Advisory Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import VulnerabilityMatch, VulnerabilityStatus


class PYHVuln004Withdrawn:
    """Detector for dependencies associated with withdrawn vulnerability advisories."""

    id = "PYH-VULN-004"
    name = "Withdrawn Vulnerability Advisory"
    category = Category.VULNERABLE_DEPENDENCY
    confidence = Confidence.HIGH

    def evaluate_match(self, match: VulnerabilityMatch) -> Finding | None:
        if match.status != VulnerabilityStatus.WITHDRAWN:
            return None

        vuln = match.vulnerability
        dep = match.dependency
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))

        return Finding(
            rule_id=self.id,
            severity=Severity.INFO,
            confidence=self.confidence,
            category=self.category,
            title=f"Withdrawn Advisory Info: {dep.name} ({vuln.id})",
            description=(
                f"Vulnerability advisory {vuln.id} for package '{dep.name}' was withdrawn by the issuing authority. "
                "No action is required."
            ),
            file_path=dep.manifest_path,
            location=loc,
            evidence=f"Package: {dep.name} | Withdrawn Advisory: {vuln.id}",
            remediation="No remediation required as advisory was withdrawn.",
        )
