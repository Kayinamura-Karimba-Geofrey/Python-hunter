"""PYH-VULN-003: Unknown Dependency Version Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import VulnerabilityMatch, VulnerabilityStatus


class PYHVuln003Unknown:
    """Detector for dependencies with unresolvable or missing version information."""

    id = "PYH-VULN-003"
    name = "Unknown Dependency Version"
    category = Category.VULNERABLE_DEPENDENCY
    confidence = Confidence.LOW

    def evaluate_match(self, match: VulnerabilityMatch) -> Finding | None:
        if match.status != VulnerabilityStatus.UNKNOWN:
            return None

        dep = match.dependency
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))

        return Finding(
            rule_id=self.id,
            severity=Severity.INFO,
            confidence=self.confidence,
            category=self.category,
            title=f"Unknown Dependency Version: {dep.name}",
            description=(
                f"Dependency '{dep.name}' in '{dep.manifest_path}' has no exact version or version constraint. "
                "Vulnerability status cannot be evaluated."
            ),
            file_path=dep.manifest_path,
            location=loc,
            evidence=f"Package: {dep.name} (Version Unknown)",
            remediation="Specify an exact version or version specifier in manifest or lockfile to enable vulnerability scanning.",
        )
