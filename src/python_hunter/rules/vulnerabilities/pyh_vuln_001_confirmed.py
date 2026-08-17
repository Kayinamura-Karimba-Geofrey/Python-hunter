"""PYH-VULN-001: Confirmed Vulnerable Dependency Detector."""

from python_hunter.domain.common.enums import Category, Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.vulnerabilities.models import VulnerabilityMatch, VulnerabilityStatus


class PYHVuln001Confirmed:
    """Detector for dependencies with confirmed version matches to known vulnerability advisories."""

    id = "PYH-VULN-001"
    name = "Confirmed Vulnerable Dependency"
    category = Category.VULNERABLE_DEPENDENCY
    confidence = Confidence.HIGH

    def evaluate_match(self, match: VulnerabilityMatch) -> Finding | None:
        if match.status != VulnerabilityStatus.AFFECTED:
            return None

        vuln = match.vulnerability
        dep = match.dependency
        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))

        path_str = " -> ".join(match.dependency_paths[0]) if match.dependency_paths else dep.name
        fix_str = match.recommended_fix or "None"

        remediation = f"Upgrade {dep.name} to version {fix_str} or later."
        if not match.constraint_compatible and match.recommended_fix:
            remediation += f" Warning: Required fix ({fix_str}) conflicts with declared constraint ({dep.version_constraint}). Update constraint first."

        return Finding(
            rule_id=self.id,
            severity=vuln.severity,
            confidence=self.confidence,
            category=self.category,
            title=f"Vulnerable Dependency: {dep.name} ({vuln.id})",
            description=(
                f"Dependency '{dep.name}' version '{dep.version}' is vulnerable to {vuln.id} ({vuln.summary}). "
                f"Dependency Path: {path_str}"
            ),
            file_path=dep.manifest_path,
            location=loc,
            evidence=f"Package: {dep.name}=={dep.version} | Advisory: {vuln.id} | Path: {path_str}",
            remediation=remediation,
        )
