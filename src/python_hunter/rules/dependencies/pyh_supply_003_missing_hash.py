"""PYH-SUPPLY-003: Missing Integrity Hash Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory, SourceType
from python_hunter.domain.findings.finding import Finding


class PYHSupply003MissingHash:
    """Detector for lockfile or URL/VCS dependencies lacking cryptographic integrity hashes."""

    id = "PYH-SUPPLY-003"
    name = "Missing Integrity Hash Detector"
    category = Category.OTHER
    severity = Severity.LOW
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            is_locked = dep.manifest_path.endswith((".lock", "Pipfile.lock"))
            is_url_or_vcs = dep.source.source_type in (SourceType.URL, SourceType.VCS)

            if (is_locked or is_url_or_vcs) and not dep.source.hashes:
                loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=f"Missing Integrity Hash: {dep.name}",
                        description=(
                            f"Dependency '{dep.name}' in '{dep.manifest_path}' lacks a cryptographic SHA-256 integrity hash. "
                            "Integrity hashes prevent tampering and man-in-the-middle artifact substitution."
                        ),
                        file_path=dep.manifest_path,
                        location=loc,
                        evidence=f"{dep.name}",
                        remediation="Enable hash pinning in package manager configuration (e.g. pip compile --generate-hashes or poetry lock).",
                    )
                )
        return findings
