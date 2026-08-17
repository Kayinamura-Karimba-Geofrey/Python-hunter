"""PYH-DEP-001: Unpinned Dependency Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.findings.finding import Finding


class PYHDep001Unpinned:
    """Detector for third-party dependencies declared without any version constraints."""

    id = "PYH-DEP-001"
    name = "Unpinned Dependency Detector"
    category = Category.OTHER
    severity = Severity.LOW
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            if dep.is_direct and not dep.version and not dep.version_constraint:
                loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=f"Unpinned Dependency: {dep.name}",
                        description=(
                            f"Dependency '{dep.name}' in '{dep.manifest_path}' is unpinned with no version range. "
                            "Unpinned dependencies risk unexpected breaking changes and supply-chain drift."
                        ),
                        file_path=dep.manifest_path,
                        location=loc,
                        evidence=f"{dep.name}",
                        remediation="Pin the dependency to a specific version or minimum version constraint (e.g. >=2.30.0).",
                    )
                )
        return findings
