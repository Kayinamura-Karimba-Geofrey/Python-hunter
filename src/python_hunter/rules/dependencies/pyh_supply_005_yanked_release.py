"""PYH-SUPPLY-005: Yanked Dependency Release Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.findings.finding import Finding


class PYHSupply005YankedRelease:
    """Detector for dependencies whose locked or target version was yanked from package registry."""

    id = "PYH-SUPPLY-005"
    name = "Yanked Dependency Release Detector"
    category = Category.OTHER
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            if dep.yanked:
                loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                reason_msg = f" (Reason: {dep.yanked_reason})" if dep.yanked_reason else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=f"Yanked Dependency Release: {dep.name}=={dep.version}",
                        description=(
                            f"Specified release '{dep.name}=={dep.version}' was yanked from package index{reason_msg}. "
                            "Yanked releases usually contain critical bugs, severe security flaws, or build regressions."
                        ),
                        file_path=dep.manifest_path,
                        location=loc,
                        evidence=f"{dep.name}=={dep.version}",
                        remediation="Upgrade or downgrade the dependency version to a non-yanked stable release.",
                    )
                )
        return findings
