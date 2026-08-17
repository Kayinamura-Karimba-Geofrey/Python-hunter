"""PYH-DEP-002: Overly Broad Version Range Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.dependencies.version import VersionSpec
from python_hunter.domain.findings.finding import Finding


class PYHDep002BroadRange:
    """Detector for dependencies allowing excessively broad version ranges (e.g. >=1)."""

    id = "PYH-DEP-002"
    name = "Overly Broad Version Range Detector"
    category = Category.OTHER
    severity = Severity.LOW
    confidence = Confidence.MEDIUM

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            if dep.is_direct and dep.version_constraint:
                if VersionSpec.is_broad_range(dep.version_constraint):
                    loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Broad Version Range: {dep.name}{dep.version_constraint}",
                            description=(
                                f"Dependency '{dep.name}' specifies an overly broad version constraint '{dep.version_constraint}'. "
                                "This reduces build reproducibility and increases risk of introducing breaking major version updates."
                            ),
                            file_path=dep.manifest_path,
                            location=loc,
                            evidence=f"{dep.name}{dep.version_constraint}",
                            remediation="Restrict version constraint range using compatible release specifiers (e.g. ~=2.31 or >=2.30,<3.0).",
                        )
                    )
        return findings
