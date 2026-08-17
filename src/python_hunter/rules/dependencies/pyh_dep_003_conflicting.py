"""PYH-DEP-003: Conflicting Dependency Constraints Detector."""

from collections import defaultdict
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import Dependency, DependencyInventory
from python_hunter.domain.dependencies.version import VersionSpec
from python_hunter.domain.findings.finding import Finding


class PYHDep003Conflicting:
    """Detector for mutually exclusive or conflicting version requirements across manifests."""

    id = "PYH-DEP-003"
    name = "Conflicting Dependency Constraints Detector"
    category = Category.OTHER
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        by_norm: dict[str, list[Dependency]] = defaultdict(list)
        for dep in inventory.dependencies:
            by_norm[dep.normalized_name].append(dep)

        for norm_name, dep_list in by_norm.items():
            if len(dep_list) < 2:
                continue
            for i in range(len(dep_list)):
                for j in range(i + 1, len(dep_list)):
                    d1, d2 = dep_list[i], dep_list[j]
                    c1, c2 = d1.version_constraint or d1.version, d2.version_constraint or d2.version
                    if c1 and c2 and VersionSpec.are_conflicting(c1, c2):
                        loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(d1.name))
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                confidence=self.confidence,
                                category=self.category,
                                title=f"Conflicting Dependency Constraints: {d1.name}",
                                description=(
                                    f"Incompatible constraints found for package '{d1.name}': "
                                    f"'{c1}' in '{d1.manifest_path}' vs '{c2}' in '{d2.manifest_path}'."
                                ),
                                file_path=d1.manifest_path,
                                location=loc,
                                evidence=f"{d1.name}: {c1} vs {c2}",
                                remediation="Harmonize requirements across project manifests so specified version ranges overlap.",
                            )
                        )
        return findings
