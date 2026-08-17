"""PYH-DEP-004: Lockfile Inconsistency Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory, ManifestType
from python_hunter.domain.findings.finding import Finding


class PYHDep004LockfileSync:
    """Detector for direct dependencies declared in manifests but missing from lockfiles."""

    id = "PYH-DEP-004"
    name = "Lockfile Inconsistency Detector"
    category = Category.OTHER
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        has_lock = any(
            m.endswith((".lock", "Pipfile.lock"))
            for m in inventory.manifests
        )
        if not has_lock:
            return findings

        locked_norms = {
            d.normalized_name
            for d in inventory.dependencies
            if d.is_transitive or d.manifest_path.endswith((".lock", "Pipfile.lock"))
        }

        for dep in inventory.dependencies:
            if dep.is_direct and not dep.manifest_path.endswith((".lock", "Pipfile.lock")):
                if dep.normalized_name not in locked_norms:
                    loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Lockfile Out of Sync: {dep.name}",
                            description=(
                                f"Declared dependency '{dep.name}' in '{dep.manifest_path}' is missing from project lockfiles. "
                                "This indicates a stale lockfile or un-synchronized environment."
                            ),
                            file_path=dep.manifest_path,
                            location=loc,
                            evidence=f"{dep.name}",
                            remediation="Run package manager sync command (e.g. poetry lock or uv sync) to regenerate lockfile.",
                        )
                    )
        return findings
