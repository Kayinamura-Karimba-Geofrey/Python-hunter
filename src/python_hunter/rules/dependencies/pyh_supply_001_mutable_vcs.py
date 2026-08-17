"""PYH-SUPPLY-001: Mutable VCS Dependency Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory, SourceType
from python_hunter.domain.findings.finding import Finding


class PYHSupply001MutableVCS:
    """Detector for VCS dependencies pointing to mutable references (e.g. branch main or master)."""

    id = "PYH-SUPPLY-001"
    name = "Mutable VCS Dependency Detector"
    category = Category.OTHER
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            if dep.source.source_type == SourceType.VCS:
                ref = dep.source.vcs_ref.lower()
                # If ref is empty or points to a branch name instead of a commit hash
                is_mutable = not ref or any(b in ref for b in ("main", "master", "dev", "head", "latest")) or len(ref) < 40
                if is_mutable:
                    loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Mutable VCS Dependency: {dep.name}",
                            description=(
                                f"VCS dependency '{dep.name}' points to a mutable Git reference '{dep.source.vcs_ref or 'HEAD'}'. "
                                "Mutable VCS references introduce supply-chain vulnerability to upstream commit tampering."
                            ),
                            file_path=dep.manifest_path,
                            location=loc,
                            evidence=f"{dep.source.vcs_repo}",
                            remediation="Pin VCS dependencies to an immutable full 40-character git commit SHA.",
                        )
                    )
        return findings
