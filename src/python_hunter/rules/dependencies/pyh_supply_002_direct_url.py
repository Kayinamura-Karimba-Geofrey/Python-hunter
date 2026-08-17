"""PYH-SUPPLY-002: Direct URL Dependency Detector."""

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory, SourceType
from python_hunter.domain.findings.finding import Finding


class PYHSupply002DirectURL:
    """Detector for dependencies installed directly from arbitrary HTTP/HTTPS artifact URLs."""

    id = "PYH-SUPPLY-002"
    name = "Direct URL Dependency Detector"
    category = Category.OTHER
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for dep in inventory.dependencies:
            if dep.source.source_type == SourceType.URL:
                loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(dep.name))
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        confidence=self.confidence,
                        category=self.category,
                        title=f"Direct URL Dependency: {dep.name}",
                        description=(
                            f"Dependency '{dep.name}' is retrieved directly from URL '{dep.source.url}'. "
                            "Direct URL dependencies bypass standard index security verification and release provenance."
                        ),
                        file_path=dep.manifest_path,
                        location=loc,
                        evidence=f"{dep.source.url}",
                        remediation="Use official PyPI/private registry packages or pin URL dependencies with cryptographic integrity hashes.",
                    )
                )
        return findings
