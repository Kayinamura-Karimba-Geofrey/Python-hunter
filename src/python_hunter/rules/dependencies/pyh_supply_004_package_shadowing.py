"""PYH-SUPPLY-004: Package Shadowing Candidate Detector."""

import os
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.dependencies.normalization import normalize_package_name
from python_hunter.domain.findings.finding import Finding


class PYHSupply004PackageShadowing:
    """Detector for local project Python files/modules that shadow installed third-party package names."""

    id = "PYH-SUPPLY-004"
    name = "Package Shadowing Candidate Detector"
    category = Category.OTHER
    severity = Severity.LOW
    confidence = Confidence.HIGH

    def evaluate(self, inventory: DependencyInventory, project_path: str) -> list[Finding]:
        findings: list[Finding] = []
        dep_norms = {d.normalized_name: d for d in inventory.dependencies}

        for root, _, files in os.walk(project_path):
            for file in files:
                if not file.endswith(".py"):
                    continue
                file_stem = file[:-3]
                file_norm = normalize_package_name(file_stem)

                if file_norm in dep_norms:
                    matched_dep = dep_norms[file_norm]
                    rel_path = os.path.relpath(os.path.join(root, file), project_path)
                    loc = Location(line_start=1, line_end=1, column_start=0, column_end=len(file_stem))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=self.severity,
                            confidence=self.confidence,
                            category=self.category,
                            title=f"Local Module Shadowing Dependency: {matched_dep.name}",
                            description=(
                                f"Local Python module '{rel_path}' shares the name of third-party dependency '{matched_dep.name}'. "
                                "This creates import resolution ambiguity and potential namespace shadowing."
                            ),
                            file_path=rel_path,
                            location=loc,
                            evidence=f"Local module: {rel_path} vs Dependency: {matched_dep.name}",
                            remediation="Rename local Python module to avoid collision with installed third-party dependencies.",
                        )
                    )
        return findings
