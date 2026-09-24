"""Generate Software Bill of Materials (SBOM) Application Use Case."""

import os
from typing import Any

from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.application.use_cases.analyze_vulnerabilities import AnalyzeVulnerabilitiesUseCase
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.dependencies.sbom.generator import SBOMGenerator
from python_hunter.domain.findings.finding import Finding


class GenerateSBOMUseCase:
    """Orchestrates project dependency discovery and standardized SBOM generation."""

    def __init__(self) -> None:
        self.dependencies_use_case = AnalyzeDependenciesUseCase()
        self.vulnerabilities_use_case = AnalyzeVulnerabilitiesUseCase(offline=True)
        self.sbom_generator = SBOMGenerator()

    def execute(
        self,
        target_path: str,
        format_type: str = "cyclonedx",
        spec_version: str | None = None,
        include_vulns: bool = False,
    ) -> dict[str, Any]:
        """Generate a complete SBOM for the target repository or manifest."""
        root_path = target_path if os.path.exists(target_path) else "."
        dep_result = self.dependencies_use_case.execute(root_path)

        project_name = str(dep_result.get("project_name", os.path.basename(os.path.abspath(root_path))))
        inventory: DependencyInventory = dep_result["inventory"]  # type: ignore

        vulnerabilities: list[Finding] | None = None
        if include_vulns:
            try:
                vuln_result = self.vulnerabilities_use_case.execute(root_path)
                vulnerabilities = vuln_result.get("findings", [])
            except Exception:
                vulnerabilities = None

        sbom_data = self.sbom_generator.generate(
            inventory=inventory,
            format_type=format_type,
            spec_version=spec_version,
            project_name=project_name,
            vulnerabilities=vulnerabilities,
        )

        sbom_json = self.sbom_generator.generate_json(
            inventory=inventory,
            format_type=format_type,
            spec_version=spec_version,
            project_name=project_name,
            vulnerabilities=vulnerabilities,
        )

        return {
            "project_name": project_name,
            "project_path": root_path,
            "format": format_type.lower(),
            "spec_version": spec_version or ("1.5" if format_type.lower() == "cyclonedx" else "2.3"),
            "components_count": len(inventory.dependencies),
            "manifests": inventory.manifests,
            "sbom": sbom_data,
            "sbom_json": sbom_json,
        }
