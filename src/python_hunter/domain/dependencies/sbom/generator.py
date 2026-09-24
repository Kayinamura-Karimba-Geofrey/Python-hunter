"""Universal SBOM Generator Facade for CycloneDX 1.5 and SPDX 2.3."""

import json
from typing import Any

from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.dependencies.sbom.cyclonedx import CycloneDXGenerator
from python_hunter.domain.dependencies.sbom.spdx import SPDXGenerator
from python_hunter.domain.findings.finding import Finding


class SBOMGenerator:
    """Universal generator interface for producing enterprise software bill-of-materials."""

    def __init__(self, default_format: str = "cyclonedx") -> None:
        self.default_format = default_format.lower()

    def generate(
        self,
        inventory: DependencyInventory,
        format_type: str | None = None,
        spec_version: str | None = None,
        project_name: str = "project",
        project_version: str = "1.0.0",
        vulnerabilities: list[Finding] | None = None,
    ) -> dict[str, Any]:
        """Generate SBOM as a Python dictionary conforming to the specified format."""
        fmt = (format_type or self.default_format).lower()

        if fmt in ("cyclonedx", "cdx"):
            ver = spec_version or "1.5"
            generator = CycloneDXGenerator(spec_version=ver)
            return generator.generate(
                inventory=inventory,
                project_name=project_name,
                project_version=project_version,
                vulnerabilities=vulnerabilities,
            )
        elif fmt in ("spdx", "spdx-json"):
            ver = spec_version or "2.3"
            spdx_gen = SPDXGenerator(spec_version=ver)
            return spdx_gen.generate(
                inventory=inventory,
                project_name=project_name,
                project_version=project_version,
            )
        else:
            raise ValueError(f"Unsupported SBOM format '{fmt}'. Choose 'cyclonedx' or 'spdx'.")

    def generate_json(
        self,
        inventory: DependencyInventory,
        format_type: str | None = None,
        spec_version: str | None = None,
        project_name: str = "project",
        project_version: str = "1.0.0",
        vulnerabilities: list[Finding] | None = None,
        indent: int = 2,
    ) -> str:
        """Generate serialized JSON string of the SBOM."""
        data = self.generate(
            inventory=inventory,
            format_type=format_type,
            spec_version=spec_version,
            project_name=project_name,
            project_version=project_version,
            vulnerabilities=vulnerabilities,
        )
        return json.dumps(data, indent=indent)
