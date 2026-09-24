"""CycloneDX 1.5 JSON Software Bill of Materials (SBOM) Generator.

Complies with the OWASP CycloneDX 1.5 JSON specification:
https://cyclonedx.org/docs/1.5/json/
"""

from datetime import datetime, timezone
import uuid
from typing import Any

from python_hunter import __version__
from python_hunter.domain.dependencies.models import Dependency, DependencyInventory
from python_hunter.domain.dependencies.sbom.purl import PURLHelper
from python_hunter.domain.findings.finding import Finding


# Curated standard SPDX license IDs for exact matching
SPDX_LICENSE_IDS = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-2.0",
}


class CycloneDXGenerator:
    """Generates CycloneDX 1.5 compliant JSON SBOM documents."""

    def __init__(self, spec_version: str = "1.5") -> None:
        self.spec_version = spec_version

    def generate(
        self,
        inventory: DependencyInventory,
        project_name: str = "project",
        project_version: str = "1.0.0",
        vulnerabilities: list[Finding] | None = None,
    ) -> dict[str, Any]:
        """Generate CycloneDX 1.5 JSON dictionary."""
        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        root_purl = f"pkg:generic/{project_name}@{project_version}"
        root_bom_ref = root_purl

        metadata: dict[str, Any] = {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Python Hunter",
                    "name": "python-hunter",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
                "bom-ref": root_bom_ref,
                "purl": root_purl,
            },
        }

        components: list[dict[str, Any]] = []
        dependencies_graph: list[dict[str, Any]] = []
        root_depends_on: list[str] = []

        # Map dependency normalized name to bom-ref for DAG linking
        norm_to_ref: dict[str, str] = {}

        for dep in inventory.dependencies:
            purl = PURLHelper.generate_purl(
                ecosystem=dep.ecosystem,
                name=dep.name,
                version=dep.version or dep.version_constraint,
            )
            bom_ref = purl
            norm_to_ref[dep.normalized_name] = bom_ref

            comp: dict[str, Any] = {
                "type": "library",
                "name": dep.name,
                "version": dep.version or dep.version_constraint or "UNKNOWN",
                "purl": purl,
                "bom-ref": bom_ref,
                "scope": self._determine_scope(dep),
            }

            # Licenses
            if dep.license and dep.license.upper() != "UNKNOWN":
                lic_id = self._match_spdx_id(dep.license)
                if lic_id:
                    comp["licenses"] = [{"license": {"id": lic_id}}]
                else:
                    comp["licenses"] = [{"license": {"name": dep.license}}]

            # Hashes
            hashes = self._extract_hashes(dep)
            if hashes:
                comp["hashes"] = hashes

            # Properties
            props: list[dict[str, str]] = [
                {"name": "python_hunter:direct", "value": str(dep.is_direct).lower()},
                {"name": "python_hunter:ecosystem", "value": dep.ecosystem.value},
            ]
            if dep.manifest_path:
                props.append({"name": "python_hunter:manifest_path", "value": dep.manifest_path})
            if dep.is_development:
                props.append({"name": "python_hunter:development", "value": "true"})
            comp["properties"] = props

            components.append(comp)

            if dep.is_direct:
                root_depends_on.append(bom_ref)

        # Build CycloneDX dependencies relationship array
        dependencies_graph.append({
            "ref": root_bom_ref,
            "dependsOn": sorted(list(set(root_depends_on))),
        })

        for dep in inventory.dependencies:
            bom_ref = norm_to_ref.get(dep.normalized_name)
            if not bom_ref:
                continue

            child_names = dep.metadata.get("child_dependencies", [])
            if not child_names and inventory.graph:
                node = inventory.graph.get_node(dep.normalized_name)
                if node:
                    child_names = node.dependencies

            child_refs: list[str] = []
            for c_name in child_names:
                c_ref = norm_to_ref.get(c_name)
                if c_ref:
                    child_refs.append(c_ref)

            if child_refs:
                dependencies_graph.append({
                    "ref": bom_ref,
                    "dependsOn": sorted(list(set(child_refs))),
                })

        bom_doc: dict[str, Any] = {
            "$schema": f"http://cyclonedx.org/schema/bom-{self.spec_version}.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "serialNumber": serial_number,
            "version": 1,
            "metadata": metadata,
            "components": components,
            "dependencies": dependencies_graph,
        }

        # Optional vulnerabilities inclusion
        if vulnerabilities:
            bom_doc["vulnerabilities"] = self._build_vulnerabilities(vulnerabilities, norm_to_ref)

        return bom_doc

    @staticmethod
    def _determine_scope(dep: Dependency) -> str:
        """Determines CycloneDX component scope ('required', 'optional', 'excluded')."""
        if dep.is_development:
            return "excluded"
        if dep.is_optional:
            return "optional"
        return "required"

    @staticmethod
    def _match_spdx_id(lic_str: str) -> str | None:
        """Matches a license string against standard SPDX identifiers."""
        clean = lic_str.strip()
        if clean in SPDX_LICENSE_IDS:
            return clean
        for sid in SPDX_LICENSE_IDS:
            if sid.lower() == clean.lower():
                return sid
        return None

    @staticmethod
    def _extract_hashes(dep: Dependency) -> list[dict[str, str]]:
        """Extracts cryptographic hashes in CycloneDX format."""
        hashes: list[dict[str, str]] = []
        raw_hashes = list(dep.source.hashes)
        if dep.integrity_hash and dep.integrity_hash not in raw_hashes:
            raw_hashes.append(dep.integrity_hash)

        for h in raw_hashes:
            if ":" in h:
                alg, content = h.split(":", 1)
                alg_map = {
                    "sha256": "SHA-256",
                    "sha512": "SHA-512",
                    "sha1": "SHA-1",
                    "md5": "MD5",
                }
                alg_name = alg_map.get(alg.lower(), alg.upper())
                hashes.append({"alg": alg_name, "content": content})
            elif len(h) == 64:
                hashes.append({"alg": "SHA-256", "content": h})
            elif len(h) == 128:
                hashes.append({"alg": "SHA-512", "content": h})
        return hashes

    @staticmethod
    def _build_vulnerabilities(
        findings: list[Finding],
        norm_to_ref: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Converts security findings to CycloneDX vulnerabilities array."""
        vulns: list[dict[str, Any]] = []
        for f in findings:
            target_ref = None
            for norm_name, ref in norm_to_ref.items():
                if norm_name.lower() in f.evidence.lower() or norm_name.lower() in f.title.lower():
                    target_ref = ref
                    break

            vuln_entry: dict[str, Any] = {
                "bom-ref": f"vuln-{f.rule_id}-{uuid.uuid4().hex[:8]}",
                "id": f.rule_id,
                "source": {"name": "Python Hunter Security Analysis"},
                "ratings": [
                    {
                        "severity": f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower(),
                        "score": 9.0 if f.severity.value == "CRITICAL" else (7.0 if f.severity.value == "HIGH" else 4.0),
                    }
                ],
                "description": f.description,
            }
            if target_ref:
                vuln_entry["affects"] = [{"ref": target_ref}]
            vulns.append(vuln_entry)
        return vulns
