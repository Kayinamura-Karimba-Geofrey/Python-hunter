"""SPDX 2.3 JSON Software Bill of Materials (SBOM) Generator.

Complies with the SPDX 2.3 Specification:
https://spdx.github.io/spdx-spec/v2.3/
"""

from datetime import datetime, timezone
import re
import uuid
from typing import Any

from python_hunter import __version__
from python_hunter.domain.dependencies.models import Dependency, DependencyInventory
from python_hunter.domain.dependencies.sbom.cyclonedx import SPDX_LICENSE_IDS
from python_hunter.domain.dependencies.sbom.purl import PURLHelper


class SPDXGenerator:
    """Generates SPDX 2.3 compliant JSON SBOM documents."""

    def __init__(self, spec_version: str = "2.3") -> None:
        self.spec_version = spec_version

    def generate(
        self,
        inventory: DependencyInventory,
        project_name: str = "project",
        project_version: str = "1.0.0",
    ) -> dict[str, Any]:
        """Generate SPDX 2.3 JSON dictionary."""
        doc_uuid = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        document_namespace = f"https://spdx.org/spdxdocs/{project_name}-{doc_uuid}"

        packages: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        root_id = "SPDXRef-Package-Root"
        packages.append({
            "SPDXID": root_id,
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
        })

        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": root_id,
            "relationshipType": "DESCRIBES",
        })

        norm_to_spdxid: dict[str, str] = {}

        for idx, dep in enumerate(inventory.dependencies, start=1):
            clean_name = re.sub(r"[^a-zA-Z0-9.-]", "-", dep.name)
            pkg_id = f"SPDXRef-Package-{clean_name}-{idx}"
            norm_to_spdxid[dep.normalized_name] = pkg_id

            purl = PURLHelper.generate_purl(
                ecosystem=dep.ecosystem,
                name=dep.name,
                version=dep.version or dep.version_constraint,
            )

            lic = dep.license if dep.license and dep.license.upper() != "UNKNOWN" else "NOASSERTION"
            lic_concluded = lic if lic in SPDX_LICENSE_IDS else ("NOASSERTION" if lic == "NOASSERTION" else lic)

            pkg: dict[str, Any] = {
                "SPDXID": pkg_id,
                "name": dep.name,
                "versionInfo": dep.version or dep.version_constraint or "UNKNOWN",
                "downloadLocation": dep.source.url or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": lic_concluded,
                "licenseDeclared": lic,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }

            # Checksums
            checksums = self._extract_checksums(dep)
            if checksums:
                pkg["checksums"] = checksums

            packages.append(pkg)

            if dep.is_direct:
                relationships.append({
                    "spdxElementId": root_id,
                    "relatedSpdxElement": pkg_id,
                    "relationshipType": "DEPENDS_ON",
                })

        # Add graph relationships
        for dep in inventory.dependencies:
            parent_id = norm_to_spdxid.get(dep.normalized_name)
            if not parent_id:
                continue

            child_names = dep.metadata.get("child_dependencies", [])
            if not child_names and inventory.graph:
                node = inventory.graph.get_node(dep.normalized_name)
                if node:
                    child_names = node.dependencies

            for c_name in child_names:
                child_id = norm_to_spdxid.get(c_name)
                if child_id and child_id != parent_id:
                    relationships.append({
                        "spdxElementId": parent_id,
                        "relatedSpdxElement": child_id,
                        "relationshipType": "DEPENDS_ON",
                    })

        return {
            "spdxVersion": f"SPDX-{self.spec_version}",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "documentNamespace": document_namespace,
            "creationInfo": {
                "created": timestamp,
                "creators": [
                    f"Tool: Python Hunter {__version__}",
                ],
                "licenseListVersion": "3.21",
            },
            "packages": packages,
            "relationships": relationships,
        }

    @staticmethod
    def _extract_checksums(dep: Dependency) -> list[dict[str, str]]:
        """Extracts cryptographic checksums conforming to SPDX algorithms."""
        checksums: list[dict[str, str]] = []
        raw_hashes = list(dep.source.hashes)
        if dep.integrity_hash and dep.integrity_hash not in raw_hashes:
            raw_hashes.append(dep.integrity_hash)

        for h in raw_hashes:
            if ":" in h:
                alg, content = h.split(":", 1)
                alg_map = {
                    "sha256": "SHA256",
                    "sha512": "SHA512",
                    "sha1": "SHA1",
                    "md5": "MD5",
                }
                alg_name = alg_map.get(alg.lower(), alg.upper())
                checksums.append({"algorithm": alg_name, "checksumValue": content})
            elif len(h) == 64:
                checksums.append({"algorithm": "SHA256", "checksumValue": h})
            elif len(h) == 128:
                checksums.append({"algorithm": "SHA512", "checksumValue": h})
        return checksums
