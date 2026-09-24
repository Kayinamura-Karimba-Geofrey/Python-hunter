"""Unit tests for Software Bill of Materials (SBOM) Generation (CycloneDX 1.5 & SPDX 2.3)."""

import json
import os
import tempfile
import unittest

from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.application.use_cases.generate_sbom import GenerateSBOMUseCase
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyGraph,
    DependencyInventory,
    DependencySource,
    DependencyType,
    Ecosystem,
    PackageManager,
)
from python_hunter.domain.dependencies.sbom.cyclonedx import CycloneDXGenerator
from python_hunter.domain.dependencies.sbom.generator import SBOMGenerator
from python_hunter.domain.dependencies.sbom.purl import PURLHelper
from python_hunter.domain.dependencies.sbom.spdx import SPDXGenerator
from python_hunter.domain.findings.finding import Finding
from python_hunter.interfaces.cli.commands.sbom import run_sbom_command
from python_hunter.interfaces.cli.main import run_cli
from python_hunter.presentation.renderer import CycloneDXRenderer, SPDXRenderer


class TestPURLHelper(unittest.TestCase):
    """Test canonical Package URL (purl) generation."""

    def test_pypi_purl(self) -> None:
        purl = PURLHelper.generate_purl(Ecosystem.PYTHON, "Requests", "2.31.0")
        self.assertEqual(purl, "pkg:pypi/requests@2.31.0")

        purl_underscore = PURLHelper.generate_purl(Ecosystem.PYTHON, "my_cool_pkg", "1.0.0")
        self.assertEqual(purl_underscore, "pkg:pypi/my-cool-pkg@1.0.0")

        purl_unpinned = PURLHelper.generate_purl(Ecosystem.PYTHON, "flask", "")
        self.assertEqual(purl_unpinned, "pkg:pypi/flask")

    def test_npm_purl(self) -> None:
        purl = PURLHelper.generate_purl(Ecosystem.JAVASCRIPT, "lodash", "4.17.21")
        self.assertEqual(purl, "pkg:npm/lodash@4.17.21")

        purl_scoped = PURLHelper.generate_purl(Ecosystem.JAVASCRIPT, "@angular/core", "16.0.0")
        self.assertEqual(purl_scoped, "pkg:npm/angular/core@16.0.0")

    def test_cargo_and_golang_purls(self) -> None:
        cargo_purl = PURLHelper.generate_purl(Ecosystem.CRATES_IO, "tokio", "1.28.0")
        self.assertEqual(cargo_purl, "pkg:cargo/tokio@1.28.0")

        go_purl = PURLHelper.generate_purl(Ecosystem.GO_MODULES, "gin", "1.9.0", namespace="github.com/gin-gonic")
        self.assertEqual(go_purl, "pkg:golang/github.com%2Fgin-gonic/gin@1.9.0")


class TestSBOMGenerators(unittest.TestCase):
    """Test CycloneDX 1.5 and SPDX 2.3 document generation."""

    def setUp(self) -> None:
        self.dep1 = Dependency(
            name="requests",
            ecosystem=Ecosystem.PYTHON,
            version="2.31.0",
            license="Apache-2.0",
            is_direct=True,
            is_development=False,
            manifest_path="requirements.txt",
            source=DependencySource(hashes=["sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]),
            metadata={"child_dependencies": ["urllib3"]},
        )
        self.dep2 = Dependency(
            name="urllib3",
            ecosystem=Ecosystem.PYTHON,
            version="2.0.7",
            license="MIT",
            is_direct=False,
            is_transitive=True,
            is_development=False,
            manifest_path="requirements.txt",
        )
        self.dep3 = Dependency(
            name="pytest",
            ecosystem=Ecosystem.PYTHON,
            version="7.4.0",
            license="MIT",
            is_direct=True,
            is_development=True,
            manifest_path="pyproject.toml",
        )

        graph = DependencyGraph()
        graph.add_dependency(self.dep1, child_names=["urllib3"])
        graph.add_dependency(self.dep2)
        graph.add_dependency(self.dep3)

        self.inventory = DependencyInventory(
            package_manager=PackageManager.PIP,
            manifests=["requirements.txt", "pyproject.toml"],
            total_count=3,
            direct_count=2,
            transitive_count=1,
            development_count=1,
            dependencies=[self.dep1, self.dep2, self.dep3],
            graph=graph,
        )

    def test_cyclonedx_1_5_schema(self) -> None:
        generator = CycloneDXGenerator(spec_version="1.5")
        doc = generator.generate(
            inventory=self.inventory,
            project_name="my-service",
            project_version="2.0.0",
        )

        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["specVersion"], "1.5")
        self.assertTrue(doc["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(doc["version"], 1)

        # Metadata
        self.assertEqual(doc["metadata"]["component"]["name"], "my-service")
        self.assertEqual(doc["metadata"]["component"]["version"], "2.0.0")

        # Components
        comps = doc["components"]
        self.assertEqual(len(comps), 3)

        req_comp = next(c for c in comps if c["name"] == "requests")
        self.assertEqual(req_comp["version"], "2.31.0")
        self.assertEqual(req_comp["purl"], "pkg:pypi/requests@2.31.0")
        self.assertEqual(req_comp["scope"], "required")
        self.assertEqual(req_comp["licenses"][0]["license"]["id"], "Apache-2.0")
        self.assertEqual(req_comp["hashes"][0]["alg"], "SHA-256")

        dev_comp = next(c for c in comps if c["name"] == "pytest")
        self.assertEqual(dev_comp["scope"], "excluded")

        # Dependencies graph
        deps = doc["dependencies"]
        self.assertGreaterEqual(len(deps), 2)
        root_dep = next(d for d in deps if d["ref"] == doc["metadata"]["component"]["bom-ref"])
        self.assertIn("pkg:pypi/requests@2.31.0", root_dep["dependsOn"])

        req_dep = next(d for d in deps if d["ref"] == "pkg:pypi/requests@2.31.0")
        self.assertIn("pkg:pypi/urllib3@2.0.7", req_dep["dependsOn"])

    def test_cyclonedx_with_vulnerabilities(self) -> None:
        vuln = Finding(
            rule_id="CVE-2023-9999",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.VULNERABLE_DEPENDENCY,
            title="Vulnerability in requests",
            description="Buffer overflow vulnerability in requests package",
            file_path="requirements.txt",
            location=Location(1, 1, 0, 15),
            evidence="requests==2.31.0",
        )
        generator = CycloneDXGenerator()
        doc = generator.generate(
            inventory=self.inventory,
            project_name="my-service",
            vulnerabilities=[vuln],
        )

        self.assertIn("vulnerabilities", doc)
        self.assertEqual(len(doc["vulnerabilities"]), 1)
        v = doc["vulnerabilities"][0]
        self.assertEqual(v["id"], "CVE-2023-9999")
        self.assertEqual(v["ratings"][0]["severity"], "high")
        self.assertEqual(v["affects"][0]["ref"], "pkg:pypi/requests@2.31.0")

    def test_spdx_2_3_schema(self) -> None:
        generator = SPDXGenerator(spec_version="2.3")
        doc = generator.generate(
            inventory=self.inventory,
            project_name="my-service",
            project_version="1.0.0",
        )

        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc["dataLicense"], "CC0-1.0")
        self.assertEqual(doc["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertEqual(doc["name"], "my-service")
        self.assertTrue(doc["documentNamespace"].startswith("https://spdx.org/spdxdocs/my-service-"))

        # Packages: 1 root + 3 dependencies = 4 packages
        self.assertEqual(len(doc["packages"]), 4)
        pkg_names = [p["name"] for p in doc["packages"]]
        self.assertIn("my-service", pkg_names)
        self.assertIn("requests", pkg_names)
        self.assertIn("urllib3", pkg_names)
        self.assertIn("pytest", pkg_names)

        req_pkg = next(p for p in doc["packages"] if p["name"] == "requests")
        self.assertEqual(req_pkg["versionInfo"], "2.31.0")
        self.assertEqual(req_pkg["licenseConcluded"], "Apache-2.0")
        self.assertEqual(req_pkg["externalRefs"][0]["referenceLocator"], "pkg:pypi/requests@2.31.0")

        # Relationships
        rels = doc["relationships"]
        describes_rel = [r for r in rels if r["relationshipType"] == "DESCRIBES"]
        self.assertEqual(len(describes_rel), 1)
        self.assertEqual(describes_rel[0]["spdxElementId"], "SPDXRef-DOCUMENT")
        self.assertEqual(describes_rel[0]["relatedSpdxElement"], "SPDXRef-Package-Root")

        depends_rels = [r for r in rels if r["relationshipType"] == "DEPENDS_ON"]
        self.assertGreaterEqual(len(depends_rels), 2)

    def test_universal_sbom_generator_facade(self) -> None:
        facade = SBOMGenerator()
        cdx = facade.generate(self.inventory, format_type="cyclonedx")
        self.assertEqual(cdx["bomFormat"], "CycloneDX")

        spdx = facade.generate(self.inventory, format_type="spdx")
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")

        cdx_json = facade.generate_json(self.inventory, format_type="cyclonedx")
        parsed = json.loads(cdx_json)
        self.assertEqual(parsed["bomFormat"], "CycloneDX")

        with self.assertRaises(ValueError):
            facade.generate(self.inventory, format_type="invalid-format")


class TestSBOMUseCaseAndCLI(unittest.TestCase):
    """Test Application use case and CLI integration."""

    def test_generate_sbom_use_case_with_temp_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = os.path.join(temp_dir, "requirements.txt")
            with open(req_file, "w", encoding="utf-8") as f:
                f.write("requests==2.31.0\nurllib3==2.0.7\n")

            use_case = GenerateSBOMUseCase()
            result = use_case.execute(temp_dir, format_type="cyclonedx")

            self.assertEqual(result["format"], "cyclonedx")
            self.assertEqual(result["spec_version"], "1.5")
            self.assertGreaterEqual(result["components_count"], 2)
            self.assertIn("sbom", result)
            self.assertIn("sbom_json", result)

            sbom_dict = result["sbom"]
            comp_names = [c["name"] for c in sbom_dict["components"]]
            self.assertIn("requests", comp_names)
            self.assertIn("urllib3", comp_names)

    def test_cli_sbom_command_stdout_and_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = os.path.join(temp_dir, "requirements.txt")
            with open(req_file, "w", encoding="utf-8") as f:
                f.write("flask==2.3.3\nwerkzeug==2.3.7\n")

            out_file = os.path.join(temp_dir, "bom.json")
            exit_code = run_sbom_command([temp_dir, "--format", "cyclonedx", "-o", out_file])
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                saved_bom = json.load(f)
            self.assertEqual(saved_bom["bomFormat"], "CycloneDX")
            names = [c["name"] for c in saved_bom["components"]]
            self.assertIn("flask", names)

            # Test SPDX file generation
            spdx_out = os.path.join(temp_dir, "spdx.json")
            exit_code = run_sbom_command([temp_dir, "--format", "spdx", "-o", spdx_out])
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(spdx_out))
            with open(spdx_out, "r", encoding="utf-8") as f:
                saved_spdx = json.load(f)
            self.assertEqual(saved_spdx["spdxVersion"], "SPDX-2.3")

    def test_scan_format_cyclonedx_and_spdx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = os.path.join(temp_dir, "requirements.txt")
            with open(req_file, "w", encoding="utf-8") as f:
                f.write("colorama==0.4.6\n")

            out_cdx = os.path.join(temp_dir, "scan_bom.json")
            code = run_cli(["scan", temp_dir, "--format", "cyclonedx", "-o", out_cdx])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_cdx))
            with open(out_cdx, "r", encoding="utf-8") as f:
                cdx = json.load(f)
            self.assertEqual(cdx["bomFormat"], "CycloneDX")

            out_spdx = os.path.join(temp_dir, "scan_spdx.json")
            code = run_cli(["scan", temp_dir, "--format", "spdx", "-o", out_spdx])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_spdx))
            with open(out_spdx, "r", encoding="utf-8") as f:
                spdx = json.load(f)
            self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")


if __name__ == "__main__":
    unittest.main()
