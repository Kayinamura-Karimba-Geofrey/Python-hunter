"""Unit tests for Step 35 — Advanced Software Composition Analysis (SCA) & Dependency Intelligence."""

import os
import tempfile
import unittest

from python_hunter.domain.dependencies.advisory_db import AdvisoryDatabase
from python_hunter.domain.dependencies.dependency_graph_engine import DependencyGraphEngine
from python_hunter.domain.dependencies.ecosystem_registry import DependencyEcosystemRegistry
from python_hunter.domain.dependencies.license_policy import LicenseAction, LicensePolicyEngine
from python_hunter.domain.dependencies.lockfile_parsers import UniversalLockfileParser
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyGraph,
    Ecosystem,
    ManifestType,
    PackageManager,
)
from python_hunter.domain.dependencies.pr_dependency_diff import DependencyChangeType, PRDependencyDiffEngine
from python_hunter.domain.dependencies.reachability_engine import ReachabilityConfidence, ReachabilityEngine
from python_hunter.domain.dependencies.remediation_engine import RemediationEngine
from python_hunter.domain.dependencies.semver_engine import SemVerEngine
from python_hunter.domain.dependencies.vulnerability_intel import Advisory, VulnerabilityIntelligence
from python_hunter.domain.semantics.program_model import ProgramCall, ProgramFunction, ProgramModel, ProgramModule


class TestSCAEngineUnit(unittest.TestCase):

    def test_ecosystem_registry(self) -> None:
        registry = DependencyEcosystemRegistry()
        spec = registry.get_spec(Ecosystem.PYTHON)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.name, "PyPI")

        detected = registry.detect_ecosystem_by_filename("package.json")
        self.assertIsNotNone(detected)
        self.assertEqual(detected.ecosystem, Ecosystem.JAVASCRIPT)

    def test_semver_engine_range_matching(self) -> None:
        self.assertTrue(SemVerEngine.is_version_in_range("9.5.0", ">=9.0.0,<10.0.1"))
        self.assertFalse(SemVerEngine.is_version_in_range("10.0.2", ">=9.0.0,<10.0.1"))
        self.assertTrue(SemVerEngine.is_version_in_range("1.2.5", "^1.2.0"))
        self.assertFalse(SemVerEngine.is_version_in_range("2.0.0", "^1.2.0"))
        self.assertTrue(SemVerEngine.is_version_in_range("1.2.5", "~1.2.0"))
        self.assertFalse(SemVerEngine.is_version_in_range("1.3.0", "~1.2.0"))

    def test_version_conflicts(self) -> None:
        deps = [
            Dependency(name="urllib3", version="1.26.5"),
            Dependency(name="urllib3", version="2.0.0"),
        ]
        conflicts = SemVerEngine.find_version_conflicts(deps)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["package_name"], "urllib3")

    def test_lockfile_parser_requirements_txt(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="requirements.txt") as f:
            f.write("pillow==9.5.0\nflask>=2.0.0\n# comment line\n")
            f_path = f.name

        try:
            deps = UniversalLockfileParser.parse_requirements_txt(f_path)
            self.assertEqual(len(deps), 2)
            self.assertEqual(deps[0].name, "pillow")
            self.assertEqual(deps[0].version, "9.5.0")
        finally:
            os.unlink(f_path)

    def test_lockfile_parser_package_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="package.json") as f:
            f.write('{"dependencies": {"axios": "^0.21.1"}, "devDependencies": {"jest": "^29.0.0"}}')
            f_path = f.name

        try:
            deps = UniversalLockfileParser.parse_npm(f_path)
            self.assertEqual(len(deps), 2)
            names = [d.name for d in deps]
            self.assertIn("axios", names)
            self.assertIn("jest", names)
        finally:
            os.unlink(f_path)

    def test_dependency_graph_and_spof_analytics(self) -> None:
        graph = DependencyGraph()
        app_dep = Dependency(name="my_app", is_direct=True)
        pkg_a = Dependency(name="pkg_a", is_direct=True)
        pkg_b = Dependency(name="pkg_b", is_direct=True)
        shared_dep = Dependency(name="shared_core", is_transitive=True)

        graph.add_dependency(app_dep, ["pkg_a", "pkg_b"])
        graph.add_dependency(pkg_a, ["shared_core"])
        graph.add_dependency(pkg_b, ["shared_core"])
        graph.add_dependency(shared_dep, [])

        analytics = DependencyGraphEngine.analyze_graph(graph)
        self.assertEqual(analytics.total_nodes, 4)
        self.assertEqual(len(analytics.single_points_of_failure), 1)
        self.assertEqual(analytics.single_points_of_failure[0]["package"], "shared-core")

    def test_advisory_database_and_atomic_update(self) -> None:
        temp_dir = tempfile.mkdtemp()
        try:
            db = AdvisoryDatabase(db_dir=temp_dir)
            advs = db.get_advisories("pillow", Ecosystem.PYTHON)
            self.assertGreaterEqual(len(advs), 1)

            new_adv = Advisory(
                identifier="GHSA-TEST-001",
                package="custom-pkg",
                ecosystem=Ecosystem.PYTHON,
                affected_versions=">=1.0.0",
                severity="HIGH",
            )
            success = db.update_database_atomic([new_adv], new_version="1.1.0")
            self.assertTrue(success)

            freshness = db.get_freshness_info()
            self.assertEqual(freshness.database_version, "1.1.0")
            self.assertFalse(freshness.is_stale)
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_reachability_engine_evaluation(self) -> None:
        model = ProgramModel()
        mod = ProgramModule(name="app", file_path="app.py", language="python")
        fn = ProgramFunction(name="get_image", qualified_name="app.get_image", module_name="app", is_endpoint_handler=True)
        fn.calls.append(ProgramCall(caller_qualified_name="app.get_image", callee_name="Image.open"))
        mod.functions["app.get_image"] = fn
        model.add_module(mod)

        reach_engine = ReachabilityEngine(model)
        dep = Dependency(name="pillow", version="9.5.0")
        adv = Advisory(identifier="GHSA-vhq6-9248-wjmp", package="pillow", vulnerable_functions=["Image.open"])

        res = reach_engine.evaluate_reachability(dep, adv)
        self.assertTrue(res.is_reachable)
        self.assertEqual(res.confidence, ReachabilityConfidence.CONFIRMED)

    def test_license_policy_engine(self) -> None:
        engine = LicensePolicyEngine()
        dep_mit = Dependency(name="axios", license="MIT")
        res_mit = engine.evaluate_dependency(dep_mit)
        self.assertEqual(res_mit.action, LicenseAction.ALLOW)

        dep_gpl = Dependency(name="bad_copyleft", license="GPL-3.0")
        res_gpl = engine.evaluate_dependency(dep_gpl)
        self.assertEqual(res_gpl.action, LicenseAction.DENY)

    def test_remediation_engine(self) -> None:
        dep = Dependency(name="pillow", version="9.5.0")
        adv = Advisory(identifier="CVE-2023-4863", package="pillow", patched_versions="10.0.1")

        remed = RemediationEngine.generate_recommendation(dep, adv)
        self.assertEqual(remed.action, "UPGRADE")
        self.assertEqual(remed.recommended_version, "10.0.1")
        self.assertEqual(remed.breaking_change_risk, "HIGH")  # 9.x to 10.x major bump

    def test_pr_dependency_diff_engine(self) -> None:
        db = AdvisoryDatabase()
        intel = VulnerabilityIntelligence([db])
        diff_engine = PRDependencyDiffEngine(intel)

        base_deps = [Dependency(name="pillow", version="10.0.1", ecosystem=Ecosystem.PYTHON)]
        head_deps = [Dependency(name="pillow", version="9.5.0", ecosystem=Ecosystem.PYTHON)]  # Downgraded to vulnerable version

        res = diff_engine.compare_dependencies(base_deps, head_deps)
        self.assertTrue(res.has_regressions)
        self.assertEqual(res.introduced_vulnerabilities, 1)


if __name__ == "__main__":
    unittest.main()
