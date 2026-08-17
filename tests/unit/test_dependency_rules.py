"""Unit tests for dependency and supply-chain analysis rules."""

import unittest
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyInventory,
    DependencySource,
    SourceType,
)
from python_hunter.rules.dependencies import (
    PYHDep001Unpinned,
    PYHDep002BroadRange,
    PYHDep003Conflicting,
    PYHSupply001MutableVCS,
    PYHSupply002DirectURL,
    PYHSupply004PackageShadowing,
    PYHSupply005YankedRelease,
)


class TestDependencyRules(unittest.TestCase):
    """Test suite for dependency and supply-chain security rules."""

    def test_pyh_dep_001_unpinned(self) -> None:
        """Verify PYH-DEP-001 detects unpinned dependencies."""
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="requests", version="", version_constraint="", manifest_path="requirements.txt")
            ]
        )
        rule = PYHDep001Unpinned()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-DEP-001")

    def test_pyh_dep_002_broad_range(self) -> None:
        """Verify PYH-DEP-002 detects overly broad version ranges."""
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="django", version_constraint=">=1", manifest_path="requirements.txt")
            ]
        )
        rule = PYHDep002BroadRange()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-DEP-002")

    def test_pyh_dep_003_conflicting(self) -> None:
        """Verify PYH-DEP-003 detects conflicting version constraints."""
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="requests", version_constraint=">=2.31.0", manifest_path="req1.txt"),
                Dependency(name="requests", version_constraint="<2.20.0", manifest_path="req2.txt"),
            ]
        )
        rule = PYHDep003Conflicting()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-DEP-003")

    def test_pyh_supply_001_mutable_vcs(self) -> None:
        """Verify PYH-SUPPLY-001 detects mutable VCS references."""
        source = DependencySource(source_type=SourceType.VCS, vcs_repo="git+https://example.com/repo", vcs_ref="main")
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="my-lib", source=source, manifest_path="requirements.txt")
            ]
        )
        rule = PYHSupply001MutableVCS()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SUPPLY-001")

    def test_pyh_supply_002_direct_url(self) -> None:
        """Verify PYH-SUPPLY-002 detects direct HTTP/HTTPS URL dependencies."""
        source = DependencySource(source_type=SourceType.URL, url="https://example.com/pkg.tar.gz")
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="my-pkg", source=source, manifest_path="requirements.txt")
            ]
        )
        rule = PYHSupply002DirectURL()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SUPPLY-002")

    def test_pyh_supply_004_package_shadowing(self) -> None:
        """Verify PYH-SUPPLY-004 detects local module shadowing third-party dependencies."""
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="requests", version="2.31.0", manifest_path="requirements.txt")
            ]
        )
        rule = PYHSupply004PackageShadowing()
        findings = rule.evaluate(inventory, "tests/fixtures/dependencies/shadowing")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SUPPLY-004")

    def test_pyh_supply_005_yanked_release(self) -> None:
        """Verify PYH-SUPPLY-005 detects yanked package versions."""
        inventory = DependencyInventory(
            dependencies=[
                Dependency(name="vulnerable-pkg", version="1.0.0", yanked=True, yanked_reason="Critical bug", manifest_path="requirements.txt")
            ]
        )
        rule = PYHSupply005YankedRelease()
        findings = rule.evaluate(inventory, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SUPPLY-005")


if __name__ == "__main__":
    unittest.main()
