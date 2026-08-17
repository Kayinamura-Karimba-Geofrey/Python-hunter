"""Unit tests for dependency domain models, normalization, and versions."""

import unittest
from python_hunter.domain.dependencies.models import (
    Dependency,
    DependencyGraph,
    DependencyInventory,
    DependencySource,
    SourceType,
)
from python_hunter.domain.dependencies.normalization import normalize_package_name
from python_hunter.domain.dependencies.version import VersionSpec


class TestDependencyDomainModels(unittest.TestCase):
    """Test suite for domain entities, version handling, and normalization."""

    def test_pep503_normalization(self) -> None:
        """Verify PEP 503 package name normalization rules."""
        self.assertEqual(normalize_package_name("Example_Package"), "example-package")
        self.assertEqual(normalize_package_name("example.package"), "example-package")
        self.assertEqual(normalize_package_name("EXAMPLE---PACKAGE"), "example-package")

    def test_version_spec_parsing_and_matching(self) -> None:
        """Verify VersionSpec parsing and constraint matching."""
        self.assertTrue(VersionSpec.matches("2.31.0", ">=2.20.0,<3.0"))
        self.assertFalse(VersionSpec.matches("1.19.0", ">=2.20.0"))

    def test_version_spec_conflict_detection(self) -> None:
        """Verify detection of conflicting version specifiers."""
        self.assertTrue(VersionSpec.are_conflicting(">=2.31.0", "<2.20.0"))
        self.assertFalse(VersionSpec.are_conflicting(">=2.20.0", "<3.0.0"))

    def test_dependency_graph_tree_rendering(self) -> None:
        """Verify ascii tree generation from DependencyGraph."""
        graph = DependencyGraph()
        parent = Dependency(name="fastapi", version="0.110.0", is_direct=True)
        child = Dependency(name="starlette", version="0.36.3", is_direct=False, is_transitive=True)

        graph.add_dependency(parent, child_names=["starlette"])
        graph.add_dependency(child)

        tree = graph.to_tree_str()
        self.assertIn("fastapi==0.110.0", tree)
        self.assertIn("starlette==0.36.3", tree)


if __name__ == "__main__":
    unittest.main()
