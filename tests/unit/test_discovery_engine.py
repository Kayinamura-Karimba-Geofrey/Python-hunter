"""Unit tests for Project Discovery Engine."""

import os
import unittest
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.domain.discovery.enums import PackageLayout, ProjectType
from python_hunter.domain.exceptions.base import ProjectError, ValidationError

FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "projects"))


class TestProjectDiscoveryEngine(unittest.TestCase):
    """Unit test suite for Project Discovery Engine capabilities."""

    def setUp(self) -> None:
        self.engine = DiscoverProjectUseCase()

    def test_invalid_and_missing_paths(self) -> None:
        """Verify empty and non-existent paths raise expected domain exceptions."""
        with self.assertRaises(ValidationError):
            self.engine.discover("")

        with self.assertRaises(ProjectError):
            self.engine.discover("/non/existent/path/for/python_hunter")

    def test_basic_project_discovery(self) -> None:
        """Verify discovery on basic_project fixture."""
        path = os.path.join(FIXTURES_DIR, "basic_project")
        manifest = self.engine.discover(path)

        self.assertEqual(manifest.project_name, "basic_project")
        self.assertGreaterEqual(manifest.statistics.python_files, 1)
        self.assertEqual(manifest.package_layout, PackageLayout.FLAT_LAYOUT)

    def test_src_layout_discovery(self) -> None:
        """Verify discovery on src_layout fixture."""
        path = os.path.join(FIXTURES_DIR, "src_layout")
        manifest = self.engine.discover(path)

        self.assertEqual(manifest.project_name, "src-layout-demo")
        self.assertEqual(manifest.package_layout, PackageLayout.SRC_LAYOUT)
        self.assertEqual(manifest.project_type, ProjectType.PACKAGE)

    def test_fastapi_framework_detection(self) -> None:
        """Verify FastAPI framework detection."""
        path = os.path.join(FIXTURES_DIR, "fastapi_project")
        manifest = self.engine.discover(path)

        self.assertIn("FastAPI", manifest.frameworks)
        self.assertEqual(manifest.project_type, ProjectType.WEB_APPLICATION)

    def test_django_framework_detection(self) -> None:
        """Verify Django framework detection."""
        path = os.path.join(FIXTURES_DIR, "django_project")
        manifest = self.engine.discover(path)

        self.assertIn("Django", manifest.frameworks)
        self.assertIn("manage.py", manifest.entry_points)
        self.assertEqual(manifest.project_type, ProjectType.WEB_APPLICATION)

    def test_cli_framework_detection(self) -> None:
        """Verify Click/Typer CLI project detection."""
        path = os.path.join(FIXTURES_DIR, "cli_project")
        manifest = self.engine.discover(path)

        self.assertTrue(any(f in manifest.frameworks for f in ["Click", "Typer"]))
        self.assertEqual(manifest.project_type, ProjectType.CLI_APPLICATION)

    def test_git_docker_ci_detection(self) -> None:
        """Verify Git, Docker, and CI/CD discovery."""
        git_path = os.path.join(FIXTURES_DIR, "git_project")
        self.assertTrue(self.engine.discover(git_path).is_git_repository)

        docker_path = os.path.join(FIXTURES_DIR, "docker_project")
        self.assertTrue(self.engine.discover(docker_path).has_docker)

        ci_path = os.path.join(FIXTURES_DIR, "ci_project")
        self.assertTrue(self.engine.discover(ci_path).has_ci_cd)


if __name__ == "__main__":
    unittest.main()
