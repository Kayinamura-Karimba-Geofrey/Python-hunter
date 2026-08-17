"""Security test suite for Project Discovery Engine."""

import os
import unittest
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.infrastructure.discovery.local_filesystem import LocalFileSystem

FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "projects"))


class TestDiscoverySecurity(unittest.TestCase):
    """Security tests verifying path traversal protection, symlink limits, and secret safety."""

    def setUp(self) -> None:
        self.fs = LocalFileSystem()
        self.engine = DiscoverProjectUseCase(fs=self.fs)

    def test_path_traversal_guard(self) -> None:
        """Verify path traversal outside project root is prevented."""
        root = os.path.join(FIXTURES_DIR, "basic_project")
        escaped = os.path.join(root, "..", "..", "..", "etc", "passwd")
        self.assertFalse(self.fs.is_safe_path(root, escaped))

    def test_env_file_secrets_not_exposed(self) -> None:
        """Verify secret values in .secret_env file are not exposed in manifest or metadata."""
        path = os.path.join(FIXTURES_DIR, "malicious_paths")
        manifest = self.engine.discover(path)

        for meta in manifest.files:
            self.assertNotIn("super_secret_12345", meta.relative_path)
            self.assertNotIn("super_secret_12345", str(manifest.metadata_info))


if __name__ == "__main__":
    unittest.main()
