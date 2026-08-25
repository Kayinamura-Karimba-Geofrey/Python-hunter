"""Unit tests for CI Application Use Case and Artifact Export."""

import os
import tempfile
import unittest

from python_hunter.application.use_cases.run_ci import RunCIUseCase


class TestCIUseCase(unittest.TestCase):
    """Test suite verifying python-hunter ci execution flow and artifact generation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_ci_execution_and_artifacts(self) -> None:
        # Create dummy Python file for scan
        py_file = os.path.join(self.temp_dir.name, "app.py")
        with open(py_file, "w") as f:
            f.write("import os\nos.system('echo hello')\n")

        output_dir = os.path.join(self.temp_dir.name, "artifacts")
        ci_use_case = RunCIUseCase()
        exit_code = ci_use_case.execute(
            target_path=self.temp_dir.name,
            export_artifacts=True,
            output_dir=output_dir,
        )

        self.assertIn(exit_code, (0, 1, 2))

        self.assertTrue(os.path.exists(os.path.join(output_dir, "report.json")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "report.sarif")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "report.md")))


if __name__ == "__main__":
    unittest.main()
