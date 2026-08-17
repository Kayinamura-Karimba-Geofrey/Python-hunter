"""Integration tests for 'taint' CLI subcommand."""

import json
import os
import unittest
from io import StringIO
from unittest.mock import patch

from python_hunter.interfaces.cli.main import run_cli


class TestCLITaint(unittest.TestCase):
    """Integration test suite for python-hunter taint subcommand."""

    def setUp(self) -> None:
        self.fixture_path = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "taint", "vulnerable_app.py"
        )

    def test_cli_taint_text_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            exit_code = run_cli(["taint", self.fixture_path])
            output = fake_out.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Python Hunter Static Dataflow & Taint Analysis", output)
            self.assertIn("PYH-TAINT-SQL-001", output)
            self.assertIn("PYH-TAINT-CMD-001", output)

    def test_cli_taint_json_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            exit_code = run_cli(["taint", self.fixture_path, "--format", "json"])
            output = fake_out.getvalue()

            self.assertEqual(exit_code, 0)
            data = json.loads(output)
            self.assertIn("flows", data)
            self.assertIn("findings", data)
            self.assertGreater(len(data["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
