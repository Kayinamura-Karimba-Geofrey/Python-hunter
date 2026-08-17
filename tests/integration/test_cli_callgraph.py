"""Integration tests for 'callgraph' CLI subcommand."""

import json
import os
import unittest
from io import StringIO
from unittest.mock import patch

from python_hunter.interfaces.cli.main import run_cli


class TestCLICallGraph(unittest.TestCase):
    """Integration test suite for python-hunter callgraph subcommand."""

    def setUp(self) -> None:
        self.fixture_path = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "callgraph", "app_flow.py"
        )

    def test_cli_callgraph_text_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            exit_code = run_cli(["callgraph", self.fixture_path])
            output = fake_out.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Python Hunter Interprocedural Call Graph & CFG Engine", output)
            self.assertIn("Discovered Application Entry Points", output)

    def test_cli_callgraph_json_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            exit_code = run_cli(["callgraph", self.fixture_path, "--format", "json"])
            output = fake_out.getvalue()

            self.assertEqual(exit_code, 0)
            data = json.loads(output)
            self.assertIn("symbols", data)
            self.assertIn("call_edges", data)
            self.assertIn("entry_points", data)

    def test_cli_callgraph_dot_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            exit_code = run_cli(["callgraph", self.fixture_path, "--format", "dot"])
            output = fake_out.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("digraph CallGraph", output)


if __name__ == "__main__":
    unittest.main()
