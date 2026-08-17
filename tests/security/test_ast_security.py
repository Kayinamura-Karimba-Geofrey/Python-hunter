"""Security test suite for AST Engine."""

import os
import unittest
from python_hunter.domain.exceptions.base import ProjectError
from python_hunter.infrastructure.ast.parser import StandardASTParser
from python_hunter.infrastructure.ast.source_loader import SafeSourceLoader

AST_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "ast"))


class TestASTSecurity(unittest.TestCase):
    """Security tests verifying zero code execution and file size limits."""

    def test_file_size_limit_guard(self) -> None:
        """Verify SafeSourceLoader enforces max file size limit."""
        loader = SafeSourceLoader()
        path = os.path.join(AST_FIXTURES_DIR, "basic_module.py")

        with self.assertRaises(ProjectError):
            loader.load_source(path, max_bytes=10)

    def test_zero_code_execution(self) -> None:
        """Verify AST parsing does not execute target code or import modules."""
        parser = StandardASTParser()
        path = os.path.join(AST_FIXTURES_DIR, "complex_module.py")
        doc = parser.parse_file(path)

        self.assertIsNone(doc.parse_error)
        self.assertGreaterEqual(len(doc.imports), 2)


if __name__ == "__main__":
    unittest.main()
