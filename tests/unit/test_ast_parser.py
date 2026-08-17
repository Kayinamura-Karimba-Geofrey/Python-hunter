"""Unit tests for AST Parser and ComprehensiveASTVisitor."""

import os
import unittest
from python_hunter.infrastructure.ast.parser import StandardASTParser

AST_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "ast"))


class TestASTParser(unittest.TestCase):
    """Unit test suite for AST Parser capabilities."""

    def setUp(self) -> None:
        self.parser = StandardASTParser()

    def test_basic_parsing(self) -> None:
        """Verify basic module parsing."""
        path = os.path.join(AST_FIXTURES_DIR, "basic_module.py")
        doc = self.parser.parse_file(path)

        self.assertIsNone(doc.parse_error)
        self.assertTrue(any(f.name == "hello" for f in doc.functions))
        self.assertIn("Hello, ", doc.constants)

    def test_import_and_alias_resolution(self) -> None:
        """Verify import extraction and call alias resolution (e.g. sp.run -> subprocess.run)."""
        path = os.path.join(AST_FIXTURES_DIR, "aliases.py")
        doc = self.parser.parse_file(path)

        self.assertIsNone(doc.parse_error)
        self.assertGreaterEqual(len(doc.imports), 2)

        # Check call resolution for sp.run -> subprocess.run
        sp_call = next((c for c in doc.calls if c.name == "sp.run"), None)
        self.assertIsNotNone(sp_call)
        self.assertEqual(sp_call.resolved_alias, "subprocess.run")
        self.assertEqual(sp_call.qualified_name, "subprocess.run")

        # Check call resolution for sys_call -> os.system
        sys_call = next((c for c in doc.calls if c.name == "sys_call"), None)
        self.assertIsNotNone(sys_call)
        self.assertEqual(sys_call.resolved_alias, "os.system")

    def test_functions_and_classes_extraction(self) -> None:
        """Verify function and class definition extraction."""
        path_fn = os.path.join(AST_FIXTURES_DIR, "functions.py")
        doc_fn = self.parser.parse_file(path_fn)
        self.assertTrue(any(f.is_async for f in doc_fn.functions))

        path_cls = os.path.join(AST_FIXTURES_DIR, "classes.py")
        doc_cls = self.parser.parse_file(path_cls)
        self.assertTrue(any(c.name == "UserService" for c in doc_cls.classes))

    def test_syntax_error_handling(self) -> None:
        """Verify syntax error handling produces ASTParseError without raising uncaught exception."""
        path = os.path.join(AST_FIXTURES_DIR, "syntax_error.py")
        doc = self.parser.parse_file(path)

        self.assertIsNotNone(doc.parse_error)
        self.assertEqual(doc.parse_error.error_type, "SYNTAX_ERROR")
        self.assertEqual(doc.parse_error.line, 1)

    def test_location_tracking(self) -> None:
        """Verify source location tracking attributes on AST nodes."""
        path = os.path.join(AST_FIXTURES_DIR, "basic_module.py")
        doc = self.parser.parse_file(path)

        hello_fn = next(f for f in doc.functions if f.name == "hello")
        self.assertIsNotNone(hello_fn.location)
        self.assertEqual(hello_fn.location.line_start, 3)


if __name__ == "__main__":
    unittest.main()
