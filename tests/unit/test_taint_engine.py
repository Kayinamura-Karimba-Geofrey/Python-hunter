"""Unit tests for Static Dataflow & Taint Analysis Engine."""

import ast
import unittest

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.taint.engine import TaintAnalysisEngine
from python_hunter.domain.taint.models import TaintSinkCategory


class TestTaintEngine(unittest.TestCase):
    """Test suite for TaintAnalysisEngine AST visitor and flow discovery."""

    def setUp(self) -> None:
        self.engine = TaintAnalysisEngine()

    def test_sql_injection_detection(self) -> None:
        code = """
username = request.args["username"]
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)
        """
        doc = ASTDocument(file_path="test_sql.py", module_name="test_sql", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_category, TaintSinkCategory.SQL_INJECTION)
        self.assertEqual(flows[0].vulnerability_type, "PYH-TAINT-SQL-001")

    def test_command_injection_detection(self) -> None:
        code = """
cmd = request.args["cmd"]
os.system(cmd)
        """
        doc = ASTDocument(file_path="test_cmd.py", module_name="test_cmd", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_category, TaintSinkCategory.COMMAND_INJECTION)

    def test_path_traversal_detection(self) -> None:
        code = """
path = request.args["path"]
open(path, "r")
        """
        doc = ASTDocument(file_path="test_path.py", module_name="test_path", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink_category, TaintSinkCategory.PATH_TRAVERSAL)

    def test_safe_parameterized_sql_negative_case(self) -> None:
        code = """
username = request.args["username"]
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
        """
        doc = ASTDocument(file_path="test_safe.py", module_name="test_safe", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 0)

    def test_safe_subprocess_array_negative_case(self) -> None:
        code = """
filename = request.args["filename"]
subprocess.run(["ls", filename], shell=False)
        """
        doc = ASTDocument(file_path="test_safe_cmd.py", module_name="test_safe_cmd", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 0)

    def test_sanitized_path_negative_case(self) -> None:
        code = """
filename = request.args["filename"]
safe_name = os.path.basename(filename)
open(safe_name, "r")
        """
        doc = ASTDocument(file_path="test_san.py", module_name="test_san", source_lines=code.strip().split("\n"))
        flows = self.engine.analyze_document(doc)
        self.assertEqual(len(flows), 0)


if __name__ == "__main__":
    unittest.main()
