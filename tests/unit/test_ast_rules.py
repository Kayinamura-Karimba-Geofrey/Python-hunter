"""Unit tests for built-in AST security rules (PYH-AST-001 to PYH-AST-010)."""

import os
import unittest
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.projects.project import Project
from python_hunter.infrastructure.ast.parser import StandardASTParser
from python_hunter.rules.ast.pyh_ast_001_eval import PYHAST001Eval
from python_hunter.rules.ast.pyh_ast_004_os_system import PYHAST004OsSystem
from python_hunter.rules.ast.pyh_ast_005_subprocess_shell import PYHAST005SubprocessShell
from python_hunter.rules.ast.pyh_ast_006_pickle import PYHAST006Pickle
from python_hunter.rules.ast.pyh_ast_009_hardcoded_credentials import PYHAST009HardcodedCredentials

RULES_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "security_rules"))


class TestASTRules(unittest.TestCase):
    """Unit test suite for built-in AST security rules."""

    def setUp(self) -> None:
        self.parser = StandardASTParser()
        self.context = AnalysisContext(
            scan_id="test-scan",
            project=Project(name="test", root_path=RULES_FIXTURES_DIR),
            target_files=[],
        )

    def test_pyh_ast_001_eval_rule(self) -> None:
        """Verify PYH-AST-001 detects eval calls."""
        path = os.path.join(RULES_FIXTURES_DIR, "eval", "vulnerable_eval.py")
        doc = self.parser.parse_file(path)
        rule = PYHAST001Eval()

        findings = rule.evaluate(ast_summary=type("Summary", (), {"documents": [doc]})(), context=self.context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-AST-001")
        self.assertEqual(rule.cwe, "CWE-95")

    def test_pyh_ast_005_subprocess_shell_rule(self) -> None:
        """Verify PYH-AST-005 detects shell=True and ignores shell=False."""
        vuln_path = os.path.join(RULES_FIXTURES_DIR, "subprocess", "vulnerable_subprocess.py")
        safe_path = os.path.join(RULES_FIXTURES_DIR, "subprocess", "safe_subprocess.py")

        doc_vuln = self.parser.parse_file(vuln_path)
        doc_safe = self.parser.parse_file(safe_path)
        rule = PYHAST005SubprocessShell()

        findings_vuln = rule.evaluate(ast_summary=type("Summary", (), {"documents": [doc_vuln]})(), context=self.context)
        self.assertEqual(len(findings_vuln), 1)

        findings_safe = rule.evaluate(ast_summary=type("Summary", (), {"documents": [doc_safe]})(), context=self.context)
        self.assertEqual(len(findings_safe), 0)

    def test_pyh_ast_006_pickle_rule(self) -> None:
        """Verify PYH-AST-006 detects pickle.loads."""
        path = os.path.join(RULES_FIXTURES_DIR, "pickle", "vulnerable_pickle.py")
        doc = self.parser.parse_file(path)
        rule = PYHAST006Pickle()

        findings = rule.evaluate(ast_summary=type("Summary", (), {"documents": [doc]})(), context=self.context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-AST-006")


if __name__ == "__main__":
    unittest.main()
