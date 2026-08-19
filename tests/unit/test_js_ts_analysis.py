"""Unit and Integration tests for Step 24 JavaScript & TypeScript security engine."""

import os
import unittest
from python_hunter.domain.dependencies.models import PackageManager
from python_hunter.domain.dependencies.npm_analyzer import NPMAnalyzer
from python_hunter.domain.discovery.language_detector import LanguageDetector
from python_hunter.domain.language.javascript.parser import JSParser
from python_hunter.domain.language.javascript_adapter import JavaScriptLanguageAdapter, TypeScriptLanguageAdapter
from python_hunter.domain.language.models import Language
from python_hunter.domain.rules.javascript.rule_engine import JSSecurityRuleEngine


class TestJSTSAnalysisEngine(unittest.TestCase):
    """Test suite for JavaScript and TypeScript AST parsing, adapters, security rules, and npm analysis."""

    def setUp(self) -> None:
        self.js_adapter = JavaScriptLanguageAdapter()
        self.ts_adapter = TypeScriptLanguageAdapter()
        self.js_rule_engine = JSSecurityRuleEngine()
        self.npm_analyzer = NPMAnalyzer()

    def test_js_parser_functions_and_calls(self) -> None:
        content = """
        function executeQuery(userInput) {
            const query = "SELECT * FROM users WHERE id = " + userInput;
            db.query(query);
        }
        """
        parser = JSParser()
        nodes = parser.parse_file("app.js", content)
        func_nodes = [n for n in nodes if n.node_type == "function"]
        call_nodes = [n for n in nodes if n.node_type == "call"]
        self.assertTrue(len(func_nodes) > 0)
        self.assertTrue(len(call_nodes) > 0)

    def test_js_security_rules_sqli_and_eval(self) -> None:
        content = """
        db.query("SELECT * FROM users WHERE id = " + req.query.id);
        eval(req.body.code);
        """
        findings = self.js_rule_engine.analyze_file("app.js", content, Language.JAVASCRIPT)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYHUNTER-JS-SQL-001", rule_ids)
        self.assertIn("PYHUNTER-JS-CODE-001", rule_ids)

    def test_npm_analyzer_static_parsing(self) -> None:
        result = self.npm_analyzer.analyze(".")
        self.assertIn(result.package_manager, (PackageManager.NPM, PackageManager.UNKNOWN))


if __name__ == "__main__":
    unittest.main()
