"""Unit tests for Step 47 Advanced Multi-Language Security Analysis Platform."""

import os
import tempfile
import unittest
from python_hunter.domain.analysis.ast_nodes import ASTNode, ASTNodeType, DataFlowEngine
from python_hunter.domain.analysis.monorepo import CrossLanguageCorrelationEngine, MonorepoDiscoveryEngine
from python_hunter.domain.language import Language, LanguageRegistry, PolyglotSecurityAnalysisEngine
from python_hunter.domain.language.detector import LanguageDetector


class TestPolyglotSecurityAnalysis(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = PolyglotSecurityAnalysisEngine()

    def test_all_13_languages_registered(self) -> None:
        registered = self.engine.registry.get_registered_languages()
        self.assertEqual(len(registered), 13)
        expected_langs = [
            Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT,
            Language.JAVA, Language.GO, Language.RUST, Language.C,
            Language.CPP, Language.CSHARP, Language.PHP, Language.RUBY,
            Language.KOTLIN, Language.SWIFT
        ]
        for lang in expected_langs:
            self.assertIn(lang, registered)

    def test_language_detector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create files for Python, TypeScript, and Go
            with open(os.path.join(tmp_dir, "app.py"), "w") as f:
                f.write("import os\nos.system('ls')\n")
            with open(os.path.join(tmp_dir, "index.ts"), "w") as f:
                f.write("eval('console.log(1)')\n")
            with open(os.path.join(tmp_dir, "main.go"), "w") as f:
                f.write("package main\n")

            profile = LanguageDetector.detect_workspace_languages(tmp_dir)
            self.assertIn("python", profile.percentage_by_files)
            self.assertIn("typescript", profile.percentage_by_files)
            self.assertIn("go", profile.percentage_by_files)

    def test_csharp_analyzer(self) -> None:
        adapter = self.engine.registry.get_adapter(Language.CSHARP)
        self.assertIsNotNone(adapter)
        with tempfile.TemporaryDirectory() as tmp_dir:
            cs_file = os.path.join(tmp_dir, "UserService.cs")
            with open(cs_file, "w") as f:
                f.write('var cmd = new SqlCommand("SELECT * FROM Users WHERE id = " + userId);\nProcess.Start(userInput);\n')
            findings = adapter.analyze(tmp_dir)
            self.assertGreaterEqual(len(findings), 2)
            rule_ids = [f["rule_id"] for f in findings]
            self.assertIn("PYH-CS-001", rule_ids)
            self.assertIn("PYH-CS-002", rule_ids)

    def test_kotlin_analyzer(self) -> None:
        adapter = self.engine.registry.get_adapter(Language.KOTLIN)
        self.assertIsNotNone(adapter)
        with tempfile.TemporaryDirectory() as tmp_dir:
            kt_file = os.path.join(tmp_dir, "AuthActivity.kt")
            with open(kt_file, "w") as f:
                f.write('db.rawQuery("SELECT * FROM users WHERE name = " + name, null)\nwebView.setJavaScriptEnabled(true)\n')
            findings = adapter.analyze(tmp_dir)
            self.assertGreaterEqual(len(findings), 2)
            rule_ids = [f["rule_id"] for f in findings]
            self.assertIn("PYH-KT-001", rule_ids)
            self.assertIn("PYH-KT-002", rule_ids)

    def test_swift_adapter(self) -> None:
        adapter = self.engine.registry.get_adapter(Language.SWIFT)
        self.assertIsNotNone(adapter)
        with tempfile.TemporaryDirectory() as tmp_dir:
            swift_file = os.path.join(tmp_dir, "LoginViewController.swift")
            with open(swift_file, "w") as f:
                f.write('UserDefaults.standard.set(userPassword, forKey: "password")\n')
            findings = adapter.analyze(tmp_dir)
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule_id"], "PYH-SW-001")

    def test_ast_dataflow_engine(self) -> None:
        call_node = ASTNode(
            node_type=ASTNodeType.CALL_EXPRESSION,
            name="os.system",
            code_snippet="os.system(request.args.get('cmd'))",
            file_path="src/app.py",
            start_line=10,
            end_line=10
        )
        taint = DataFlowEngine.analyze_node_dataflow(call_node)
        self.assertIsNotNone(taint)
        self.assertEqual(taint.sink_type, "COMMAND_EXECUTION")
        self.assertEqual(taint.source_type, "HTTP_REQUEST_PARAM")

    def test_monorepo_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "frontend"))
            os.makedirs(os.path.join(tmp_dir, "backend"))
            with open(os.path.join(tmp_dir, "frontend", "package.json"), "w") as f:
                f.write("{}")
            with open(os.path.join(tmp_dir, "backend", "requirements.txt"), "w") as f:
                f.write("flask==2.0")

            sub_projs = MonorepoDiscoveryEngine.discover_monorepo_projects(tmp_dir)
            self.assertEqual(len(sub_projs), 2)
            names = [p.name for p in sub_projs]
            self.assertIn("frontend", names)
            self.assertIn("backend", names)


if __name__ == "__main__":
    unittest.main()
