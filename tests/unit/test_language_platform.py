"""Unit tests for Step 33 — Multi-Language Analysis Platform."""

import os
import shutil
import tempfile
import unittest

from python_hunter.domain.dependencies.polyglot_dependency_adapter import PolyglotDependencyAdapter
from python_hunter.domain.frameworks.framework_registry import FrameworkRegistry
from python_hunter.domain.language.c_cpp_adapter import CLanguageAdapter, CPPLanguageAdapter
from python_hunter.domain.language.detector import LanguageDetector
from python_hunter.domain.language.go_adapter import GoLanguageAdapter
from python_hunter.domain.language.java_adapter import JavaLanguageAdapter
from python_hunter.domain.language.javascript_adapter import JavaScriptLanguageAdapter, TypeScriptLanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language
from python_hunter.domain.language.parser_provider import ParserProvider
from python_hunter.domain.language.php_adapter import PHPLanguageAdapter
from python_hunter.domain.language.python_adapter import PythonLanguageAdapter
from python_hunter.domain.language.registry import LanguageRegistry
from python_hunter.domain.language.ruby_adapter import RubyLanguageAdapter
from python_hunter.domain.language.rust_adapter import RustLanguageAdapter
from python_hunter.domain.rules.polyglot_rule_registry import PolyglotRuleRegistry


class TestMultiLanguagePlatform(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_language_registry_supports_10_languages(self):
        registry = LanguageRegistry()
        registered = registry.get_registered_languages()
        self.assertEqual(len(registered), 13)

        expected_langs = [
            Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT,
            Language.JAVA, Language.GO, Language.RUST,
            Language.C, Language.CPP, Language.PHP, Language.RUBY,
        ]
        for lang in expected_langs:
            self.assertIn(lang, registered)
            adapter = registry.get_adapter(lang)
            self.assertIsNotNone(adapter)
            self.assertTrue(adapter.capabilities.supports(AnalyzerCapability.AST))

    def test_language_detector_polyglot_profile(self):
        # Create polyglot project structure
        os.makedirs(os.path.join(self.temp_dir, "src/java"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "src/go"), exist_ok=True)

        with open(os.path.join(self.temp_dir, "main.py"), "w") as f:
            f.write("print('hello python')\n")

        with open(os.path.join(self.temp_dir, "src/java/App.java"), "w") as f:
            f.write("public class App { public static void main(String[] args) {} }\n")

        with open(os.path.join(self.temp_dir, "src/go/main.go"), "w") as f:
            f.write("package main\nfunc main() {}\n")

        with open(os.path.join(self.temp_dir, "pom.xml"), "w") as f:
            f.write("<project></project>\n")

        profile = LanguageDetector.detect_workspace_languages(self.temp_dir)
        self.assertGreaterEqual(profile.total_files, 3)
        self.assertIn("python", profile.percentage_by_lines)
        self.assertIn("java", profile.percentage_by_lines)
        self.assertIn("go", profile.percentage_by_lines)
        self.assertIn("pom.xml", profile.detected_manifests)

    def test_parser_provider_failure_isolation(self):
        code_broken = "def broken_func(:\n    invalid syntax here!"
        res = ParserProvider.parse_python(code_broken, "broken.py")
        self.assertTrue(res.is_partial)
        self.assertEqual(len(res.diagnostics), 1)
        self.assertIn("Syntax Error", res.diagnostics[0].message)

    def test_java_adapter_vulnerabilities(self):
        java_path = os.path.join(self.temp_dir, "Vulnerable.java")
        with open(java_path, "w") as f:
            f.write("""
            public class Vulnerable {
                public void testSql(String id) {
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
                }
                public void testCmd(String cmd) {
                    Runtime.getRuntime().exec(cmd);
                }
                public void testDeserialize(ObjectInputStream in) throws Exception {
                    in.readObject();
                }
            }
            """)

        adapter = JavaLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 3)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PYH-JAVA-001", rule_ids)
        self.assertIn("PYH-JAVA-002", rule_ids)
        self.assertIn("PYH-JAVA-003", rule_ids)

    def test_go_adapter_vulnerabilities(self):
        go_path = os.path.join(self.temp_dir, "main.go")
        with open(go_path, "w") as f:
            f.write("""
            package main
            import ("database/sql"; "fmt"; "os/exec"; "net/http")
            func handler(id string) {
                db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
                exec.Command(id)
                http.Get(id)
            }
            """)

        adapter = GoLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 3)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PYH-GO-001", rule_ids)
        self.assertIn("PYH-GO-002", rule_ids)

    def test_rust_adapter_vulnerabilities(self):
        rs_path = os.path.join(self.temp_dir, "main.rs")
        with open(rs_path, "w") as f:
            f.write("""
            fn main() {
                unsafe {
                    let ptr = 0x1234 as *const i32;
                }
                std::process::Command::new("sh");
            }
            """)

        adapter = RustLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 2)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PYH-RUST-001", rule_ids)
        self.assertIn("PYH-RUST-002", rule_ids)

    def test_c_cpp_adapter_vulnerabilities(self):
        c_path = os.path.join(self.temp_dir, "main.c")
        with open(c_path, "w") as f:
            f.write("""
            #include <stdio.h>
            #include <string.h>
            void func(char *str) {
                char buf[10];
                strcpy(buf, str);
                system(str);
            }
            """)

        adapter = CLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 2)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PYH-C-001", rule_ids)
        self.assertIn("PYH-C-002", rule_ids)

    def test_php_adapter_vulnerabilities(self):
        php_path = os.path.join(self.temp_dir, "app.php")
        with open(php_path, "w") as f:
            f.write("""
            <?php
            system($_GET['cmd']);
            include $_GET['page'];
            unserialize($_POST['data']);
            echo $_GET['user'];
            ?>
            """)

        adapter = PHPLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 4)

    def test_ruby_adapter_vulnerabilities(self):
        rb_path = os.path.join(self.temp_dir, "app.rb")
        with open(rb_path, "w") as f:
            f.write("""
            class App
              def query(param)
                User.where("name = '#{params[:name]}'")
                Marshal.load(params[:data])
                eval(params[:code])
              end
            end
            """)

        adapter = RubyLanguageAdapter()
        findings = adapter.analyze(self.temp_dir)
        self.assertGreaterEqual(len(findings), 3)

    def test_polyglot_dependency_adapter(self):
        pom_path = os.path.join(self.temp_dir, "pom.xml")
        with open(pom_path, "w") as f:
            f.write("<project><artifactId>spring-boot-starter-web</artifactId><version>2.7.0</version></project>")

        req_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("django==4.2.0\nfastapi==0.95.0\n")

        deps = PolyglotDependencyAdapter.parse_workspace_dependencies(self.temp_dir)
        self.assertGreaterEqual(len(deps), 3)
        ecosystems = [d.ecosystem for d in deps]
        self.assertIn("Maven", ecosystems)
        self.assertIn("PyPI", ecosystems)


if __name__ == "__main__":
    unittest.main()
