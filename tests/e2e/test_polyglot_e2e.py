"""E2E Test for Polyglot Repository Scanning and Cross-Language Analysis."""

import os
import shutil
import tempfile
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestPolyglotE2E(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.service = SecurityApplicationService()

        # Build a 4-tier polyglot microservice repository fixture
        # Frontend: TypeScript
        # Backend: Java Spring Boot
        # Worker: Python
        # Service: Go
        os.makedirs(os.path.join(self.temp_dir, "frontend"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "backend/src/main/java"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "worker"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "service"), exist_ok=True)

        with open(os.path.join(self.temp_dir, "frontend/apiClient.ts"), "w") as f:
            f.write("export async function fetchUsers() { return fetch('/api/users'); }\n")

        with open(os.path.join(self.temp_dir, "backend/src/main/java/UserController.java"), "w") as f:
            f.write("""
            @RestController
            public class UserController {
                @GetMapping("/api/users")
                public String getUsers(String query) {
                    Statement stmt = conn.createStatement();
                    return stmt.executeQuery("SELECT * FROM users WHERE name = '" + query + "'");
                }
            }
            """)

        with open(os.path.join(self.temp_dir, "backend/pom.xml"), "w") as f:
            f.write("<project><artifactId>spring-boot-starter-web</artifactId><version>2.7.0</version></project>\n")

        with open(os.path.join(self.temp_dir, "worker/tasks.py"), "w") as f:
            f.write("""
            import os
            def execute_task(cmd):
                os.system(cmd)
            """)

        with open(os.path.join(self.temp_dir, "service/main.go"), "w") as f:
            f.write("""
            package main
            import ("database/sql"; "fmt")
            func queryData(param string) {
                db.Query(fmt.Sprintf("SELECT * FROM data WHERE key = %s", param))
            }
            """)

        with open(os.path.join(self.temp_dir, "service/go.mod"), "w") as f:
            f.write("module github.com/org/service\ngo 1.20\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_polyglot_workspace_scanning(self):
        # 1. Profile Detection
        profile = self.service.get_repository_language_profile(self.temp_dir)
        self.assertGreaterEqual(profile["total_files"], 4)
        self.assertIn("java", profile["percentage_by_lines"])
        self.assertIn("python", profile["percentage_by_lines"])
        self.assertIn("go", profile["percentage_by_lines"])
        self.assertIn("typescript", profile["percentage_by_lines"])

        # 2. Polyglot Security Scan
        result = self.service.scan_polyglot_workspace(self.temp_dir)
        self.assertGreaterEqual(result["total_findings"], 2)
        active_langs = result["active_languages"]
        self.assertIn("java", active_langs)
        self.assertIn("go", active_langs)
        self.assertIn("python", active_langs)

        # 3. Dependencies
        self.assertGreaterEqual(result["dependencies_count"], 1)

    def test_system_info_supported_languages(self):
        sys_info = self.service.get_system_info()
        self.assertIn("Java", sys_info["supported_languages"])
        self.assertIn("Go", sys_info["supported_languages"])
        self.assertIn("Rust", sys_info["supported_languages"])
        self.assertIn("C", sys_info["supported_languages"])
        self.assertIn("C++", sys_info["supported_languages"])
        self.assertIn("PHP", sys_info["supported_languages"])
        self.assertIn("Ruby", sys_info["supported_languages"])


if __name__ == "__main__":
    unittest.main()
