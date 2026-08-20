"""E2E Test for Step 34 Interprocedural SAST Engine & Cross-File Traces."""

import os
import shutil
import tempfile
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestInterproceduralE2E(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.service = SecurityApplicationService()

        # Create multi-file interprocedural vulnerable architecture:
        # controller.py -> service.py -> repository.py (contains SQL query)
        os.makedirs(os.path.join(self.temp_dir, "app"), exist_ok=True)

        with open(os.path.join(self.temp_dir, "app/controller.py"), "w") as f:
            f.write("""
            def get_user_route(request):
                user_id = request.args
                return user_service(user_id)
            """)

        with open(os.path.join(self.temp_dir, "app/service.py"), "w") as f:
            f.write("""
            def user_service(uid):
                return user_repo(uid)
            """)

        with open(os.path.join(self.temp_dir, "app/repository.py"), "w") as f:
            f.write("""
            def user_repo(query_id):
                cursor.execute(query_id)
            """)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_interprocedural_cross_file_trace(self):
        res = self.service.execute_interprocedural_scan(self.temp_dir)
        self.assertIn("total_nodes", res)
        self.assertIn("total_evidences", res)
        self.assertIn("findings", res)

        findings = res["findings"]
        self.assertGreaterEqual(len(findings), 1)

        finding = findings[0]
        self.assertIn("trace_steps", finding)
        self.assertGreaterEqual(len(finding["trace_steps"]), 2)

    def test_false_positive_reduction_safe_fixture(self):
        safe_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(safe_dir, "safe_app.py"), "w") as f:
                f.write("""
                def safe_route(request):
                    clean_id = int(request.args)
                    cursor.execute("SELECT * FROM users WHERE id = %s", (clean_id,))
                """)

            res = self.service.execute_interprocedural_scan(safe_dir)
            # Safe parameterized query fixture should have no unhandled critical vulnerabilities
            unhandled_criticals = [f for f in res["findings"] if f["severity"] == "CRITICAL" and not f.get("is_sanitized")]
            self.assertEqual(len(unhandled_criticals), 0)
        finally:
            shutil.rmtree(safe_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
