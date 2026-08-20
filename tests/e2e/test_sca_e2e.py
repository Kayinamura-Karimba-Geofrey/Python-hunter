"""End-to-end tests for Step 35 — Advanced Software Composition Analysis (SCA) Platform."""

import os
import shutil
import tempfile
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestSCAPlatformE2E(unittest.TestCase):

    def setUp(self) -> None:
        self.service = SecurityApplicationService()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_e2e_polyglot_sca_scan_with_reachability(self) -> None:
        reqs_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(reqs_path, "w", encoding="utf-8") as f:
            f.write("pillow==9.5.0\nflask==2.1.0\n")

        app_path = os.path.join(self.temp_dir, "app.py")
        with open(app_path, "w", encoding="utf-8") as f:
            f.write("""
def get_user_avatar(request):
    img = Image.open("avatar.webp")
    return img
""")

        res = self.service.execute_sca_scan(self.temp_dir)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertIn(reqs_path, res["manifests"])
        self.assertEqual(res["dependency_inventory"]["total_dependencies"], 2)
        self.assertGreaterEqual(res["vulnerability_findings_count"], 2)

        # Check reachability output
        findings = res["vulnerability_findings"]
        pillow_finding = next((f for f in findings if f["package"] == "pillow"), None)
        self.assertIsNotNone(pillow_finding)
        self.assertTrue(pillow_finding["reachability"]["is_reachable"])
        self.assertTrue(any("Image.open" in trace for trace in pillow_finding["reachability"]["call_trace"]))

    def test_e2e_unreachable_vulnerability_differentiation(self) -> None:
        reqs_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(reqs_path, "w", encoding="utf-8") as f:
            f.write("pillow==9.5.0\n")

        app_path = os.path.join(self.temp_dir, "app.py")
        with open(app_path, "w", encoding="utf-8") as f:
            f.write("""
def safe_math_func():
    return 1 + 1
""")

        res = self.service.execute_sca_scan(self.temp_dir)
        findings = res["vulnerability_findings"]
        pillow_finding = next((f for f in findings if f["package"] == "pillow"), None)
        self.assertIsNotNone(pillow_finding)
        self.assertFalse(pillow_finding["reachability"]["is_reachable"])
        self.assertIn("UNUSED / POSSIBLY UNUSED", pillow_finding["reachability"]["evidence"])


if __name__ == "__main__":
    unittest.main()
