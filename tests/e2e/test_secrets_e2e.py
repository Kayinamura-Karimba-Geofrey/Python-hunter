"""E2E Test Suite for Step 36 Secrets Engine & Credential Exposure Intelligence."""

import os
import shutil
import subprocess
import tempfile
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.secrets.git_history_engine import PRSecretDiffEngine
from python_hunter.domain.secrets.models import SecretCandidate, SecretType


class TestSecretsE2E(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.service = SecurityApplicationService()

        # Initialize git repo in temp_dir for git history testing
        subprocess.run(["git", "init"], cwd=self.temp_dir, capture_output=True, check=False)
        subprocess.run(["git", "config", "user.name", "TestUser"], cwd=self.temp_dir, capture_output=True, check=False)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.temp_dir, capture_output=True, check=False)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_e2e_workspace_secrets_scan_and_redaction(self):
        # Create a workspace with multiple secret types
        config_path = os.path.join(self.temp_dir, "config.py")
        raw_gcp_key = "AIzaSyB3q7_k9Xm2Lp0r8StVuWz1Y234567890"
        with open(config_path, "w") as f:
            f.write(f"GCP_KEY = '{raw_gcp_key}'\n")

        dotenv_path = os.path.join(self.temp_dir, ".env")
        raw_db_url = "postgres://admin:SuperSecretPass123!@localhost:5432/mydb"
        with open(dotenv_path, "w") as f:
            f.write(f"DATABASE_URL={raw_db_url}\n")

        res = self.service.execute_secrets_scan(self.temp_dir)

        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreaterEqual(res["active_secrets_count"], 2)

        # Zero raw secret leakage assertion
        for sec in res["active_secrets"]:
            self.assertNotIn(raw_gcp_key, sec["evidence"])
            self.assertNotIn("SuperSecretPass123!", sec["evidence"])
            self.assertTrue(sec["fingerprint"].startswith("sec_fp_"))

    def test_e2e_git_history_deleted_secret_detection(self):
        # Step 1: Commit file containing secret
        sec_file = os.path.join(self.temp_dir, "credentials.py")
        raw_stripe_key = "sk_test_51NxXxXxXxXxXxXxXxXxXxXxX"
        with open(sec_file, "w") as f:
            f.write(f"STRIPE_KEY = '{raw_stripe_key}'\n")

        subprocess.run(["git", "add", "credentials.py"], cwd=self.temp_dir, capture_output=True, check=False)
        subprocess.run(["git", "commit", "-m", "Add credentials"], cwd=self.temp_dir, capture_output=True, check=False)

        # Step 2: Delete secret in subsequent commit
        with open(sec_file, "w") as f:
            f.write("# Removed credentials\n")

        subprocess.run(["git", "add", "credentials.py"], cwd=self.temp_dir, capture_output=True, check=False)
        subprocess.run(["git", "commit", "-m", "Remove credentials"], cwd=self.temp_dir, capture_output=True, check=False)

        # Execute scan with history=True
        res = self.service.execute_secrets_scan(self.temp_dir, scan_history=True)

        self.assertGreaterEqual(res["historical_secrets_count"], 1)
        hist_sec = res["historical_secrets"][0]
        self.assertEqual(hist_sec["file_path"], "credentials.py")
        self.assertNotIn(raw_stripe_key, str(hist_sec))

    def test_e2e_pr_secret_diffing(self):
        cand1 = SecretCandidate("val1", "app.py", 10, 1, "PYH-SECRET-001", SecretType.API_KEY)
        cand2 = SecretCandidate("val2", "app.py", 20, 1, "PYH-SECRET-011", SecretType.GCP_KEY)

        base_fps = {cand1.fingerprint}
        head_cands = [cand1, cand2]

        diff_res = PRSecretDiffEngine.compare_secret_candidates(base_fps, head_cands)
        self.assertTrue(diff_res["has_introduced_secrets"])
        self.assertEqual(diff_res["introduced_count"], 1)
        self.assertEqual(diff_res["introduced_candidates"][0].fingerprint, cand2.fingerprint)


if __name__ == "__main__":
    unittest.main()
