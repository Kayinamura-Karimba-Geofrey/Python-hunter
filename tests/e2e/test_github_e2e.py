"""End-to-End Test for GitHub Integration & Pull Request Security Platform."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.infrastructure.storage.scan_store import ScanResultStore


class TestGitHubWorkflowE2E(unittest.TestCase):

    def test_github_pr_workflow_e2e(self):
        secret = "pyh_webhook_secret_dev_12345"
        data_dir = tempfile.TemporaryDirectory()
        self.addCleanup(data_dir.cleanup)
        with mock.patch.dict(os.environ, {"PYH_WEBHOOK_SECRET": secret}):
            svc = SecurityApplicationService(store=ScanResultStore(data_dir.name))

        payload_data = {
            "action": "synchronize",
            "number": 42,
            "pull_request": {
                "id": "pr-42",
                "number": 42,
                "title": "Add JWT Auth and parameterize SQL query",
                "user": {"login": "kayinamura-geofrey"},
                "base": {"sha": "a1b2c3d4e5", "ref": "main"},
                "head": {"sha": "f6g7h8i9j0", "ref": "feature/auth-hardening"},
            },
            "repository": {
                "full_name": "kayinamura-karimba-geofrey/python-hunter",
                "clone_url": "https://github.com/kayinamura-karimba-geofrey/python-hunter.git",
            },
            "installation": {
                "id": 9941,
                "account": {"login": "kayinamura-karimba-geofrey"},
                "permissions": {"contents": "read", "pull_requests": "write", "checks": "write"},
            },
        }

        raw_body = json.dumps(payload_data).encode("utf-8")
        mac = hmac.new(secret.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
        sig_header = f"sha256={mac.hexdigest()}"
        delivery_id = "deliv-e2e-001"

        # 1. Process webhook event via application service
        res_data = svc.process_github_webhook(
            raw_body=raw_body,
            signature_header=sig_header,
            delivery_id=delivery_id,
            event_type="pull_request",
        )
        self.assertEqual(res_data["status"], "ACCEPTED")

        # 2. Verify webhook status metrics updated
        st_data = svc.get_webhook_status()
        self.assertTrue(st_data["webhook_active"])
        self.assertGreaterEqual(st_data["total_events"], 1)

        # 3. Query Pull Requests list
        prs = svc.list_pull_requests()
        self.assertGreaterEqual(len(prs), 1)
        target_pr = prs[0]
        self.assertEqual(target_pr["pr_number"], 42)
        self.assertEqual(target_pr["policy_result"], "PASS")
        self.assertEqual(target_pr["title"], "Add JWT Auth and parameterize SQL query")
        self.assertEqual(target_pr["author"], "kayinamura-geofrey")

        # 4. Re-analyze with real BASE/HEAD findings: the SQL injection is fixed on HEAD
        base_findings = [
            {
                "id": "find-1",
                "title": "SQL Injection in User Lookup Query",
                "rule_id": "PYH-SQLI-001",
                "severity": "CRITICAL",
                "risk_score": 9.2,
                "file_path": "src/db.py",
                "line_number": 42,
            }
        ]
        svc.run_pull_request_analysis(
            "kayinamura-karimba-geofrey/python-hunter",
            42,
            "a1b2c3d4e5",
            "f6g7h8i9j0",
            base_findings=base_findings,
            head_findings=[],
            changed_files=["src/db.py"],
        )

        # 5. Query PR detail
        detail = svc.get_pull_request_detail(target_pr["pr_id"])
        self.assertIn("security_relevant_files", detail)
        self.assertGreaterEqual(len(detail["timeline"]), 2)
        self.assertGreaterEqual(detail["fixed_vulnerabilities_count"], 1)

        # 6. Query GitHub installations
        inst_data = svc.list_github_installations()
        self.assertGreaterEqual(len(inst_data), 1)
        self.assertEqual(inst_data[0]["status"], "ACTIVE")
        self.assertIn("kayinamura-karimba-geofrey/python-hunter", inst_data[0]["repositories"])


if __name__ == "__main__":
    unittest.main()
