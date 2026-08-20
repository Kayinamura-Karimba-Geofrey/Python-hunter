"""End-to-End Test for GitHub Integration & Pull Request Security Platform."""

import hashlib
import hmac
import json
import unittest

from python_hunter.application.services.security_app_service import SecurityApplicationService


class TestGitHubWorkflowE2E(unittest.TestCase):

    def test_github_pr_workflow_e2e(self):
        svc = SecurityApplicationService()
        secret = "pyh_webhook_secret_dev_12345"
        
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

        # 4. Query PR detail
        detail = svc.get_pull_request_detail(target_pr["pr_id"])
        self.assertIn("security_relevant_files", detail)
        self.assertIn("timeline", detail)
        self.assertGreaterEqual(detail["fixed_vulnerabilities_count"], 1)

        # 5. Query GitHub installations
        inst_data = svc.list_github_installations()
        self.assertGreaterEqual(len(inst_data), 1)
        self.assertEqual(inst_data[0]["status"], "ACTIVE")


if __name__ == "__main__":
    unittest.main()
