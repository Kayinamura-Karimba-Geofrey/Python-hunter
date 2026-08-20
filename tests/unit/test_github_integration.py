"""Unit tests for GitHub App Integration, Webhooks, Signature Validation, Replay Protection, SSRF, Secret Redaction, and PR Security Delta Engine."""

import hashlib
import hmac
import json
import unittest

from python_hunter.domain.github.github_app import GitHubAppIntegration
from python_hunter.domain.github.github_checks_service import GitHubChecksService, GitHubCommentService
from python_hunter.domain.github.github_models import PolicyResultStatus
from python_hunter.domain.github.pr_security_engine import PullRequestSecurityEngine, SecretRedactor
from python_hunter.domain.github.repo_config import RepoConfigParser
from python_hunter.domain.github.webhook_handler import GitHubWebhookHandler, WebhookValidationError
from python_hunter.domain.github.webhook_queue import GitHubWebhookEventQueue
from python_hunter.infrastructure.github.isolated_checkout import IsolatedCheckoutService


class TestGitHubIntegration(unittest.TestCase):

    def test_github_app_jwt_generation(self):
        app = GitHubAppIntegration(app_id="9941", private_key="MOCK_KEY")
        jwt_token = app.generate_jwt()
        self.assertTrue(jwt_token.startswith("pyh_jwt_app_9941") or len(jwt_token) > 10)

        masked = app.mask_token("ghs_1234567890abcdef")
        self.assertEqual(masked, "ghs_****cdef")

    def test_webhook_signature_validation(self):
        handler = GitHubWebhookHandler(secret="test_secret_123")
        payload = json.dumps({"action": "opened", "number": 1}).encode("utf-8")
        
        # Valid signature
        mac = hmac.new(b"test_secret_123", msg=payload, digestmod=hashlib.sha256)
        valid_sig = f"sha256={mac.hexdigest()}"
        
        self.assertTrue(handler.validate_signature(payload, valid_sig))

        # Invalid signature
        with self.assertRaises(WebhookValidationError):
            handler.validate_signature(payload, "sha256=invalid_hash_value")

        # Missing header
        with self.assertRaises(WebhookValidationError):
            handler.validate_signature(payload, None)

    def test_webhook_replay_protection(self):
        handler = GitHubWebhookHandler(secret="test_secret_123")
        delivery_id = "deliv-uuid-112233"

        # First delivery succeeds
        is_new_1 = handler.check_replay_and_record(delivery_id, "pull_request")
        self.assertTrue(is_new_1)

        # Duplicate delivery is rejected/flagged as false
        is_new_2 = handler.check_replay_and_record(delivery_id, "pull_request")
        self.assertFalse(is_new_2)

    def test_ssrf_host_validation(self):
        handler = GitHubWebhookHandler()
        self.assertTrue(handler.validate_ssrf_host("https://github.com/myorg/myrepo"))
        self.assertTrue(handler.validate_ssrf_host("https://api.github.com/repos/myorg/myrepo"))

        with self.assertRaises(WebhookValidationError):
            handler.validate_ssrf_host("http://169.254.169.254/latest/meta-data")

        with self.assertRaises(WebhookValidationError):
            handler.validate_ssrf_host("https://malicious-external-server.com/evil")

    def test_secret_redaction(self):
        secret = "ghp_1234567890SecretKey"
        redacted = SecretRedactor.redact_secret(secret)
        self.assertEqual(redacted, "ghp****Key")

        finding = {
            "id": "f1",
            "title": "Exposed API Secret",
            "code_snippet": 'api_key = "ghp_1234567890SecretKey"',
        }
        redacted_finding = SecretRedactor.redact_finding_dict(finding)
        self.assertNotIn("ghp_1234567890SecretKey", redacted_finding["code_snippet"])
        self.assertIn("****", redacted_finding["code_snippet"])

    def test_pr_security_delta_calculation(self):
        engine = PullRequestSecurityEngine()
        
        base_findings = [
            {"id": "f1", "title": "SQLi", "severity": "CRITICAL", "risk_score": 9.0, "file_path": "db.py"},
            {"id": "f2", "title": "XSS", "severity": "MEDIUM", "risk_score": 5.0, "file_path": "app.py"},
        ]
        head_findings = [
            {"id": "f2", "title": "XSS", "severity": "MEDIUM", "risk_score": 5.0, "file_path": "app.py"},
        ]  # f1 fixed in PR!

        res = engine.analyze_pull_request(
            pr_number=42,
            repository="org/repo",
            base_sha="base123",
            head_sha="head456",
            base_findings=base_findings,
            head_findings=head_findings,
            base_attack_paths=[],
            head_attack_paths=[],
            changed_files=["db.py"],
            base_dependencies=[],
            head_dependencies=[],
        )

        self.assertEqual(len(res.fixed_findings), 1)
        self.assertEqual(res.fixed_findings[0]["id"], "f1")
        self.assertEqual(len(res.new_findings), 0)
        self.assertGreater(res.score_delta, 0)
        self.assertEqual(res.policy_result, PolicyResultStatus.PASS)

    def test_check_run_annotations_and_limits(self):
        checks_service = GitHubChecksService()
        engine = PullRequestSecurityEngine()

        new_findings = [
            {"id": f"f-{i}", "title": f"Vulnerability {i}", "severity": "HIGH", "risk_score": 8.0, "file_path": "auth.py", "description": "High severity finding"}
            for i in range(70)
        ]

        res = engine.analyze_pull_request(
            pr_number=10,
            repository="org/repo",
            base_sha="base",
            head_sha="head",
            base_findings=[],
            head_findings=new_findings,
            base_attack_paths=[],
            head_attack_paths=[],
            changed_files=["auth.py"],
            base_dependencies=[],
            head_dependencies=[],
        )

        summary = engine.generate_summary(res, {"id": "pr-10", "number": 10})
        check_run = checks_service.build_check_run(res, summary, max_annotations=50)

        self.assertEqual(len(check_run.annotations), 50)
        self.assertIn("Exceeded maximum annotation limit", check_run.text)

    def test_repo_config_parsing_and_server_override(self):
        yaml_content = """
        scan_profile: strict
        score_threshold: 40
        max_annotations: 25
        """
        config = RepoConfigParser.parse_yaml(yaml_content)
        self.assertEqual(config.score_threshold, 40)

        # Server policy enforces minimum threshold of 60
        server_policy = {"min_score_threshold": 60, "force_pr_scans": True}
        validated = RepoConfigParser.validate_against_server_policy(config, server_policy)
        self.assertEqual(validated.score_threshold, 60)


if __name__ == "__main__":
    unittest.main()
