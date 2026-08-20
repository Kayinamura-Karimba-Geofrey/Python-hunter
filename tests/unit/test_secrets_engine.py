"""Unit test suite for Step 36 Secrets Engine & Credential Exposure Intelligence."""

import unittest
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.secrets.context_analyzer import SecretContextAnalyzer
from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.domain.secrets.models import (
    SecretCandidate,
    SecretType,
    compute_secret_fingerprint,
)
from python_hunter.domain.secrets.placeholders import PlaceholderFilter
from python_hunter.domain.secrets.redaction import Redactor
from python_hunter.domain.secrets.validation import SecretValidator


class TestSecretsEngine(unittest.TestCase):

    def setUp(self):
        from python_hunter.domain.projects.project import Project
        self.engine = SecretDetectionEngine()
        self.context = AnalysisContext(scan_id="test_scan", project=Project(name="test", root_path="/tmp"))

    def test_non_reversible_secret_fingerprinting(self):
        secret1 = "AKIA1234567890EXAMPLE"
        secret2 = "AKIA1234567890EXAMPLE"
        secret3 = "AKIA9876543210DIFFERENT"

        fp1 = compute_secret_fingerprint(secret1)
        fp2 = compute_secret_fingerprint(secret2)
        fp3 = compute_secret_fingerprint(secret3)

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)
        self.assertTrue(fp1.startswith("sec_fp_"))
        self.assertNotIn(secret1, fp1)

    def test_zero_raw_secret_redaction_guarantee(self):
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = Redactor.redact_value(raw_secret)

        self.assertNotIn(raw_secret, redacted)
        self.assertIn("*", redacted)

        evidence = f"AWS_KEY = '{raw_secret}'"
        sanitized = Redactor.sanitize_evidence(evidence, raw_secret)
        self.assertNotIn(raw_secret, sanitized)

    def test_placeholder_filter(self):
        self.assertTrue(PlaceholderFilter.is_placeholder("YOUR_API_KEY"))
        self.assertTrue(PlaceholderFilter.is_placeholder("CHANGE_ME"))
        self.assertTrue(PlaceholderFilter.is_placeholder("xxxxxxxxxxxxxxxx"))
        self.assertFalse(PlaceholderFilter.is_placeholder("AIzaSyB3q7_k9Xm2Lp0r8StVuWz1Y234567890"))

    def test_offline_structural_validation(self):
        cand_aws = SecretCandidate(
            value="AKIA1234567890ABCD12",
            file_path="config.py",
            line=1,
            column=1,
            detector_id="PYH-SECRET-006",
            secret_type=SecretType.CLOUD_CREDENTIAL,
        )
        self.assertTrue(SecretValidator.validate_structurally(cand_aws))

        cand_invalid = SecretCandidate(
            value="short",
            file_path="config.py",
            line=1,
            column=1,
            detector_id="PYH-SECRET-006",
            secret_type=SecretType.CLOUD_CREDENTIAL,
        )
        self.assertFalse(SecretValidator.validate_structurally(cand_invalid))

    def test_detector_gcp_api_key(self):
        content = "GCP_KEY = 'AIzaSyB3q7_k9Xm2Lp0r8StVuWz1Y234567890'"
        findings = self.engine.scan_file("settings.py", content, self.context)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SECRET-011")
        self.assertNotIn("AIzaSyB3q7", findings[0].evidence)
        self.assertIn("*", findings[0].evidence)

    def test_detector_stripe_key(self):
        content = "STRIPE_SECRET = 'sk_test_51NxXxXxXxXxXxXxXxXxXxXxX'"
        findings = self.engine.scan_file("app.py", content, self.context)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYH-SECRET-013")
        self.assertIn(findings[0].severity, (Severity.CRITICAL, Severity.MEDIUM))

    def test_detector_private_key_pem(self):
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Z3v9...
        -----END RSA PRIVATE KEY-----
        """
        findings = self.engine.scan_file("server.key", content, self.context)

        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any(f.rule_id in ("PYH-SECRET-014", "PYH-SECRET-003") for f in findings))

    def test_test_file_context_classification(self):
        content = "API_KEY = 'AIzaSyB3q7_k9Xm2Lp0r8StVuWz1Y234567890'"
        findings = self.engine.scan_file("tests/test_api.py", content, self.context)

        self.assertEqual(len(findings), 1)
        # Severity downgraded for test directory
        self.assertIn(findings[0].severity, (Severity.MEDIUM, Severity.LOW))


if __name__ == "__main__":
    unittest.main()
