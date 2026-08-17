"""Unit tests for individual secret detectors PYH-SECRET-001 through 010."""

import unittest

from python_hunter.detectors.secrets import (
    PYHSecret001GenericAPIKey,
    PYHSecret002GenericAccessToken,
    PYHSecret003PrivateKey,
    PYHSecret004JWT,
    PYHSecret005DatabaseURL,
    PYHSecret006AWSCredentials,
    PYHSecret007GitHubToken,
    PYHSecret008GenericPassword,
    PYHSecret009Dotenv,
    PYHSecret010HighEntropy,
)
from python_hunter.domain.analysis.context import AnalysisContext


from python_hunter.domain.projects.project import Project


class TestSecretDetectors(unittest.TestCase):
    """Test suite evaluating individual secret detector matching."""

    def setUp(self) -> None:
        project = Project(name="test", root_path="/tmp")
        self.context = AnalysisContext(scan_id="test-scan", project=project)

    def test_pyh_secret_001_api_key(self) -> None:
        detector = PYHSecret001GenericAPIKey()
        candidates = detector.detect('api_key = "ak_mock_99887766554433221100aabb"', "app.py", self.context)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].value, "ak_mock_99887766554433221100aabb")

    def test_pyh_secret_003_private_key(self) -> None:
        detector = PYHSecret003PrivateKey()
        candidates = detector.detect("-----BEGIN PRIVATE KEY-----", "key.pem", self.context)
        self.assertEqual(len(candidates), 1)

    def test_pyh_secret_004_jwt(self) -> None:
        detector = PYHSecret004JWT()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        candidates = detector.detect(f'token = "{jwt}"', "auth.py", self.context)
        self.assertEqual(len(candidates), 1)

    def test_pyh_secret_005_database_url(self) -> None:
        detector = PYHSecret005DatabaseURL()
        url = "postgres://user:secret_pass_123@localhost:5432/db"
        candidates = detector.detect(f'DB_URL = "{url}"', "config.py", self.context)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].value, "secret_pass_123")

    def test_pyh_secret_006_aws(self) -> None:
        detector = PYHSecret006AWSCredentials()
        candidates = detector.detect('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "aws.py", self.context)
        self.assertEqual(len(candidates), 1)

    def test_pyh_secret_007_github_token(self) -> None:
        detector = PYHSecret007GitHubToken()
        candidates = detector.detect('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"', "git.py", self.context)
        self.assertEqual(len(candidates), 1)

    def test_pyh_secret_009_dotenv(self) -> None:
        detector = PYHSecret009Dotenv()
        candidates = detector.detect("DB_SECRET_KEY=super_secret_env_value_123", ".env", self.context)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].value, "super_secret_env_value_123")


if __name__ == "__main__":
    unittest.main()
