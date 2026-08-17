"""Unit Tests for VersionMatcher."""

import unittest
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.dependencies.models import Dependency
from python_hunter.domain.vulnerabilities.models import (
    AffectedRange,
    Vulnerability,
    VulnerabilityStatus,
)
from python_hunter.domain.vulnerabilities.version_matcher import VersionMatcher


class TestVersionMatcher(unittest.TestCase):
    """Test suite for version range evaluation logic against packaging specs."""

    def setUp(self) -> None:
        self.vuln = Vulnerability(
            id="CVE-2023-12345",
            summary="Test Vulnerability",
            affected_package="requests",
            affected_ranges=[
                AffectedRange(
                    range_type="ECOSYSTEM",
                    events=[{"introduced": "2.0.0"}, {"fixed": "2.25.0"}],
                )
            ],
            fixed_versions=["2.25.0"],
            severity=Severity.HIGH,
        )

    def test_affected_exact_version(self) -> None:
        dep = Dependency(name="requests", version="2.19.0", manifest_path="requirements.txt")
        match = VersionMatcher.evaluate(self.vuln, dep)
        self.assertEqual(match.status, VulnerabilityStatus.AFFECTED)
        self.assertEqual(match.recommended_fix, "2.25.0")
        self.assertTrue(match.constraint_compatible)

    def test_not_affected_exact_version(self) -> None:
        dep = Dependency(name="requests", version="2.26.0", manifest_path="requirements.txt")
        match = VersionMatcher.evaluate(self.vuln, dep)
        self.assertEqual(match.status, VulnerabilityStatus.NOT_AFFECTED)

    def test_potentially_affected_constraint_range(self) -> None:
        dep = Dependency(name="requests", version="", version_constraint=">=2.0.0,<3.0.0", manifest_path="requirements.txt")
        match = VersionMatcher.evaluate(self.vuln, dep)
        self.assertEqual(match.status, VulnerabilityStatus.POTENTIALLY_AFFECTED)

    def test_not_affected_constraint_range(self) -> None:
        dep = Dependency(name="requests", version="", version_constraint=">=3.0.0", manifest_path="requirements.txt")
        match = VersionMatcher.evaluate(self.vuln, dep)
        self.assertEqual(match.status, VulnerabilityStatus.NOT_AFFECTED)

    def test_unknown_version_handling(self) -> None:
        dep = Dependency(name="requests", version="", version_constraint="", manifest_path="requirements.txt")
        match = VersionMatcher.evaluate(self.vuln, dep)
        self.assertEqual(match.status, VulnerabilityStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
