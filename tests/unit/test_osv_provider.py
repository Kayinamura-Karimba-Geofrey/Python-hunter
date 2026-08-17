"""Unit Tests for OSV Vulnerability Provider & Cache."""

import unittest
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.vulnerabilities.models import (
    AffectedRange,
    PackageIdentity,
    Vulnerability,
)
from python_hunter.infrastructure.vulnerabilities.providers.cache import CachedVulnerabilityProvider
from python_hunter.infrastructure.vulnerabilities.providers.fake import FakeVulnerabilityProvider
from python_hunter.infrastructure.vulnerabilities.providers.osv import OSVProvider


class TestOSVProviderAndCache(unittest.TestCase):
    """Test suite for OSV response parsing and caching functionality."""

    def test_osv_record_parsing(self) -> None:
        provider = OSVProvider()
        raw_osv = {
            "id": "GHSA-c5vv-522r-2679",
            "summary": "Urllib3 header injection",
            "details": "Urllib3 vulnerability details",
            "aliases": ["CVE-2021-33503"],
            "published": "2021-06-04T19:28:44Z",
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.26.5"}],
                        }
                    ],
                }
            ],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        }

        vuln = provider._parse_osv_record(raw_osv, "urllib3")
        self.assertEqual(vuln.id, "GHSA-c5vv-522r-2679")
        self.assertEqual(vuln.aliases, ["CVE-2021-33503"])
        self.assertEqual(vuln.fixed_versions, ["1.26.5"])
        self.assertEqual(vuln.severity, Severity.HIGH)

    def test_fake_provider_query(self) -> None:
        fake = FakeVulnerabilityProvider()
        fake.add_vulnerability(
            "requests",
            Vulnerability(
                id="CVE-2023-0001",
                summary="Fake Vulnerability",
                affected_package="requests",
                affected_ranges=[
                    AffectedRange(
                        range_type="ECOSYSTEM",
                        events=[{"introduced": "2.0.0"}, {"fixed": "2.20.0"}],
                    )
                ],
                fixed_versions=["2.20.0"],
            ),
        )

        pkg = PackageIdentity(ecosystem="PyPI", name="requests")
        vulns = fake.query(pkg, "2.19.0")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].id, "CVE-2023-0001")

    def test_cached_provider_offline_mode(self) -> None:
        fake = FakeVulnerabilityProvider()
        cached = CachedVulnerabilityProvider(fake, cache_dir="/tmp/test_pyh_cache", offline=True)

        pkg = PackageIdentity(ecosystem="PyPI", name="requests")
        vulns = cached.query(pkg, "2.19.0")
        self.assertEqual(vulns, [])
        self.assertEqual(cached.status.value, "OFFLINE")


if __name__ == "__main__":
    unittest.main()
