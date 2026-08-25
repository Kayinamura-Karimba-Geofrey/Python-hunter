"""Unit tests for Step 48 Threat Intelligence & Security Research Platform."""

import unittest
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.threat_intel import (
    CisaKevAdapter, ExploitationStatus, IntelligenceSourceRegistry, NvdAdapter, ThreatIntelligenceEngine, ThreatPriority
)


class TestThreatIntelligenceEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = ThreatIntelligenceEngine()

    def test_sources_registration(self) -> None:
        sources = self.engine.registry.list_sources()
        self.assertGreaterEqual(len(sources), 2)
        source_ids = [s.source_id for s in sources]
        self.assertIn("cisa_kev", source_ids)
        self.assertIn("nvd_cve", source_ids)

    def test_sync_and_ingestion(self) -> None:
        result = self.engine.sync_all_sources()
        self.assertGreater(result["processed"], 0)
        self.assertGreater(len(self.engine.list_all_intelligence()), 0)

    def test_cisa_kev_lookup(self) -> None:
        kevs = self.engine.list_kev_vulnerabilities()
        self.assertGreater(len(kevs), 0)
        cve_ids = [k.cve_id for k in kevs]
        self.assertIn("CVE-2023-34362", cve_ids)

    def test_actively_exploited_lookup(self) -> None:
        exploited = self.engine.list_actively_exploited()
        self.assertGreater(len(exploited), 0)
        for e in exploited:
            self.assertEqual(e.exploitation_status, ExploitationStatus.ACTIVELY_EXPLOITED)

    def test_rescore_finding_with_kev(self) -> None:
        finding = Finding(
            rule_id="PYH-SCA-001",
            title="Vulnerable Dependency MOVEit",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.DEPENDENCY,
            description="MOVEit SQLi CVE-2023-34362",
            file_path="requirements.txt",
            location=None
        )

        setattr(finding, "cve_id", "CVE-2023-34362")

        rescore = self.engine.rescore_finding(finding, is_internet_facing=True, asset_criticality="CRITICAL")
        self.assertEqual(rescore["threat_priority"], ThreatPriority.CRITICAL.value)
        self.assertTrue(rescore["is_kev"])
        self.assertGreaterEqual(rescore["final_score"], 9.0)

    def test_threat_hunting_query(self) -> None:
        results = self.engine.threat_hunt("kev")
        self.assertGreater(len(results), 0)
        cves = [r["cve_id"] for r in results]
        self.assertIn("CVE-2023-34362", cves)


if __name__ == "__main__":
    unittest.main()
