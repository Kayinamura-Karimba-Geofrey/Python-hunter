"""End-to-End Test Suite for Step 40 Security Intelligence Platform."""

import unittest
from datetime import datetime, timezone

from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.intelligence.alias_graph import VulnerabilityAliasGraph
from python_hunter.domain.intelligence.engine import SecurityIntelligenceEngine
from python_hunter.domain.intelligence.models import (
    CVSSData,
    EPSSData,
    FactOrigin,
    PackageIdentity,
    SourceTrustLevel,
    VulnerabilityRecord,
)
from python_hunter.domain.intelligence.remediation import RemediationItem
from python_hunter.domain.intelligence.version_range import VersionRangeEngine
from python_hunter.infrastructure.intelligence.db import LocalIntelligenceDatabase, OSVIntelligenceSource


class TestSecurityIntelligencePlatformE2E(unittest.TestCase):
    """End-to-end tests validating the Security Intelligence Engine."""

    def setUp(self) -> None:
        self.app_service = SecurityApplicationService()

    def test_e2e_intelligence_ingestion_and_correlation(self) -> None:
        """Test ingesting vulnerabilities and correlating with repository dependencies."""
        recs = self.app_service.intel_engine.ingest_intelligence()
        self.assertGreater(len(recs), 0)

        # Correlate against a vulnerable dependency (requests 2.28.0)
        matches = self.app_service.intel_engine.correlate_with_repository(
            repo_name="kayinamura-karimba-geofrey/python-hunter",
            dependencies=[
                {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"},
                {"name": "flask", "version": "2.0.0", "ecosystem": "PyPI"},
            ],
        )

        self.assertGreaterEqual(len(matches), 2)
        vuln_ids = [m["vulnerability_id"] for m in matches]
        self.assertIn("CVE-2023-32681", vuln_ids)
        self.assertIn("CVE-2023-30861", vuln_ids)

    def test_e2e_reassessment_on_intelligence_change(self) -> None:
        """Test automatic reassessment when a vulnerability record changes."""
        # Initial scan correlation
        active_repos = {
            "my-microservice": [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]
        }
        self.app_service.intel_engine.correlate_with_repository(
            "my-microservice", active_repos["my-microservice"]
        )

        # Reassess on vulnerability change
        reassessed = self.app_service.intel_engine.reassess_impact_on_change("CVE-2023-32681", active_repos)
        self.assertEqual(len(reassessed), 1)
        self.assertEqual(reassessed[0]["repository"], "my-microservice")

    def test_e2e_remediation_queue_ranking_and_sla(self) -> None:
        """Test remediation queue prioritization and SLA calculations."""
        item1 = RemediationItem(
            id="rem-101",
            vulnerability_id="CVE-2023-30861",
            repository="auth-service",
            severity=Severity.CRITICAL,
            risk_score=9.8,
            is_reachable=True,
            is_verified=True,
            epss_score=0.75,
        )
        item2 = RemediationItem(
            id="rem-102",
            vulnerability_id="CVE-2023-32681",
            repository="auth-service",
            severity=Severity.HIGH,
            risk_score=7.5,
            is_reachable=False,
            is_verified=False,
            epss_score=0.15,
        )

        self.app_service.remediation_queue.add_item(item1)
        self.app_service.remediation_queue.add_item(item2)

        queue = self.app_service.remediation_queue.get_ranked_queue()
        self.assertEqual(queue[0].id, "rem-101")
        self.assertGreater(queue[0].rank_score, queue[1].rank_score)

    def test_e2e_security_posture_and_reporting(self) -> None:
        """Test Security Posture tracking, comparison, and report generation."""
        items = self.app_service.remediation_queue.get_ranked_queue()
        snap = self.app_service.posture_tracker.capture_posture(items, attack_paths_count=1)

        exec_summary = self.app_service.posture_tracker.generate_executive_summary(snap)
        tech_summary = self.app_service.posture_tracker.generate_technical_summary(snap, items)

        self.assertIn("security_score", exec_summary)
        self.assertEqual(exec_summary["title"], "Executive Security Summary")
        self.assertEqual(tech_summary["title"], "Detailed Technical Security Intelligence Report")


if __name__ == "__main__":
    unittest.main()
