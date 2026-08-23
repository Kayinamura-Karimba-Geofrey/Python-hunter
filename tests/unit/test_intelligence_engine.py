"""Unit tests for Step 40 Security Intelligence Engine (Unittest)."""

import unittest
from datetime import datetime, timezone

from python_hunter.domain.common.enums import Severity
from python_hunter.domain.intelligence.alias_graph import VulnerabilityAliasGraph
from python_hunter.domain.intelligence.engine import SecurityIntelligenceEngine
from python_hunter.domain.intelligence.impact import ImpactNode, IntelligenceImpactGraph
from python_hunter.domain.intelligence.knowledge_base import SecurityKnowledgeBase
from python_hunter.domain.intelligence.models import (
    CVSSData,
    EPSSData,
    FactOrigin,
    IntelligenceFreshnessState,
    PackageIdentity,
    SourceTrustLevel,
    VulnerabilityRecord,
)
from python_hunter.domain.intelligence.posture import SecurityPostureTracker
from python_hunter.domain.intelligence.remediation import RemediationItem, RemediationQueueManager, RemediationStatus
from python_hunter.domain.intelligence.source import IntelligenceSourceRegistry
from python_hunter.domain.intelligence.version_range import VersionRangeEngine
from python_hunter.infrastructure.intelligence.db import LocalIntelligenceDatabase, OSVIntelligenceSource


class TestIntelligenceEngineComponents(unittest.TestCase):

    def test_package_identity_normalization() -> None:
        pass

    def test_package_identity_normalization(self) -> None:
        pkg = PackageIdentity(ecosystem="PyPI", name="Requests_HTTP")
        self.assertEqual(pkg.normalized_name, "requests-http")

    def test_version_range_engine(self) -> None:
        engine = VersionRangeEngine()
        ranges = [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]

        self.assertTrue(engine.is_version_affected("2.30.0", ranges))
        self.assertFalse(engine.is_version_affected("2.31.0", ranges))
        self.assertEqual(engine.evaluate_status("2.31.0", ranges, fixed_versions=["2.31.0"]), "FIXED")
        self.assertEqual(engine.evaluate_status("2.28.0", ranges), "AFFECTED")

    def test_alias_graph_deduplication(self) -> None:
        graph = VulnerabilityAliasGraph()

        rec1 = VulnerabilityRecord(
            vulnerability_id="CVE-2023-32681",
            aliases=["GHSA-4v36-j8g8-hpj6"],
            title="Requests Leak",
            severity=Severity.HIGH,
            source="NVD",
            source_trust=SourceTrustLevel.OFFICIAL,
        )
        rec2 = VulnerabilityRecord(
            vulnerability_id="GHSA-4v36-j8g8-hpj6",
            aliases=["CVE-2023-32681"],
            title="Requests Leak Alternate",
            severity=Severity.HIGH,
            source="OSV",
            source_trust=SourceTrustLevel.HIGH,
        )

        canonical = graph.canonicalize_records([rec1, rec2])
        self.assertEqual(len(canonical), 1)
        self.assertEqual(canonical[0].vulnerability_id, "CVE-2023-32681")
        self.assertIn("GHSA-4v36-j8g8-hpj6", canonical[0].aliases)

    def test_remediation_queue_and_sla(self) -> None:
        manager = RemediationQueueManager()
        item1 = RemediationItem(
            id="rem-1",
            vulnerability_id="CVE-2023-1111",
            repository="repo-a",
            severity=Severity.CRITICAL,
            risk_score=9.0,
            is_reachable=True,
            is_verified=True,
            epss_score=0.8,
        )
        item2 = RemediationItem(
            id="rem-2",
            vulnerability_id="CVE-2023-2222",
            repository="repo-b",
            severity=Severity.LOW,
            risk_score=2.0,
            is_reachable=False,
            is_verified=False,
        )

        manager.add_item(item1)
        manager.add_item(item2)

        ranked = manager.get_ranked_queue()
        self.assertEqual(ranked[0].id, "rem-1")
        self.assertGreater(ranked[0].rank_score, ranked[1].rank_score)

    def test_intelligence_engine_flow(self) -> None:
        registry = IntelligenceSourceRegistry()
        registry.register(OSVIntelligenceSource())
        engine = SecurityIntelligenceEngine(registry=registry)

        records = engine.ingest_intelligence()
        self.assertGreater(len(records), 0)

        matches = engine.correlate_with_repository(
            repo_name="my-app",
            dependencies=[{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}],
        )
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["package"], "requests")

    def test_local_intelligence_db(self) -> None:
        db = LocalIntelligenceDatabase(":memory:")
        source = OSVIntelligenceSource()
        recs = source.fetch_records()
        db.save_records(recs)
        self.assertEqual(db.count(), len(recs))


if __name__ == "__main__":
    unittest.main()
