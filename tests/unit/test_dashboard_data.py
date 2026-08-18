"""Unit tests for Dashboard Data Services, Querying, and Filtering."""

import unittest

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.correlation.models import SecurityPosture
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.reporting.dashboard_services import (
    FindingQueryService,
    SecurityReportService,
    TrendService,
)
from python_hunter.domain.reporting.models import AnalysisMetadata, ScanMetadata


class TestDashboardDataServices(unittest.TestCase):
    """Test suite verifying FindingQueryService and TrendService contracts."""

    def setUp(self) -> None:
        self.f1 = Finding(
            rule_id="PYH-AST-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.CODE_SECURITY,
            title="Dangerous eval call",
            description="Use of eval",
            file_path="src/api/auth.py",
            location=None,
            risk_score=75.0,
        )
        self.f2 = Finding(
            rule_id="PYH-SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SECRET,
            title="AWS Secret",
            description="Exposed secret key",
            file_path="src/config.py",
            location=None,
            risk_score=95.0,
        )
        self.findings = [self.f1, self.f2]

    def test_query_filter_by_severity(self) -> None:
        filtered = FindingQueryService.filter_findings(self.findings, severity=Severity.CRITICAL)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].rule_id, "PYH-SEC-001")

    def test_query_filter_by_component(self) -> None:
        filtered = FindingQueryService.filter_findings(self.findings, component="auth")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].file_path, "src/api/auth.py")

    def test_sort_findings_by_risk(self) -> None:
        sorted_f = FindingQueryService.sort_findings(self.findings, sort_by="risk")
        self.assertEqual(sorted_f[0].risk_score, 95.0)

    def test_dashboard_snapshot_creation(self) -> None:
        report = SecurityReportService.create_report(
            findings=self.findings,
            attack_paths=[],
            posture=SecurityPosture(project_risk_score=85.0),
            scan_metadata=ScanMetadata(scan_id="s1", project_name="demo", project_path="."),
            analysis_metadata=AnalysisMetadata(python_version="3.11", operating_system="Linux"),
        )
        snapshot = TrendService.create_dashboard_snapshot(report)
        self.assertEqual(snapshot.summary["project_name"], "demo")
        self.assertEqual(snapshot.severity_distribution["CRITICAL"], 1)
        self.assertEqual(snapshot.severity_distribution["HIGH"], 1)


if __name__ == "__main__":
    unittest.main()
