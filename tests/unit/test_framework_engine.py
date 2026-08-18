"""Unit and Integration Tests for Framework Security Intelligence Engine (Step 13)."""

import os
import unittest

from python_hunter.application.use_cases.analyze_ast import AnalyzeASTUseCase
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.frameworks.detector import FrameworkDetector
from python_hunter.domain.frameworks.models import FrameworkType

FRAMEWORKS_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "frameworks"))


class TestFrameworkSecurityIntelligence(unittest.TestCase):
    """Test suite verifying Framework Detection, Adapters, Entry Points, and Taint Integration."""

    def setUp(self) -> None:
        self.ast_use_case = AnalyzeASTUseCase()
        self.detector = FrameworkDetector()

    def test_flask_framework_detection_and_rules(self) -> None:
        flask_file = os.path.join(FRAMEWORKS_FIXTURES_DIR, "flask_app.py")
        ast_summary = self.ast_use_case.execute(flask_file)

        profile = self.detector.analyze(ast_summary.documents)
        self.assertIn(FrameworkType.FLASK, profile.detected_frameworks)
        self.assertEqual(profile.detected_frameworks[FrameworkType.FLASK], Confidence.HIGH)

        sec_use_case = AnalyzeSecurityUseCase()
        findings, _, _ = sec_use_case.execute(flask_file)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-FLASK-001", rule_ids)
        self.assertIn("PYH-FLASK-002", rule_ids)

    def test_fastapi_framework_detection_and_rules(self) -> None:
        fastapi_file = os.path.join(FRAMEWORKS_FIXTURES_DIR, "fastapi_app.py")
        ast_summary = self.ast_use_case.execute(fastapi_file)

        profile = self.detector.analyze(ast_summary.documents)
        self.assertIn(FrameworkType.FASTAPI, profile.detected_frameworks)

        sec_use_case = AnalyzeSecurityUseCase()
        findings, _, _ = sec_use_case.execute(fastapi_file)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-FASTAPI-001", rule_ids)

    def test_django_framework_detection_and_rules(self) -> None:
        django_file = os.path.join(FRAMEWORKS_FIXTURES_DIR, "django_app.py")
        ast_summary = self.ast_use_case.execute(django_file)

        profile = self.detector.analyze(ast_summary.documents)
        self.assertIn(FrameworkType.DJANGO, profile.detected_frameworks)

        sec_use_case = AnalyzeSecurityUseCase()
        findings, _, _ = sec_use_case.execute(django_file)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PYH-DJANGO-001", rule_ids)
        self.assertIn("PYH-DJANGO-002", rule_ids)
        self.assertIn("PYH-JWT-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
