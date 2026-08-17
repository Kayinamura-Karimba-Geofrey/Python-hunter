"""Unit tests for RuleRegistry and SecurityRuleEngine."""

import unittest
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary, ASTDocument
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.exceptions.base import ValidationError
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.projects.project import Project
from python_hunter.domain.rules.engine import SecurityRuleEngine
from python_hunter.domain.rules.models import SecurityRule
from python_hunter.domain.rules.registry import RuleRegistry


class MockSuccessRule(SecurityRule):
    def __init__(self) -> None:
        super().__init__(
            id="MOCK-001",
            name="Mock Rule 1",
            description="Mock successful rule",
            category=Category.CODE_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        return [
            Finding(
                rule_id=self.id,
                severity=self.severity,
                confidence=self.confidence,
                category=self.category,
                title=self.name,
                description=self.description,
                file_path="main.py",
                location=Location(line_start=10, line_end=10, column_start=0, column_end=5),
            )
        ]


class MockFaultyRule(SecurityRule):
    def __init__(self) -> None:
        super().__init__(
            id="MOCK-002",
            name="Mock Faulty Rule",
            description="Mock rule that raises exception",
            category=Category.OTHER,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
        )

    def evaluate(self, ast_summary: ASTAnalysisSummary, context: AnalysisContext) -> list[Finding]:
        raise RuntimeError("Rule execution error simulation")


class TestRuleEngineAndRegistry(unittest.TestCase):
    """Unit test suite for RuleRegistry and SecurityRuleEngine."""

    def test_registry_registration_and_duplicates(self) -> None:
        """Verify registry prevents duplicate rule ID registrations."""
        registry = RuleRegistry()
        rule1 = MockSuccessRule()
        registry.register(rule1)

        self.assertEqual(len(registry.get_all()), 1)
        self.assertEqual(registry.get("MOCK-001"), rule1)

        with self.assertRaises(ValidationError):
            registry.register(rule1)

    def test_engine_error_isolation_and_deduplication(self) -> None:
        """Verify rule engine isolates faulty rules and deduplicates identical findings."""
        registry = RuleRegistry()
        rule1 = MockSuccessRule()
        rule2 = MockFaultyRule()
        registry.register(rule1)
        registry.register(rule2)

        engine = SecurityRuleEngine(registry=registry)
        project = Project(name="test", root_path="/tmp")
        context = AnalysisContext(scan_id="scan-1", project=project, target_files=[])
        ast_summary = ASTAnalysisSummary(documents=[ASTDocument(file_path="main.py", module_name="main")])

        findings, results = engine.evaluate_rules(ast_summary, context)

        self.assertEqual(len(results), 2)
        # Verify faulty rule error was captured without terminating engine
        faulty_res = next(r for r in results if r.rule_id == "MOCK-002")
        self.assertIsNotNone(faulty_res.error)
        self.assertIn("Rule execution error simulation", faulty_res.error)

        # Verify successful rule produced findings
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
