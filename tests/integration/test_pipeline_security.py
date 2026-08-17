"""End-to-end integration test for full Security Analysis Pipeline."""

import os
import unittest
from python_hunter.application.use_cases.analyze_security import AnalyzeSecurityUseCase

RULES_FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "security_rules"))


class TestSecurityPipelineIntegration(unittest.TestCase):
    """Integration test verifying full pipeline execution from Discovery to Findings."""

    def test_full_security_analysis_pipeline(self) -> None:
        """Verify full security pipeline detects expected vulnerabilities in integration_project fixture."""
        target = os.path.join(RULES_FIXTURES_DIR, "integration_project")
        use_case = AnalyzeSecurityUseCase()

        findings, ast_summary, rule_results = use_case.execute(target)

        self.assertGreaterEqual(ast_summary.files_analyzed, 1)
        self.assertGreaterEqual(len(rule_results), 10)
        self.assertGreaterEqual(len(findings), 4)

        # Check detected rule IDs
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PYH-AST-004", rule_ids)  # os.system
        self.assertIn("PYH-AST-005", rule_ids)  # subprocess shell=True
        self.assertIn("PYH-AST-006", rule_ids)  # pickle.loads
        self.assertIn("PYH-AST-007", rule_ids)  # yaml.load
        self.assertIn("PYH-AST-009", rule_ids)  # SECRET_KEY


if __name__ == "__main__":
    unittest.main()
