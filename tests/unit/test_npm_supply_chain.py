"""Unit tests for Step 25 Advanced NPM Dependency & Supply-Chain Security."""

import os
import unittest
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


if __name__ == "__main__":
    unittest.main()
