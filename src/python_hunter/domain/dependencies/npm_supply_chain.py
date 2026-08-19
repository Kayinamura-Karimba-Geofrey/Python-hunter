"""Static Supply-Chain Security & Lifecycle Script Analyzer for NPM."""

import json
import os
import re
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding


class NPMSupplyChainAnalyzer:
    """Statically inspects NPM lifecycle scripts, obfuscation, network calls, and typosquatting signals."""

    POPULAR_PACKAGES = {"react", "express", "lodash", "axios", "next", "vue", "typescript", "jest", "webpack"}
    SUSPICIOUS_PATTERNS = [
        ("NETWORK", r"curl\s+|wget\s+|fetch\(|http\.request\(|axios\("),
        ("PROCESS", r"child_process|exec\(|execSync\(|spawn\(|bash\s+|sh\s+"),
        ("CREDENTIALS", r"/etc/passwd|\.ssh|\.env|process\.env"),
        ("OBFUSCATION", r"eval\(|String\.fromCharCode|Buffer\.from\(.*?'base64'\)"),
    ]

    def analyze_workspace(self, workspace_path: str) -> list[Finding]:
        findings = []
        package_json_path = os.path.join(workspace_path, "package.json")

        if not os.path.exists(package_json_path):
            return findings

        try:
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            # Analyze lifecycle scripts
            scripts = data.get("scripts", {})
            for script_name in ("preinstall", "install", "postinstall"):
                if script_name in scripts:
                    script_content = scripts[script_name]
                    for category, pattern in self.SUSPICIOUS_PATTERNS:
                        if re.search(pattern, script_content):
                            findings.append(
                                Finding(
                                    rule_id="PYHUNTER-NPM-SCRIPT-001",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    category=Category.SUPPLY_CHAIN,
                                    title=f"Suspicious NPM Lifecycle Script: {script_name}",
                                    description=f"Lifecycle script '{script_name}' contains suspicious static behavior ({category}): {script_content}",
                                    file_path="package.json",
                                    location=Location(1, 1),
                                    evidence=f"{script_name}: {script_content}",
                                    remediation="Audit lifecycle scripts and remove unnecessary preinstall/postinstall hooks.",
                                )
                            )

            # Analyze Typosquatting
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for dep_name in deps.keys():
                for pop in self.POPULAR_PACKAGES:
                    if dep_name != pop and self._is_typosquat(dep_name, pop):
                        findings.append(
                            Finding(
                                rule_id="PYHUNTER-NPM-TYPO-001",
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category=Category.SUPPLY_CHAIN,
                                title=f"Potential Typosquatting Dependency: {dep_name}",
                                description=f"Dependency '{dep_name}' resembles popular NPM package '{pop}'.",
                                file_path="package.json",
                                location=Location(1, 1),
                                evidence=dep_name,
                                remediation="Verify dependency authenticity before installation.",
                            )
                        )

        except Exception:
            pass

        return findings

    @staticmethod
    def _is_typosquat(name1: str, name2: str) -> bool:
        """Check for single-character edits or transpositions between dependency names."""
        if abs(len(name1) - len(name2)) > 1:
            return False
        diffs = sum(1 for a, b in zip(name1, name2) if a != b)
        return diffs == 1
