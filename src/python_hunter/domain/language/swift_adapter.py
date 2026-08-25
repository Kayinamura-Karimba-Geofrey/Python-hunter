"""Swift Language Adapter."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata


class SwiftLanguageAdapter(LanguageAdapter):
    """Swift language adapter for iOS & Apple ecosystem security scanning."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.DEPENDENCY_ANALYSIS,
                AnalyzerCapability.FRAMEWORK_ANALYSIS,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.SWIFT,
            display_name="Swift",
            aliases=["swift", "ios"],
            file_extensions=[".swift"],
            parser="SwiftGenericParser",
            analyzer="SwiftSecurityAnalyzer",
            framework_adapters=["iOS UIKit", "SwiftUI"],
            dependency_ecosystem="swiftpm",
            capabilities=caps,
            version="1.0.0"
        )

    @property
    def language(self) -> Language:
        return Language.SWIFT

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith(".swift")
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".swift") or f == "Package.swift" for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        return {"type": "SwiftAST", "file_path": file_path}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".swift"):
                    full_path = os.path.join(root, file_name)
                    findings.extend(self._analyze_file(full_path))
        return findings

    def _analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, line in enumerate(lines, 1):
                clean = line.strip()
                if clean.startswith("//"):
                    continue

                if "UserDefaults.standard.set(" in clean and any(kw in clean.lower() for kw in ["token", "password", "secret", "key"]):
                    findings.append({
                        "rule_id": "PYH-SW-001",
                        "title": "Insecure Sensitive Data Storage in UserDefaults",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": clean,
                        "cwe": "CWE-312",
                        "owasp": "A02:2021-Cryptographic Failures",
                        "remediation": "Store sensitive credentials and tokens in the iOS Keychain Services.",
                        "language": "swift",
                        "framework": "iOS UIKit"
                    })
                elif "allowsArbitraryLoads" in clean and "true" in clean:
                    findings.append({
                        "rule_id": "PYH-SW-002",
                        "title": "Insecure App Transport Security (ATS) Arbitrary Load",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": clean,
                        "cwe": "CWE-319",
                        "owasp": "A02:2021-Cryptographic Failures",
                        "remediation": "Enforce HTTPS ATS rules in Info.plist.",
                        "language": "swift",
                        "framework": "iOS Security"
                    })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        return SecurityIR(language=Language.SWIFT)
