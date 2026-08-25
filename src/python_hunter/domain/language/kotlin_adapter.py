"""Kotlin Language Adapter."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata


class KotlinLanguageAdapter(LanguageAdapter):
    """Kotlin language adapter for Android & Spring Kotlin security scanning."""

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
            language=Language.KOTLIN,
            display_name="Kotlin",
            aliases=["kotlin", "kt", "kts"],
            file_extensions=[".kt", ".kts"],
            parser="KotlinGenericParser",
            analyzer="KotlinSecurityAnalyzer",
            framework_adapters=["Android", "Spring Boot Kotlin"],
            dependency_ecosystem="gradle",
            capabilities=caps,
            version="1.0.0"
        )

    @property
    def language(self) -> Language:
        return Language.KOTLIN

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith((".kt", ".kts"))
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".kt", ".kts")) for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        return {"type": "KotlinAST", "file_path": file_path}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith((".kt", ".kts")):
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

                if "rawQuery(" in clean or "execSQL(" in clean:
                    if "$" in clean or "+" in clean:
                        findings.append({
                            "rule_id": "PYH-KT-001",
                            "title": "Kotlin / Android SQL Injection",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": clean,
                            "cwe": "CWE-89",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Use selectionArgs with rawQuery or Room DAO query parameters.",
                            "language": "kotlin",
                            "framework": "Android"
                        })
                elif "loadUrl(\"javascript:" in clean or "setJavaScriptEnabled(true)" in clean:
                    findings.append({
                        "rule_id": "PYH-KT-002",
                        "title": "Kotlin Android Insecure WebView JavaScript Execution",
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": clean,
                        "cwe": "CWE-79",
                        "owasp": "A03:2021-Injection",
                        "remediation": "Disable JavaScript in WebViews unless explicitly required.",
                        "language": "kotlin",
                        "framework": "Android"
                    })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        return SecurityIR(language=Language.KOTLIN)
