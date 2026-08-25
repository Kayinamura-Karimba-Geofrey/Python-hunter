"""C# (CSharp) Language Adapter."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata


class CSharpLanguageAdapter(LanguageAdapter):
    """C# (.NET) language adapter for enterprise SAST scanning."""

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
            language=Language.CSHARP,
            display_name="C#",
            aliases=["csharp", "cs", ".net"],
            file_extensions=[".cs"],
            parser="RoslynGenericParser",
            analyzer="CSharpSecurityAnalyzer",
            framework_adapters=["ASP.NET Core", ".NET MVC"],
            dependency_ecosystem="nuget",
            capabilities=caps,
            version="1.0.0"
        )

    @property
    def language(self) -> Language:
        return Language.CSHARP

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith(".cs")
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".cs") or f.endswith(".csproj") or f.endswith(".sln") for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        return {"type": "CSharpAST", "file_path": file_path}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".cs"):
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

                if "SqlCommand(" in clean or "ExecuteSqlCommand(" in clean:
                    if "+" in clean or "String.Format(" in clean or "$" in clean:
                        findings.append({
                            "rule_id": "PYH-CS-001",
                            "title": "C# SQL Injection via String Concatenation",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": clean,
                            "cwe": "CWE-89",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Use parameterized SqlCommand queries.",
                            "language": "csharp",
                            "framework": "ASP.NET Core"
                        })
                elif "Process.Start(" in clean:
                    findings.append({
                        "rule_id": "PYH-CS-002",
                        "title": "C# Command Execution via Process.Start",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": clean,
                        "cwe": "CWE-78",
                        "owasp": "A03:2021-Injection",
                        "remediation": "Validate command arguments before launching processes.",
                        "language": "csharp",
                        "framework": ".NET"
                    })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        return SecurityIR(language=Language.CSHARP)
