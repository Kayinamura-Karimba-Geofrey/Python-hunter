"""PythonLanguageAdapter Implementation."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import IRFunction, IRLocation, SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class PythonLanguageAdapter(LanguageAdapter):
    """Python language adapter delegating to Python Hunter AST and security engines."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.TAINT,
                AnalyzerCapability.DEPENDENCY_ANALYSIS,
                AnalyzerCapability.FRAMEWORK_ANALYSIS,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.PYTHON,
            display_name="Python",
            aliases=["py", "python"],
            file_extensions=[".py", ".pyw"],
            parser="PythonASTParser",
            analyzer="PythonSecurityAnalyzer",
            framework_adapters=["Django", "Flask", "FastAPI"],
            dependency_ecosystem="PyPI",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith((".py", ".pyw"))
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".py") or f in ("requirements.txt", "pyproject.toml", "setup.py") for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            res = ParserProvider.parse_python(code, file_path)
            return {"file_path": file_path, "ast": res.ast, "is_partial": res.is_partial}
        except Exception:
            return {"file_path": file_path, "ast": None, "is_partial": True}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".py"):
                    full_path = os.path.join(root, file_name)
                    findings.extend(self._analyze_file(full_path))
        return findings

    def _analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                if "os.system(" in line or "subprocess.call(" in line:
                    if not line.strip().startswith("#"):
                        findings.append({
                            "rule_id": "PYH-PY-001",
                            "title": "Python OS Command Invocation",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.0,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Avoid subprocess shell execution.",
                            "language": "python",
                            "framework": "Python Core",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        return SecurityIR(language=Language.PYTHON)
