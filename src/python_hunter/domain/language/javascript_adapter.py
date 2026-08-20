"""JavaScript and TypeScript Language Adapters."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.javascript.parser import JSIRConverter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class JavaScriptLanguageAdapter(LanguageAdapter):
    """JavaScript language adapter integrating with Universal SecurityIR and security analysis engines."""

    def __init__(self) -> None:
        self.converter = JSIRConverter()
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
            language=Language.JAVASCRIPT,
            display_name="JavaScript",
            aliases=["js", "javascript"],
            file_extensions=[".js", ".jsx", ".mjs", ".cjs"],
            parser="JSBabelParser",
            analyzer="JSSecurityAnalyzer",
            framework_adapters=["Express", "Next.js", "React"],
            dependency_ecosystem="npm",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith((".js", ".jsx", ".mjs", ".cjs"))
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".js", ".jsx", ".mjs")) or f == "package.json" for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            return ParserProvider.parse_generic_structural(code, file_path, "javascript").ast
        except Exception:
            return {"type": "JSAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith((".js", ".jsx", ".mjs")):
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
                if "eval(" in line or "child_process.exec(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-JS-001",
                            "title": "JavaScript Code Execution / Eval",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.1,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-95",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Avoid dynamic code evaluation.",
                            "language": "javascript",
                            "framework": "Express",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        combined_ir = SecurityIR(language=Language.JAVASCRIPT)
        if not os.path.exists(workspace_path):
            return combined_ir

        files_to_scan = []
        if os.path.isfile(workspace_path):
            files_to_scan.append(workspace_path)
        else:
            for root, _, files in os.walk(workspace_path):
                if any(ignored in root for ignored in ("node_modules", "dist", "build", ".next", "coverage")):
                    continue
                for file in files:
                    if file.endswith((".js", ".jsx", ".mjs", ".cjs")):
                        files_to_scan.append(os.path.join(root, file))

        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                file_ir = self.converter.convert(file_path, content, Language.JAVASCRIPT)
                combined_ir.functions.extend(file_ir.functions)
                combined_ir.symbols.extend(file_ir.symbols)
                combined_ir.calls.extend(file_ir.calls)
                combined_ir.dataflow_edges.extend(file_ir.dataflow_edges)
            except Exception:
                pass

        return combined_ir


class TypeScriptLanguageAdapter(JavaScriptLanguageAdapter):
    """TypeScript language adapter building upon JavaScript language capabilities."""

    def __init__(self) -> None:
        super().__init__()
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.TAINT,
                AnalyzerCapability.TYPE_ANALYSIS,
                AnalyzerCapability.DEPENDENCY_ANALYSIS,
                AnalyzerCapability.FRAMEWORK_ANALYSIS,
            }
        )
        self._ts_metadata = LanguageMetadata(
            language=Language.TYPESCRIPT,
            display_name="TypeScript",
            aliases=["ts", "typescript", "tsx"],
            file_extensions=[".ts", ".tsx"],
            parser="TSParser",
            analyzer="TSSecurityAnalyzer",
            framework_adapters=["NestJS", "Express", "Next.js", "React"],
            dependency_ecosystem="npm",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.TYPESCRIPT

    @property
    def metadata(self) -> LanguageMetadata:
        return self._ts_metadata

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        if os.path.isfile(workspace_path):
            return workspace_path.endswith((".ts", ".tsx"))
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".ts", ".tsx")) for f in files):
                return True
        return False
