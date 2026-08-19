"""JavaScript and TypeScript Language Adapters."""

import os
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.javascript.parser import JSIRConverter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities


class JavaScriptLanguageAdapter(LanguageAdapter):
    """JavaScript language adapter integrating with Universal SecurityIR and security analysis engines."""

    def __init__(self) -> None:
        self.converter = JSIRConverter()

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def capabilities(self) -> LanguageCapabilities:
        return LanguageCapabilities(
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

    def is_available(self) -> bool:
        return True

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

    @property
    def language(self) -> Language:
        return Language.TYPESCRIPT

    def build_ir(self, workspace_path: str) -> SecurityIR:
        combined_ir = SecurityIR(language=Language.TYPESCRIPT)
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
                    if file.endswith((".ts", ".tsx")):
                        files_to_scan.append(os.path.join(root, file))

        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                file_ir = self.converter.convert(file_path, content, Language.TYPESCRIPT)
                combined_ir.functions.extend(file_ir.functions)
                combined_ir.symbols.extend(file_ir.symbols)
                combined_ir.calls.extend(file_ir.calls)
                combined_ir.dataflow_edges.extend(file_ir.dataflow_edges)
            except Exception:
                pass

        return combined_ir
