"""PythonLanguageAdapter Implementation."""

from python_hunter.domain.ir.models import IRFunction, IRLocation, SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities


class PythonLanguageAdapter(LanguageAdapter):
    """Python language adapter delegating to Python Hunter AST and security engines."""

    @property
    def language(self) -> Language:
        return Language.PYTHON

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
        """Constructs SecurityIR for Python projects."""
        return SecurityIR(language=Language.PYTHON)


class PlaceholderJavaScriptLanguageAdapter(LanguageAdapter):
    """Placeholder adapter for JavaScript (Step 24)."""

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def capabilities(self) -> LanguageCapabilities:
        return LanguageCapabilities(capabilities=set())

    def is_available(self) -> bool:
        return False

    def build_ir(self, workspace_path: str) -> SecurityIR:
        raise NotImplementedError("JavaScript security analysis is not yet available.")
