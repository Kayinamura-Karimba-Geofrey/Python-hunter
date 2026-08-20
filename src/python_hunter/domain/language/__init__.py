"""Language Package Initialization with lazy adapter loading."""

from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities

__all__ = [
    "Language",
    "AnalyzerCapability",
    "LanguageCapabilities",
    "LanguageAdapter",
    "PythonLanguageAdapter",
    "LanguageRegistry",
]


def __getattr__(name: str):
    if name == "LanguageAdapter":
        from python_hunter.domain.language.adapter import LanguageAdapter
        return LanguageAdapter
    if name == "PythonLanguageAdapter":
        from python_hunter.domain.language.python_adapter import PythonLanguageAdapter
        return PythonLanguageAdapter
    if name == "LanguageRegistry":
        from python_hunter.domain.language.registry import LanguageRegistry
        return LanguageRegistry
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
