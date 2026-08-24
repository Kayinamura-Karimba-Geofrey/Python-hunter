"""LanguageAnalyzer base plugin interface and AnalyzerRegistry for multi-language execution."""

from abc import ABC, abstractmethod
from typing import Any

from python_hunter.domain.findings.finding import Finding


class LanguageAnalyzer(ABC):
    """Abstract Plugin Interface for Multi-Language Security Analyzers."""

    @property
    @abstractmethod
    def language_id(self) -> str:
        pass

    @abstractmethod
    def detect(self, project_path: str) -> bool:
        pass

    @abstractmethod
    def prepare(self, project_path: str) -> bool:
        pass

    @abstractmethod
    def analyze(self, project_path: str) -> list[Finding]:
        pass

    @abstractmethod
    def cleanup(self) -> None:
        pass


class AnalyzerRegistry:
    """Registry managing polyglot language analyzers."""

    def __init__(self) -> None:
        self._analyzers: dict[str, LanguageAnalyzer] = {}

    def register(self, analyzer: LanguageAnalyzer) -> None:
        self._analyzers[analyzer.language_id] = analyzer

    def get(self, language_id: str) -> LanguageAnalyzer | None:
        return self._analyzers.get(language_id)
