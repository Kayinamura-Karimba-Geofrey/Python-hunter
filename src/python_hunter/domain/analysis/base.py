"""Analyzer Abstract Contract."""

from abc import ABC, abstractmethod
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.analysis.result import AnalysisResult
from python_hunter.domain.common.enums import Category


class Analyzer(ABC):
    """Abstract Base Class for all Python Hunter security analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier name for the analyzer."""

    @property
    @abstractmethod
    def category(self) -> Category:
        """Primary security category targeted by this analyzer."""

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """Execute static security analysis on the provided analysis context.
        
        Must return an AnalysisResult containing findings or caught non-fatal errors.
        """
