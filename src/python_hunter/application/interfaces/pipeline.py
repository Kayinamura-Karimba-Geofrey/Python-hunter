"""Application Pipeline Contracts."""

from abc import ABC, abstractmethod
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.analysis.result import AnalysisResult


class PipelineStage(ABC):
    """Abstract stage in the analysis execution pipeline."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the pipeline stage."""

    @abstractmethod
    def execute(self, context: AnalysisContext) -> AnalysisResult:
        """Execute pipeline stage logic on the given context."""


class PipelineContract(ABC):
    """Contract for managing and orchestrating sequential or parallel pipeline stages."""

    @abstractmethod
    def register_stage(self, stage: PipelineStage) -> None:
        """Register a new pipeline stage."""

    @abstractmethod
    def run(self, context: AnalysisContext) -> list[AnalysisResult]:
        """Execute registered pipeline stages against the context."""
