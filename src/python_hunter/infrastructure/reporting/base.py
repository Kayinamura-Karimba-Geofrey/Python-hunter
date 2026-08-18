"""Abstract Base Reporter and Reporter Registry Architecture."""

from abc import ABC, abstractmethod
from typing import Any, Type

from python_hunter.domain.reporting.models import SecurityReport


class BaseReporter(ABC):
    """Abstract interface for security report generation."""

    @abstractmethod
    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport instance into formatted string report."""
        pass


class ReporterRegistry:
    """Registry managing available report formatters."""

    _reporters: dict[str, Type[BaseReporter]] = {}

    @classmethod
    def register(cls, format_name: str, reporter_cls: Type[BaseReporter]) -> None:
        """Register a reporter class for a format name."""
        cls._reporters[format_name.lower()] = reporter_cls

    @classmethod
    def get(cls, format_name: str) -> BaseReporter:
        """Instantiate and return reporter for given format name."""
        fmt = format_name.lower()
        if fmt not in cls._reporters:
            raise ValueError(f"Unsupported report format: '{format_name}'. Supported formats: {list(cls._reporters.keys())}")
        return cls._reporters[fmt]()

    @classmethod
    def list_formats(cls) -> list[str]:
        """List registered report formats."""
        return list(cls._reporters.keys())
