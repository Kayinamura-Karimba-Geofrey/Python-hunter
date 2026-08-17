"""Lightweight Dependency Injection Container."""

from typing import Any
from python_hunter.domain.analysis.base import Analyzer
from python_hunter.infrastructure.config.settings import Settings
from python_hunter.infrastructure.observability.logging import Logger, get_logger


class Container:
    """Lightweight application dependency container."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.load_from_env()
        self._logger = get_logger("python_hunter", level=self._settings.log.level, format_type=self._settings.log.format)
        self._analyzers: dict[str, Analyzer] = {}

    @property
    def settings(self) -> Settings:
        """Access application settings."""
        return self._settings

    @property
    def logger(self) -> Logger:
        """Access application logger."""
        return self._logger

    def register_analyzer(self, analyzer: Analyzer) -> None:
        """Register an analyzer instance into the container."""
        self._analyzers[analyzer.name] = analyzer

    def get_analyzer(self, name: str) -> Analyzer | None:
        """Retrieve a registered analyzer by name."""
        return self._analyzers.get(name)

    def list_analyzers(self) -> list[str]:
        """List all registered analyzer names."""
        return list(self._analyzers.keys())
