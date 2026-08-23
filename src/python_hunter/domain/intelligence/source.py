"""Intelligence Source interfaces and Registry."""

from abc import ABC, abstractmethod
from typing import Any

from python_hunter.domain.intelligence.models import (
    IntelligenceFreshness,
    IntelligenceFreshnessState,
    SourceTrustLevel,
    VulnerabilityRecord,
)


class IntelligenceSource(ABC):
    """Abstract interface for external/offline security intelligence sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the intelligence source (e.g. NVD, GHSA, OSV, EPSS)."""
        pass

    @property
    @abstractmethod
    def trust_level(self) -> SourceTrustLevel:
        """Source trust priority level."""
        pass

    @abstractmethod
    def fetch_records(self, ecosystem: str | None = None) -> list[VulnerabilityRecord]:
        """Fetch or load vulnerability records from source."""
        pass

    @abstractmethod
    def get_freshness(self) -> IntelligenceFreshness:
        """Check freshness metadata for this source."""
        pass


class IntelligenceSourceRegistry:
    """Registry for managing and orchestrating active intelligence sources."""

    def __init__(self) -> None:
        self._sources: dict[str, IntelligenceSource] = {}
        self._enabled: dict[str, bool] = {}

    def register(self, source: IntelligenceSource, enabled: bool = True) -> None:
        """Register a new intelligence source."""
        self._sources[source.name] = source
        self._enabled[source.name] = enabled

    def enable(self, name: str) -> None:
        """Enable source by name."""
        if name in self._sources:
            self._enabled[name] = True

    def disable(self, name: str) -> None:
        """Disable source by name."""
        if name in self._sources:
            self._enabled[name] = False

    def get_active_sources(self) -> list[IntelligenceSource]:
        """Return list of currently enabled sources."""
        return [src for name, src in self._sources.items() if self._enabled.get(name, False)]

    def refresh_all(self, ecosystem: str | None = None) -> list[VulnerabilityRecord]:
        """Fetch records from all active intelligence sources."""
        all_records = []
        for src in self.get_active_sources():
            try:
                recs = src.fetch_records(ecosystem=ecosystem)
                all_records.extend(recs)
            except Exception:
                # Failure handling: continue using other sources
                pass
        return all_records

    def status(self) -> dict[str, dict[str, Any]]:
        """Return operational status and freshness of all registered sources."""
        res = {}
        for name, src in self._sources.items():
            enabled = self._enabled.get(name, False)
            try:
                freshness = src.get_freshness()
                f_state = freshness.freshness.value
                ver = freshness.version
            except Exception:
                f_state = IntelligenceFreshnessState.UNAVAILABLE.value
                ver = "unknown"

            res[name] = {
                "enabled": enabled,
                "trust_level": src.trust_level.name,
                "freshness": f_state,
                "version": ver,
            }
        return res
