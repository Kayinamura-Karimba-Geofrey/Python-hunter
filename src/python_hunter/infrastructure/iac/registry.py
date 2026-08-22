"""Base infrastructure adapter interface and registry."""

from abc import ABC, abstractmethod
from typing import List, Optional
from python_hunter.domain.infrastructure.models import (
    InfrastructureIR,
    InfrastructureResource,
)


class InfrastructureAdapter(ABC):
    """Abstract base class for all Infrastructure-as-Code and CI/CD parsers and adapters."""

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Name of the infrastructure adapter."""
        pass

    @abstractmethod
    def detect(self, file_path: str, content: str) -> bool:
        """Determines if this adapter handles the given file."""
        pass

    @abstractmethod
    def parse_and_build_ir(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        """Parses the file content and populates the unified InfrastructureIR."""
        pass


class InfrastructureRegistry:
    """Central registry of infrastructure scanners and adapters."""

    def __init__(self) -> None:
        self._adapters: List[InfrastructureAdapter] = []

    def register_adapter(self, adapter: InfrastructureAdapter) -> None:
        self._adapters.append(adapter)

    def get_adapters(self) -> List[InfrastructureAdapter]:
        return list(self._adapters)

    def process_file(self, file_path: str, content: str, ir: InfrastructureIR) -> bool:
        handled = False
        for adapter in self._adapters:
            if adapter.detect(file_path, content):
                try:
                    adapter.parse_and_build_ir(file_path, content, ir)
                    handled = True
                except Exception as ex:
                    # Isolated failure handling
                    pass
        return handled
