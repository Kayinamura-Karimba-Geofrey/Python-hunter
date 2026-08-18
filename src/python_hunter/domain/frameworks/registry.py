"""Framework Adapter Registry."""

import threading
from typing import Type

from python_hunter.domain.frameworks.adapter import BaseFrameworkAdapter
from python_hunter.domain.frameworks.models import FrameworkType


class FrameworkRegistry:
    """Thread-safe global registry for Framework Adapters."""

    _adapters: dict[FrameworkType, BaseFrameworkAdapter] = {}
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def register(cls, adapter: BaseFrameworkAdapter) -> None:
        """Register a framework adapter instance."""
        with cls._lock:
            cls._adapters[adapter.framework_type] = adapter

    @classmethod
    def get(cls, framework_type: FrameworkType) -> BaseFrameworkAdapter | None:
        """Retrieve a registered adapter by framework type."""
        with cls._lock:
            return cls._adapters.get(framework_type)

    @classmethod
    def list_adapters(cls) -> list[BaseFrameworkAdapter]:
        """List all registered framework adapters."""
        with cls._lock:
            return list(cls._adapters.values())

    @classmethod
    def clear(cls) -> None:
        """Clear all registered adapters (for testing)."""
        with cls._lock:
            cls._adapters.clear()
