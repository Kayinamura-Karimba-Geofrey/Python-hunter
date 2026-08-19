"""Framework Registry discovering and managing Python and JS/TS framework adapters."""

from python_hunter.domain.frameworks.framework_adapter import FrameworkAdapter
from python_hunter.domain.frameworks.framework_models import ApplicationModel
from python_hunter.domain.frameworks.jsts_frameworks import ExpressFrameworkAdapter
from python_hunter.domain.frameworks.python_frameworks import FastAPIFrameworkAdapter, FlaskFrameworkAdapter


class FrameworkRegistry:
    """Registry managing framework adapters for discovery and capability negotiation."""

    def __init__(self) -> None:
        self._adapters: dict[str, FrameworkAdapter] = {}
        self.register_adapter(FlaskFrameworkAdapter())
        self.register_adapter(FastAPIFrameworkAdapter())
        self.register_adapter(ExpressFrameworkAdapter())

    def register_adapter(self, adapter: FrameworkAdapter) -> None:
        self._adapters[adapter.framework_id] = adapter

    def get_adapter(self, framework_id: str) -> FrameworkAdapter | None:
        return self._adapters.get(framework_id)

    def detect_all(self, workspace_path: str) -> list[ApplicationModel]:
        models = []
        for adapter in self._adapters.values():
            model = adapter.detect_and_enrich(workspace_path)
            if model:
                models.append(model)
        return models
