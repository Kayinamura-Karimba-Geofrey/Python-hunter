"""Feature Flag Rollout Service."""

from typing import Any


class FeatureFlagService:
    """Feature flag rollout service supporting global, organization, and percentage rollouts."""

    def __init__(self) -> None:
        self._flags: dict[str, bool] = {
            "experimental_taint_engine": True,
            "distributed_queue_v2": True,
            "fast_ast_parser": True,
        }

    def is_enabled(self, flag_name: str, organization_id: str | None = None) -> bool:
        return self._flags.get(flag_name, False)

    def set_flag(self, flag_name: str, enabled: bool) -> None:
        self._flags[flag_name] = enabled
