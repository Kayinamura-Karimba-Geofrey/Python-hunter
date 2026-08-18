"""Domain Models for Dynamic Python Behavior Analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location


class DynamicBehaviorType(str, Enum):
    """Classification of static dynamic Python behaviors."""

    REFLECTION = "REFLECTION"
    DYNAMIC_IMPORT = "DYNAMIC_IMPORT"
    DYNAMIC_EXECUTION = "DYNAMIC_EXECUTION"
    DESERIALIZATION = "DESERIALIZATION"
    DYNAMIC_DISPATCH = "DYNAMIC_DISPATCH"
    DECORATOR = "DECORATOR"
    METACLASS = "METACLASS"
    MONKEY_PATCH = "MONKEY_PATCH"
    PLUGIN_LOADING = "PLUGIN_LOADING"
    RUNTIME_REGISTRATION = "RUNTIME_REGISTRATION"


class ResolutionState(str, Enum):
    """Static resolution certainty state of dynamic behavior."""

    EXACT = "EXACT"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class DynamicBehavior:
    """Discovered dynamic Python behavior entity."""

    behavior_type: DynamicBehaviorType
    file_path: str
    location: Location | None = None
    confidence: Confidence = Confidence.HIGH
    resolution_state: ResolutionState = ResolutionState.EXACT
    target: str | None = None
    source: str | None = None
    resolved_targets: list[str] = field(default_factory=list)
    unresolved_targets: list[str] = field(default_factory=list)
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DynamicBehaviorSummary:
    """Aggregated statistical summary of dynamic behaviors in project."""

    total_behaviors: int = 0
    reflection_count: int = 0
    dynamic_import_count: int = 0
    dynamic_execution_count: int = 0
    unsafe_deserialization_count: int = 0
    dynamic_dispatch_count: int = 0
    unresolved_calls_count: int = 0
    decorator_count: int = 0
    metaclass_count: int = 0
    monkey_patch_count: int = 0
    plugin_loading_count: int = 0
    by_resolution_state: dict[str, int] = field(default_factory=dict)
