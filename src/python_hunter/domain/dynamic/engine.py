"""Dynamic Behavior Engine Core Implementation."""

from typing import Literal
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.dynamic.analyzers import (
    BaseDynamicAnalyzer,
    DecoratorAnalyzer,
    DeserializationAnalyzer,
    DynamicDispatchAnalyzer,
    DynamicImportAnalyzer,
    EvalExecAnalyzer,
    MetaclassAnalyzer,
    MonkeyPatchAnalyzer,
    PluginLoaderAnalyzer,
    ReflectionAnalyzer,
    RuntimeRegistrationAnalyzer,
)

from python_hunter.domain.dynamic.models import (
    DynamicBehavior,
    DynamicBehaviorSummary,
    DynamicBehaviorType,
    ResolutionState,
)


AnalysisMode = Literal["conservative", "balanced", "aggressive"]


class DynamicBehaviorEngine:
    """Orchestrates static analysis of dynamic Python behaviors."""

    def __init__(self, mode: AnalysisMode = "balanced") -> None:
        self.mode = mode
        self.analyzers: list[BaseDynamicAnalyzer] = [
            ReflectionAnalyzer(),
            DynamicImportAnalyzer(),
            EvalExecAnalyzer(),
            DeserializationAnalyzer(),
            DecoratorAnalyzer(),
            MetaclassAnalyzer(),
            MonkeyPatchAnalyzer(),
            DynamicDispatchAnalyzer(),
            PluginLoaderAnalyzer(),
            RuntimeRegistrationAnalyzer(),
        ]

    def analyze(self, documents: list[ASTDocument]) -> tuple[list[DynamicBehavior], DynamicBehaviorSummary]:
        """Analyze documents for dynamic behaviors without executing code."""
        all_behaviors: list[DynamicBehavior] = []
        for analyzer in self.analyzers:
            behaviors = analyzer.analyze(documents)
            all_behaviors.extend(behaviors)

        # Filter behaviors based on analysis mode
        if self.mode == "conservative":
            filtered_behaviors = [
                b for b in all_behaviors if b.resolution_state in (ResolutionState.EXACT, ResolutionState.HIGH_CONFIDENCE)
            ]
        else:
            filtered_behaviors = all_behaviors

        summary = self._summarize(filtered_behaviors)
        return filtered_behaviors, summary

    def _summarize(self, behaviors: list[DynamicBehavior]) -> DynamicBehaviorSummary:
        summary = DynamicBehaviorSummary(total_behaviors=len(behaviors))
        by_res: dict[str, int] = {}

        for b in behaviors:
            by_res[b.resolution_state.value] = by_res.get(b.resolution_state.value, 0) + 1
            if b.behavior_type == DynamicBehaviorType.REFLECTION:
                summary.reflection_count += 1
            elif b.behavior_type == DynamicBehaviorType.DYNAMIC_IMPORT:
                summary.dynamic_import_count += 1
            elif b.behavior_type == DynamicBehaviorType.DYNAMIC_EXECUTION:
                summary.dynamic_execution_count += 1
            elif b.behavior_type == DynamicBehaviorType.DESERIALIZATION:
                summary.unsafe_deserialization_count += 1
            elif b.behavior_type == DynamicBehaviorType.DYNAMIC_DISPATCH:
                summary.dynamic_dispatch_count += 1
            elif b.behavior_type == DynamicBehaviorType.DECORATOR:
                summary.decorator_count += 1
            elif b.behavior_type == DynamicBehaviorType.METACLASS:
                summary.metaclass_count += 1
            elif b.behavior_type == DynamicBehaviorType.MONKEY_PATCH:
                summary.monkey_patch_count += 1
            elif b.behavior_type == DynamicBehaviorType.PLUGIN_LOADING:
                summary.plugin_loading_count += 1
            elif b.behavior_type == DynamicBehaviorType.RUNTIME_REGISTRATION:
                summary.runtime_registration_count += 1

            if b.resolution_state == ResolutionState.UNKNOWN:
                summary.unresolved_calls_count += 1

        summary.by_resolution_state = by_res
        return summary

