"""Framework Detection Subsystem using Static AST Evidence."""

from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.frameworks.models import (
    FrameworkEvidence,
    FrameworkProfile,
    FrameworkType,
)
from python_hunter.domain.frameworks.registry import FrameworkRegistry


class FrameworkDetector:
    """Detects active Python frameworks based on static evidence and registered adapters."""

    def __init__(self) -> None:
        pass

    def analyze(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> FrameworkProfile:
        """Run framework detection across all documents and dependencies."""
        profile = FrameworkProfile()
        adapters = FrameworkRegistry.list_adapters()

        for adapter in adapters:
            evidences = adapter.detect(documents, dependencies)
            if not evidences:
                continue

            profile.evidences.extend(evidences)

            # Determine aggregate framework confidence
            highest_conf = Confidence.LOW
            for ev in evidences:
                if ev.confidence == Confidence.HIGH:
                    highest_conf = Confidence.HIGH
                    break
                elif ev.confidence == Confidence.MEDIUM and highest_conf != Confidence.HIGH:
                    highest_conf = Confidence.MEDIUM

            profile.detected_frameworks[adapter.framework_type] = highest_conf

        return profile
