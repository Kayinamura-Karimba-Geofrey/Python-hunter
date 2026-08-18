"""Celery Framework Adapter Implementation."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint, EntryPointType
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.frameworks.adapter import BaseFrameworkAdapter
from python_hunter.domain.frameworks.models import (
    FrameworkEvidence,
    FrameworkProfile,
    FrameworkRoute,
    FrameworkType,
)
from python_hunter.domain.taint.models import TaintSinkCategory, TaintSourceCategory


class CeleryAdapter(BaseFrameworkAdapter):
    """Adapter for Celery distributed task queues."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.CELERY

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "celery" or imp.module.startswith("celery."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.CELERY,
                            confidence=Confidence.HIGH,
                            evidence_type="import",
                            source_element=imp.module,
                            file_path=doc.file_path,
                            line=imp.location.line_start if imp.location else None,
                        )
                    )
        return evidences

    def discover_entry_points(self, documents: list[ASTDocument]) -> list[EntryPoint]:
        entry_points = []
        for doc in documents:
            for fn in doc.functions:
                for dec in fn.decorators:
                    if dec.name in ("task", "shared_task") or dec.name.endswith(".task"):
                        entry_points.append(
                            EntryPoint(
                                name=fn.name,
                                qualified_name=f"{doc.module_name}.{fn.name}",
                                entry_type=EntryPointType.CELERY_TASK,
                                file_path=doc.file_path,
                                location=fn.location,
                            )
                        )
        return entry_points

    def discover_routes(self, documents: list[ASTDocument]) -> list[FrameworkRoute]:
        return []

    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        # Task parameter inputs are registered as untrusted task sources
        return {"task_args": TaintSourceCategory.CLI_ARGUMENT}

    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        return {}

    def analyze_framework_patterns(
        self, documents: list[ASTDocument], profile: FrameworkProfile
    ) -> list[Finding]:
        return []
