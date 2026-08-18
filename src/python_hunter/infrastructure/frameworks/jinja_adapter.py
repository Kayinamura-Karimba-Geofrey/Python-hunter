"""Jinja2 Framework Adapter Implementation."""

from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint
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


class JinjaAdapter(BaseFrameworkAdapter):
    """Adapter for Jinja2 Templating Engine."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.JINJA2

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "jinja2" or imp.module.startswith("jinja2."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.JINJA2,
                            confidence=Confidence.HIGH,
                            evidence_type="import",
                            source_element=imp.module,
                            file_path=doc.file_path,
                            line=imp.location.line_start if imp.location else None,
                        )
                    )
        return evidences

    def discover_entry_points(self, documents: list[ASTDocument]) -> list[EntryPoint]:
        return []

    def discover_routes(self, documents: list[ASTDocument]) -> list[FrameworkRoute]:
        return []

    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        return {}

    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        return {
            "render_template_string": TaintSinkCategory.TEMPLATE_INJECTION,
            "Template": TaintSinkCategory.TEMPLATE_INJECTION,
            "Environment.from_string": TaintSinkCategory.TEMPLATE_INJECTION,
        }

    def analyze_framework_patterns(
        self, documents: list[ASTDocument], profile: FrameworkProfile
    ) -> list[Finding]:
        return []
