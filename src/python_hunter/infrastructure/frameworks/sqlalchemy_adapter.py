"""SQLAlchemy Framework Adapter Implementation."""

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


class SQLAlchemyAdapter(BaseFrameworkAdapter):
    """Adapter for SQLAlchemy ORM and Database Toolkit."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.SQLALCHEMY

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "sqlalchemy" or imp.module.startswith("sqlalchemy."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.SQLALCHEMY,
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
            "text": TaintSinkCategory.SQL_INJECTION,
            "session.execute": TaintSinkCategory.SQL_INJECTION,
            "engine.execute": TaintSinkCategory.SQL_INJECTION,
        }

    def analyze_framework_patterns(
        self, documents: list[ASTDocument], profile: FrameworkProfile
    ) -> list[Finding]:
        return []
