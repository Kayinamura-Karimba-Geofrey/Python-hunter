"""Django Framework Adapter Implementation."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint, EntryPointType
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.frameworks.adapter import BaseFrameworkAdapter
from python_hunter.domain.frameworks.models import (
    FrameworkEvidence,
    FrameworkProfile,
    FrameworkRoute,
    FrameworkType,
)
from python_hunter.domain.taint.models import TaintSinkCategory, TaintSourceCategory


class DjangoAdapter(BaseFrameworkAdapter):
    """Adapter for Django web applications."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.DJANGO

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "django" or imp.module.startswith("django."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.DJANGO,
                            confidence=Confidence.HIGH,
                            evidence_type="import",
                            source_element=imp.module,
                            file_path=doc.file_path,
                            line=imp.location.line_start if imp.location else None,
                        )
                    )
            if doc.file_path.endswith("settings.py") or doc.file_path.endswith("urls.py") or doc.file_path.endswith("wsgi.py"):
                evidences.append(
                    FrameworkEvidence(
                        framework=FrameworkType.DJANGO,
                        confidence=Confidence.HIGH,
                        evidence_type="config",
                        source_element=doc.file_path.split("/")[-1],
                        file_path=doc.file_path,
                    )
                )
        return evidences

    def discover_entry_points(self, documents: list[ASTDocument]) -> list[EntryPoint]:
        entry_points = []
        routes = self.discover_routes(documents)
        for r in routes:
            entry_points.append(
                EntryPoint(
                    name=r.handler_name,
                    qualified_name=r.handler_qualified_name,
                    entry_type=EntryPointType.HTTP_ROUTE,
                    file_path=r.file_path,
                    location=r.location,
                    route_path=r.path,
                    http_method=r.http_method,
                )
            )
        return entry_points

    def discover_routes(self, documents: list[ASTDocument]) -> list[FrameworkRoute]:
        routes = []
        for doc in documents:
            if not doc.file_path.endswith("urls.py"):
                continue
            for call in doc.calls:
                if call.name in ("path", "re_path"):
                    routes.append(
                        FrameworkRoute(
                            framework=FrameworkType.DJANGO,
                            http_method="GET",
                            path="/" + call.name,
                            handler_name=call.name,
                            handler_qualified_name=f"{doc.module_name}.{call.name}",
                            file_path=doc.file_path,
                            location=call.location,
                        )
                    )
        return routes

    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        return {
            "request.GET": TaintSourceCategory.HTTP_REQUEST,
            "request.POST": TaintSourceCategory.HTTP_REQUEST,
            "request.FILES": TaintSourceCategory.HTTP_REQUEST,
            "request.COOKIES": TaintSourceCategory.HTTP_REQUEST,
            "request.headers": TaintSourceCategory.HTTP_REQUEST,
            "request.body": TaintSourceCategory.HTTP_REQUEST,
        }

    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        return {
            "raw": TaintSinkCategory.SQL_INJECTION,
            "extra": TaintSinkCategory.SQL_INJECTION,
            "connection.cursor": TaintSinkCategory.SQL_INJECTION,
        }

    def analyze_framework_patterns(
        self, documents: list[ASTDocument], profile: FrameworkProfile
    ) -> list[Finding]:
        findings = []
        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                # Detect @csrf_exempt
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in node.decorator_list:
                        dec_name = getattr(dec, "id", None) or getattr(dec, "attr", None)
                        if dec_name == "csrf_exempt":
                            line = getattr(node, "lineno", 1)
                            findings.append(
                                Finding(
                                    rule_id="PYH-DJANGO-002",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    category=Category.CONFIGURATION,
                                    title="Explicit CSRF Exemption (@csrf_exempt)",
                                    description=f"View function '{node.name}' explicitly disables CSRF protection using @csrf_exempt.",
                                    file_path=doc.file_path,
                                    location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                    remediation="Ensure CSRF protection is enabled for state-changing HTTP endpoints.",
                                    risk_score=75.0,
                                )
                            )

                # Detect DEBUG = True
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        target_name = getattr(target, "id", None)
                        if target_name == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                            line = getattr(node, "lineno", 1)
                            findings.append(
                                Finding(
                                    rule_id="PYH-DJANGO-001",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    category=Category.CONFIGURATION,
                                    title="Django Debug Mode Enabled",
                                    description="DEBUG = True in Django settings displays detailed tracebacks containing secrets and environment state on uncaught exceptions.",
                                    file_path=doc.file_path,
                                    location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                    remediation="Set DEBUG = False in production settings or read dynamically from environment variables.",
                                    risk_score=70.0,
                                )
                            )
        return findings
