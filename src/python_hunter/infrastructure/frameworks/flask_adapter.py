"""Flask Framework Adapter Implementation."""

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


class FlaskAdapter(BaseFrameworkAdapter):
    """Adapter for Flask web applications."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.FLASK

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "flask" or imp.module.startswith("flask."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.FLASK,
                            confidence=Confidence.HIGH,
                            evidence_type="import",
                            source_element=imp.module,
                            file_path=doc.file_path,
                            line=imp.location.line_start if imp.location else None,
                        )
                    )
            for call in doc.calls:
                if call.name in ("Flask", "Blueprint"):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.FLASK,
                            confidence=Confidence.HIGH,
                            evidence_type="object",
                            source_element=call.name,
                            file_path=doc.file_path,
                            line=call.location.line_start if call.location else None,
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
            for fn in doc.functions:
                for dec in fn.decorators:
                    if "route" in dec.name or any(m in dec.name for m in ["get", "post", "put", "delete"]):
                        method = "GET"
                        path = "/" + fn.name
                        routes.append(
                            FrameworkRoute(
                                framework=FrameworkType.FLASK,
                                http_method=method,
                                path=path,
                                handler_name=fn.name,
                                handler_qualified_name=f"{doc.module_name}.{fn.name}",
                                file_path=doc.file_path,
                                location=fn.location,
                            )
                        )
        return routes

    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        return {
            "request.args": TaintSourceCategory.HTTP_REQUEST,
            "request.form": TaintSourceCategory.HTTP_REQUEST,
            "request.json": TaintSourceCategory.HTTP_REQUEST,
            "request.data": TaintSourceCategory.HTTP_REQUEST,
            "request.values": TaintSourceCategory.HTTP_REQUEST,
            "request.headers": TaintSourceCategory.HTTP_REQUEST,
            "request.cookies": TaintSourceCategory.HTTP_REQUEST,
            "request.files": TaintSourceCategory.HTTP_REQUEST,
        }

    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        return {
            "render_template_string": TaintSinkCategory.TEMPLATE_INJECTION,
            "send_file": TaintSinkCategory.PATH_TRAVERSAL,
            "send_from_directory": TaintSinkCategory.PATH_TRAVERSAL,
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
                # Detect app.run(debug=True)
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    if func_name == "run":
                        for kw in node.keywords:
                            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                line = getattr(node, "lineno", 1)
                                findings.append(
                                    Finding(
                                        rule_id="PYH-FLASK-001",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.HIGH,
                                        category=Category.CONFIGURATION,
                                        title="Flask Debug Mode Enabled in Application Code",
                                        description="app.run(debug=True) enables interactive debugger that permits arbitrary code execution if exposed.",
                                        file_path=doc.file_path,
                                        location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                        remediation="Ensure debug=False in production deployments or control via environment variables.",
                                        risk_score=75.0,
                                    )
                                )

                # Detect app.secret_key = "hardcoded"
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        target_name = getattr(target, "attr", None) or getattr(target, "id", None)
                        if target_name in ("secret_key", "SECRET_KEY") and isinstance(node.value, (ast.Constant, ast.Str)):
                            val = getattr(node.value, "value", None) or getattr(node.value, "s", None)
                            if isinstance(val, str) and len(val) > 0 and not val.startswith("env:"):
                                line = getattr(node, "lineno", 1)
                                findings.append(
                                    Finding(
                                        rule_id="PYH-FLASK-002",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.HIGH,
                                        category=Category.SECRET,
                                        title="Hardcoded Flask Secret Key",
                                        description="Flask secret key is hardcoded in source code, enabling session forgery if exposed.",
                                        file_path=doc.file_path,
                                        location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                        remediation="Load Flask secret_key securely from environment variables or secret manager.",
                                        risk_score=80.0,
                                    )
                                )
        return findings
