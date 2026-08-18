"""FastAPI Framework Adapter Implementation."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint, EntryPointType
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.frameworks.adapter import BaseFrameworkAdapter
from python_hunter.domain.frameworks.models import (
    FrameworkEvidence,
    FrameworkProfile,
    FrameworkRoute,
    FrameworkType,
)
from python_hunter.domain.taint.models import TaintSinkCategory, TaintSourceCategory


class FastAPIAdapter(BaseFrameworkAdapter):
    """Adapter for FastAPI web applications."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.FASTAPI

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module == "fastapi" or imp.module.startswith("fastapi."):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.FASTAPI,
                            confidence=Confidence.HIGH,
                            evidence_type="import",
                            source_element=imp.module,
                            file_path=doc.file_path,
                            line=imp.location.line_start if imp.location else None,
                        )
                    )
            for call in doc.calls:
                if call.name in ("FastAPI", "APIRouter"):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.FASTAPI,
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
                    dec_base = dec.name.split(".")[-1]
                    if dec_base in ("get", "post", "put", "delete", "patch", "options", "api_route"):
                        method = dec_base.upper() if dec_base != "api_route" else "GET"
                        path = "/" + fn.name

                        has_auth = "Depends" in str(fn.arguments) and any(
                            d in str(fn.arguments).lower()
                            for d in ["auth", "token", "security", "bearer", "oauth", "current_user"]
                        )
                        routes.append(
                            FrameworkRoute(
                                framework=FrameworkType.FASTAPI,
                                http_method=method,
                                path=path,
                                handler_name=fn.name,
                                handler_qualified_name=f"{doc.module_name}.{fn.name}",
                                file_path=doc.file_path,
                                location=fn.location,
                                auth_required=has_auth,
                            )
                        )
        return routes

    def discover_sources(self, documents: list[ASTDocument]) -> dict[str, TaintSourceCategory]:
        return {
            "Query": TaintSourceCategory.HTTP_REQUEST,
            "Path": TaintSourceCategory.HTTP_REQUEST,
            "Header": TaintSourceCategory.HTTP_REQUEST,
            "Cookie": TaintSourceCategory.HTTP_REQUEST,
            "Body": TaintSourceCategory.HTTP_REQUEST,
            "Form": TaintSourceCategory.HTTP_REQUEST,
            "File": TaintSourceCategory.HTTP_REQUEST,
        }

    def discover_sinks(self, documents: list[ASTDocument]) -> dict[str, TaintSinkCategory]:
        return {}

    def analyze_framework_patterns(
        self, documents: list[ASTDocument], profile: FrameworkProfile
    ) -> list[Finding]:
        findings = []
        routes = self.discover_routes(documents)
        sensitive_keywords = ["admin", "delete", "reset", "secret", "config", "internal", "exec"]

        for r in routes:
            is_sensitive = any(kw in r.path.lower() or kw in r.handler_name.lower() for kw in sensitive_keywords)
            if is_sensitive and not r.auth_required:
                findings.append(
                    Finding(
                        rule_id="PYH-FASTAPI-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category=Category.AUTHENTICATION,
                        title="Unauthenticated Sensitive FastAPI Endpoint",
                        description=f"Endpoint '{r.http_method} {r.path}' appears sensitive but lacks explicit authentication dependency (Depends(Security)).",
                        file_path=r.file_path,
                        location=r.location,
                        remediation="Add security dependencies (e.g. Depends(get_current_user) or Depends(HTTPBearer())) to protect sensitive endpoints.",
                        risk_score=70.0,
                    )
                )
        return findings
