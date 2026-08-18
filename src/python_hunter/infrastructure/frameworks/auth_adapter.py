"""Authentication Libraries Adapter Implementation."""

import ast
from typing import Any

from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.callgraph.models import EntryPoint
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


class AuthAdapter(BaseFrameworkAdapter):
    """Adapter for Authentication & JWT Libraries (PyJWT, bcrypt, argon2, passlib)."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.AUTH_LIBRARIES

    def detect(
        self, documents: list[ASTDocument], dependencies: list[Any] | None = None
    ) -> list[FrameworkEvidence]:
        evidences = []
        for doc in documents:
            for imp in doc.imports:
                if imp.module in ("jwt", "bcrypt", "argon2", "passlib"):
                    evidences.append(
                        FrameworkEvidence(
                            framework=FrameworkType.AUTH_LIBRARIES,
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
        return {}

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
                # Detect jwt.decode(..., options={"verify_signature": False})
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    if func_name == "decode":
                        for kw in node.keywords:
                            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                                for k, v in zip(kw.value.keys, kw.value.values):
                                    if (
                                        isinstance(k, (ast.Constant, ast.Str))
                                        and (getattr(k, "value", None) == "verify_signature" or getattr(k, "s", None) == "verify_signature")
                                        and isinstance(v, ast.Constant)
                                        and v.value is False
                                    ):
                                        line = getattr(node, "lineno", 1)
                                        findings.append(
                                            Finding(
                                                rule_id="PYH-JWT-001",
                                                severity=Severity.CRITICAL,
                                                confidence=Confidence.HIGH,
                                                category=Category.AUTHENTICATION,
                                                title="Insecure JWT Signature Verification Disabled",
                                                description="jwt.decode call explicitly disables signature verification, allowing forged JWT tokens to be accepted.",
                                                file_path=doc.file_path,
                                                location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                                remediation="Remove options={'verify_signature': False} and enforce signature verification with a secret/public key.",
                                                risk_score=95.0,
                                            )
                                        )
                            elif kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                line = getattr(node, "lineno", 1)
                                findings.append(
                                    Finding(
                                        rule_id="PYH-JWT-001",
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.HIGH,
                                        category=Category.AUTHENTICATION,
                                        title="Insecure JWT Signature Verification Disabled",
                                        description="jwt.decode call explicitly disables token verification (verify=False).",
                                        file_path=doc.file_path,
                                        location=Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0)),
                                        remediation="Enforce signature verification when decoding JWT tokens.",
                                        risk_score=95.0,
                                    )
                                )
        return findings
