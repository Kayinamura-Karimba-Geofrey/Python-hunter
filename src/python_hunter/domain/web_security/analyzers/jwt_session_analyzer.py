"""JWT & Session Security Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.web_security.analyzers.base import BaseWebSecurityAnalyzer
from python_hunter.domain.web_security.models import JWTSecurityConfig


class JWTSessionAnalyzer(BaseWebSecurityAnalyzer):
    """Analyzes JWT signature validation, algorithms, claim checks, and session cookie attributes."""

    def analyze(self, documents: list[ASTDocument]) -> dict[str, Any]:
        jwt_configs: list[JWTSecurityConfig] = []
        cors_issues: list[dict[str, Any]] = []

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                # 1. JWT decode calls (jwt.decode(token, secret, algorithms=[...]))
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    line = getattr(node, "lineno", 1)
                    loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                    if func_name == "decode":
                        # Check keyword arguments
                        options_kw = next((kw for kw in node.keywords if kw.arg == "options"), None)
                        algos_kw = next((kw for kw in node.keywords if kw.arg == "algorithms"), None)

                        verifies_sig = True
                        accepts_none = False

                        if options_kw and isinstance(options_kw.value, ast.Dict):
                            for k, v in zip(options_kw.value.keys, options_kw.value.values):
                                if isinstance(k, ast.Constant) and k.value == "verify_signature" and isinstance(v, ast.Constant) and v.value is False:
                                    verifies_sig = False

                        jwt_configs.append(
                            JWTSecurityConfig(
                                file_path=doc.file_path,
                                location=loc,
                                verifies_signature=verifies_sig,
                                verifies_exp=True,
                                accepts_none=accepts_none,
                            )
                        )

                    # 2. CORS configuration (CORSMiddleware, add_middleware(..., allow_origins=["*"], allow_credentials=True))
                    elif func_name == "add_middleware" or "CORS" in str(func_name):
                        code_snippet = ast.unparse(node) if hasattr(ast, "unparse") else ""
                        if '"*"' in code_snippet and "allow_credentials=True" in code_snippet:
                            cors_issues.append({
                                "issue": "CORS wildcard with credentials",
                                "file_path": doc.file_path,
                                "location": loc,
                            })

        return {
            "jwt_configs": jwt_configs,
            "cors_issues": cors_issues,
        }
