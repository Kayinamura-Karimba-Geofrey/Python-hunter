"""Route & Lifecycle Analyzer Implementation."""

import ast
from typing import Any
from python_hunter.domain.ast.models import ASTDocument
from python_hunter.domain.common.enums import Confidence
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.web_security.analyzers.base import BaseWebSecurityAnalyzer
from python_hunter.domain.web_security.models import AuthRequirement, AuthzMechanism, RouteSecurityModel


class RouteAnalyzer(BaseWebSecurityAnalyzer):
    """Discovers web routes, HTTP methods, route parameters, auth requirements, and IDOR/BOLA patterns."""

    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

    def analyze(self, documents: list[ASTDocument]) -> dict[str, Any]:
        routes: list[RouteSecurityModel] = []
        ssrf_paths: list[dict[str, Any]] = []

        for doc in documents:
            try:
                tree = ast.parse("\n".join(doc.source_lines))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Check decorators for route definitions (@app.get("/path"), @router.post, etc.)
                    for decorator in node.decorator_list:
                        route_path, method = self._extract_route_info(decorator)
                        if route_path:
                            line = getattr(node, "lineno", 1)
                            loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))

                            # Inspect function body for auth / ownership checks
                            code_body = ast.unparse(node) if hasattr(ast, "unparse") else ""
                            is_authenticated = any(kw in code_body for kw in ("current_user", "get_current_user", "login_required", "authenticate"))
                            is_ownership = any(kw in code_body for kw in ("owner_id", "user_id == ", "created_by"))
                            has_rbac = any(kw in code_body for kw in ("role", "has_permission", "is_admin", "require_role"))

                            auth_req = AuthRequirement.AUTHENTICATED if is_authenticated else AuthRequirement.PUBLIC
                            authz = AuthzMechanism.OWNERSHIP if is_ownership else (AuthzMechanism.RBAC if has_rbac else AuthzMechanism.NONE)

                            routes.append(
                                RouteSecurityModel(
                                    route_path=route_path,
                                    http_methods=[method.upper()],
                                    handler_name=node.name,
                                    file_path=doc.file_path,
                                    location=loc,
                                    auth_requirement=auth_req,
                                    authz_mechanism=authz,
                                    has_ownership_check=is_ownership,
                                    is_csrf_protected=(method.lower() not in ("post", "put", "delete", "patch")),
                                    is_sensitive=("admin" in route_path or "delete" in route_path or "user" in route_path),
                                    confidence=Confidence.HIGH,
                                )
                            )

                # Track SSRF sinks (requests.get(url), httpx.get(url))
                elif isinstance(node, ast.Call):
                    func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                    mod_name = None
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        mod_name = node.func.value.id

                    if func_name in ("get", "post", "put", "request") and mod_name in ("requests", "httpx", "aiohttp"):
                        line = getattr(node, "lineno", 1)
                        loc = Location(line_start=line, line_end=line, column_start=getattr(node, "col_offset", 0))
                        ssrf_paths.append({
                            "client": mod_name,
                            "method": func_name,
                            "file_path": doc.file_path,
                            "location": loc,
                        })

        return {
            "routes": routes,
            "ssrf_paths": ssrf_paths,
        }

    def _extract_route_info(self, decorator: ast.expr) -> tuple[str | None, str]:
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                attr_name = decorator.func.attr.lower()
                if attr_name in self.HTTP_METHODS or attr_name in ("route", "add_url_rule"):
                    if decorator.args:
                        arg0 = decorator.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                            return arg0.value, attr_name
        return None, ""
