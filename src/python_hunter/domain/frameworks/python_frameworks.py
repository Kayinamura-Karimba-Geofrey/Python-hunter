"""Python framework adapters for Django, Flask, and FastAPI."""

import ast
import os
import re
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.frameworks.framework_adapter import FrameworkAdapter
from python_hunter.domain.frameworks.framework_models import ApplicationModel, AuthStatus, FrameworkCapability, Route
from python_hunter.domain.language.models import Language


class FlaskFrameworkAdapter(FrameworkAdapter):
    """Static framework adapter for Flask applications."""

    @property
    def framework_id(self) -> str:
        return "flask"

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def capabilities(self) -> set[FrameworkCapability]:
        return {
            FrameworkCapability.ROUTE_DISCOVERY,
            FrameworkCapability.REQUEST_SOURCE_DISCOVERY,
            FrameworkCapability.AUTHENTICATION_DETECTION,
            FrameworkCapability.CONFIGURATION_ANALYSIS,
        }

    def detect_and_enrich(self, workspace_path: str) -> ApplicationModel | None:
        model = ApplicationModel(
            app_name=os.path.basename(workspace_path) or "flask_app",
            framework_id=self.framework_id,
            framework_version="2.x",
            language=self.language,
        )

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        if "Flask(" in content or "@app.route(" in content:
                            lines = content.splitlines()
                            for idx, line in enumerate(lines, 1):
                                match = re.search(r"@app\.route\(\s*['\"]([^'\"]+)['\"](?:.*methods=\[([^\]]+)\])?", line)
                                if match:
                                    path = match.group(1)
                                    methods = match.group(2) or "GET"
                                    methods_list = [m.strip().replace("'", "").replace('"', "") for m in methods.split(",")]
                                    for m in methods_list:
                                        model.routes.append(
                                            Route(
                                                http_method=m,
                                                path=path,
                                                handler_name=f"handler_L{idx}",
                                                file_path=full_path,
                                                location=Location(idx, idx),
                                                auth_status=AuthStatus.AUTHENTICATED if "login_required" in content else AuthStatus.UNAUTHENTICATED,
                                            )
                                        )
                    except Exception:
                        pass

        return model if model.routes else None


class FastAPIFrameworkAdapter(FrameworkAdapter):
    """Static framework adapter for FastAPI applications."""

    @property
    def framework_id(self) -> str:
        return "fastapi"

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def capabilities(self) -> set[FrameworkCapability]:
        return {
            FrameworkCapability.ROUTE_DISCOVERY,
            FrameworkCapability.REQUEST_SOURCE_DISCOVERY,
            FrameworkCapability.AUTHENTICATION_DETECTION,
            FrameworkCapability.AUTHORIZATION_DETECTION,
            FrameworkCapability.ORM_ANALYSIS,
        }

    def detect_and_enrich(self, workspace_path: str) -> ApplicationModel | None:
        model = ApplicationModel(
            app_name=os.path.basename(workspace_path) or "fastapi_app",
            framework_id=self.framework_id,
            framework_version="0.x",
            language=self.language,
        )

        for root, _, files in os.walk(workspace_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        if "FastAPI(" in content or "@app.get(" in content or "@router." in content:
                            lines = content.splitlines()
                            for idx, line in enumerate(lines, 1):
                                match = re.search(r"@(app|router)\.(get|post|put|delete)\(\s*['\"]([^'\"]+)['\"]", line)
                                if match:
                                    method = match.group(2).upper()
                                    path = match.group(3)
                                    model.routes.append(
                                        Route(
                                            http_method=method,
                                            path=path,
                                            handler_name=f"fastapi_handler_L{idx}",
                                            file_path=full_path,
                                            location=Location(idx, idx),
                                            auth_status=AuthStatus.AUTHENTICATED if "Depends" in line or "Security" in content else AuthStatus.UNAUTHENTICATED,
                                        )
                                    )
                    except Exception:
                        pass

        return model if model.routes else None
