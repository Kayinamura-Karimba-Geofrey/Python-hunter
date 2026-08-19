"""JavaScript and TypeScript framework adapters for Express and NestJS."""

import os
import re
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.frameworks.framework_adapter import FrameworkAdapter
from python_hunter.domain.frameworks.framework_models import ApplicationModel, AuthStatus, FrameworkCapability, Route
from python_hunter.domain.language.models import Language


class ExpressFrameworkAdapter(FrameworkAdapter):
    """Static framework adapter for Express applications."""

    @property
    def framework_id(self) -> str:
        return "express"

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def capabilities(self) -> set[FrameworkCapability]:
        return {
            FrameworkCapability.ROUTE_DISCOVERY,
            FrameworkCapability.REQUEST_SOURCE_DISCOVERY,
            FrameworkCapability.MIDDLEWARE_ANALYSIS,
        }

    def detect_and_enrich(self, workspace_path: str) -> ApplicationModel | None:
        model = ApplicationModel(
            app_name=os.path.basename(workspace_path) or "express_app",
            framework_id=self.framework_id,
            framework_version="4.x",
            language=self.language,
        )

        for root, _, files in os.walk(workspace_path):
            if "node_modules" in root:
                continue
            for file in files:
                if file.endswith((".js", ".ts")):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        if "express()" in content or "router.get(" in content or "app.get(" in content:
                            lines = content.splitlines()
                            for idx, line in enumerate(lines, 1):
                                match = re.search(r"(app|router)\.(get|post|put|delete)\(\s*['\"]([^'\"]+)['\"]", line)
                                if match:
                                    method = match.group(2).upper()
                                    path = match.group(3)
                                    model.routes.append(
                                        Route(
                                            http_method=method,
                                            path=path,
                                            handler_name=f"express_handler_L{idx}",
                                            file_path=full_path,
                                            location=Location(idx, idx),
                                            auth_status=AuthStatus.AUTHENTICATED if "authenticate" in line or "verifyToken" in line else AuthStatus.UNAUTHENTICATED,
                                        )
                                    )
                    except Exception:
                        pass

        return model if model.routes else None
