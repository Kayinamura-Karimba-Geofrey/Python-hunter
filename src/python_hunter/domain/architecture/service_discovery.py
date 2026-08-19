"""Statically discovers services, Docker Compose configs, OpenAPI specs, and outbound API calls."""

import json
import os
import re
from python_hunter.domain.architecture.service_models import (
    ApiClientCall,
    DatabaseAsset,
    ExternalService,
    InterServiceDataFlow,
    Service,
    TrustBoundary,
)
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.language.models import Language


class ServiceDiscoveryEngine:
    """Discovers services, docker-compose services, OpenAPI specs, and outbound API calls statically."""

    def discover_services(self, workspace_path: str) -> list[Service]:
        services = []

        # 1. Search monorepo directories (e.g. services/*, backend/, frontend/, apps/*)
        for root, dirs, files in os.walk(workspace_path):
            if "node_modules" in root or ".git" in root:
                continue

            rel_path = os.path.relpath(root, workspace_path)
            depth = len(rel_path.split(os.sep))

            if ("package.json" in files or any(f.endswith(".py") for f in files)) and depth <= 3:
                service_id = os.path.basename(root) or "root_service"
                if service_id not in [s.service_id for s in services]:
                    lang = Language.JAVASCRIPT if "package.json" in files else Language.PYTHON
                    boundary = TrustBoundary.PUBLIC_API if ("gateway" in service_id.lower() or "auth" in service_id.lower()) else TrustBoundary.INTERNAL_SERVICE

                    service = Service(
                        service_id=service_id,
                        name=service_id,
                        language=lang,
                        root_directory=root,
                        trust_boundary=boundary,
                    )
                    self._extract_api_calls(service)
                    services.append(service)

        # 2. Parse docker-compose.yml statically
        compose_path = os.path.join(workspace_path, "docker-compose.yml")
        if not os.path.exists(compose_path):
            compose_path = os.path.join(workspace_path, "docker-compose.yaml")

        if os.path.exists(compose_path):
            try:
                with open(compose_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Basic regex match for compose service names
                service_names = re.findall(r"^\s\s([a-zA-Z0-9_-]+):", content, re.MULTILINE)
                for sname in service_names:
                    if sname not in [s.service_id for s in services] and sname not in ("version", "services", "networks", "volumes"):
                        services.append(
                            Service(
                                service_id=sname,
                                name=sname,
                                language=Language.UNKNOWN,
                                root_directory=workspace_path,
                                trust_boundary=TrustBoundary.INTERNAL_SERVICE,
                            )
                        )
            except Exception:
                pass

        return services

    def _extract_api_calls(self, service: Service) -> None:
        """Statically extract outbound HTTP API calls (requests, httpx, fetch, axios)."""
        patterns = [
            r"requests\.(get|post|put|delete)\(\s*['\"]([^'\"]+)['\"]",
            r"httpx\.(get|post|put|delete)\(\s*['\"]([^'\"]+)['\"]",
            r"fetch\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.(get|post|put|delete)\(\s*['\"]([^'\"]+)['\"]",
        ]

        for root, _, files in os.walk(service.root_directory):
            if "node_modules" in root:
                continue
            for file in files:
                if file.endswith((".py", ".js", ".ts")):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        lines = content.splitlines()
                        for idx, line in enumerate(lines, 1):
                            for pat in patterns:
                                match = re.search(pat, line)
                                if match:
                                    method = match.group(1).upper() if len(match.groups()) > 1 else "GET"
                                    url = match.group(2) if len(match.groups()) > 1 else match.group(1)
                                    service.api_calls.append(
                                        ApiClientCall(
                                            caller_service=service.service_id,
                                            target_url=url,
                                            http_method=method,
                                            path=url,
                                            file_path=full_path,
                                            location=Location(idx, idx),
                                        )
                                    )
                    except Exception:
                        pass
