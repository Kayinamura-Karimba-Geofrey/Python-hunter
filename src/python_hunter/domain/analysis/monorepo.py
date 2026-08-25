"""Monorepo Project Discovery and Cross-Language Correlation Engine."""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.language.models import Language


@dataclass
class MonorepoSubProject:
    project_id: str
    name: str
    relative_path: str
    languages: List[Language]
    manifests: List[str]


class MonorepoDiscoveryEngine:
    """Discovers sub-projects and service boundaries in polyglot monorepos."""

    COMMON_PROJECT_DIRS = {"frontend", "backend", "services", "service", "mobile", "api", "infrastructure", "client", "server"}

    @classmethod
    def discover_monorepo_projects(cls, workspace_path: str) -> List[MonorepoSubProject]:
        sub_projects = []
        if not os.path.exists(workspace_path) or not os.path.isdir(workspace_path):
            return sub_projects

        for entry in os.listdir(workspace_path):
            full_path = os.path.join(workspace_path, entry)
            if os.path.isdir(full_path) and entry.lower() in cls.COMMON_PROJECT_DIRS:
                manifests = []
                langs = []
                for root, dirs, files in os.walk(full_path):
                    for f in files:
                        if f in ["package.json", "pom.xml", "go.mod", "Cargo.toml", "requirements.txt", "Gemfile", "composer.json"]:
                            manifests.append(f)
                sub_projects.append(MonorepoSubProject(
                    project_id=f"proj-{entry}",
                    name=entry,
                    relative_path=entry,
                    languages=langs,
                    manifests=manifests
                ))
        return sub_projects


class CrossLanguageCorrelationEngine:
    """Correlates security vulnerabilities across polyglot service boundaries (e.g. React frontend -> Express API -> Python service)."""

    @classmethod
    def correlate_findings(cls, findings: List[Finding]) -> List[Dict[str, Any]]:
        correlations = []
        frontend_findings = [f for f in findings if f.file_path and any(f.file_path.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx"])]
        backend_findings = [f for f in findings if f.file_path and any(f.file_path.endswith(ext) for ext in [".py", ".java", ".go", ".cs", ".php", ".rb"])]

        for ff in frontend_findings:
            for bf in backend_findings:
                # Correlate XSS/API parameter flow
                if "XSS" in ff.title or "Client" in ff.title:
                    if "SQL" in bf.title or "Command" in bf.title:
                        correlations.append({
                            "correlation_id": f"corr-{ff.rule_id}-{bf.rule_id}",
                            "title": "Cross-Language End-to-End Exploit Path",
                            "frontend_finding": ff.rule_id,
                            "backend_finding": bf.rule_id,
                            "description": f"Untrusted input handled in frontend ({ff.file_path}) flows to dangerous backend sink ({bf.file_path})."
                        })
        return correlations
