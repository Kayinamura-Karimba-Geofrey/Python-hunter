"""Analyze Secrets Use Case."""

import os
from typing import Any

import uuid
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.detectors.secrets import create_default_secret_registry
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.projects.project import Project
from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.domain.secrets.registry import SecretDetectorRegistry


class AnalyzeSecretsUseCase:
    """Orchestrates Project Discovery -> File Eligibility Check -> Secret Detection Engine."""

    def __init__(
        self,
        discover_use_case: DiscoverProjectUseCase | None = None,
        registry: SecretDetectorRegistry | None = None,
    ) -> None:
        self.discover_use_case = discover_use_case or DiscoverProjectUseCase()
        self.registry = registry or create_default_secret_registry()
        self.engine = SecretDetectionEngine(registry=self.registry)

    def execute(self, project_path: str) -> dict[str, Any]:
        """Execute secret detection scan on target project."""
        manifest = self.discover_use_case.discover(project_path)
        project = Project(name=manifest.project_name, root_path=manifest.root_path)
        context = AnalysisContext(scan_id=str(uuid.uuid4()), project=project)

        scanned_files = 0
        all_findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for file_meta in manifest.files:
            rel_path = file_meta.relative_path
            abs_path = os.path.join(manifest.root_path, rel_path)

            if not self.engine.is_eligible_file(abs_path):
                continue

            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                scanned_files += 1
                findings = self.engine.scan_file(rel_path, content, context)

                for finding in findings:
                    if finding.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(finding.fingerprint)
                        all_findings.append(finding)
            except Exception:
                continue

        return {
            "project_name": manifest.project_name,
            "project_path": manifest.root_path,
            "files_scanned": scanned_files,
            "detectors_executed": len(self.registry.enabled_detectors()),
            "total_findings": len(all_findings),
            "findings": all_findings,
        }
