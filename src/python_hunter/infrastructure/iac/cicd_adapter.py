"""CI/CD and GitHub Actions workflow static parser adapter."""

import os
import re
from typing import Any, Dict, List, Optional
from python_hunter.domain.infrastructure.models import (
    IAMPermission,
    IAMPolicy,
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)
from python_hunter.domain.infrastructure.yaml_parser import safe_yaml_load
from python_hunter.infrastructure.iac.registry import InfrastructureAdapter


class CICDAdapter(InfrastructureAdapter):
    """Parses GitHub Actions workflows and CI/CD configuration files into Infrastructure IR."""

    @property
    def adapter_name(self) -> str:
        return "CICDAdapter"

    def detect(self, file_path: str, content: str) -> bool:
        norm_path = file_path.replace("\\", "/")
        if ".github/workflows/" in norm_path and norm_path.endswith((".yml", ".yaml")):
            return True
        if ".gitlab-ci.yml" in norm_path or "jenkinsfile" in norm_path.lower():
            return True
        return False

    def parse_and_build_ir(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        try:
            wf_data = safe_yaml_load(content)
        except Exception:
            wf_data = {}

        if not isinstance(wf_data, dict):
            return

        wf_name = wf_data.get("name", os.path.basename(file_path))
        triggers = wf_data.get("on", {})
        if isinstance(triggers, str):
            triggers = [triggers]
        elif isinstance(triggers, dict):
            triggers = list(triggers.keys())

        global_permissions = wf_data.get("permissions", {})
        jobs = wf_data.get("jobs", {})

        unpinned_actions = []
        dangerous_runs = []
        excessive_perms = []

        if isinstance(global_permissions, dict):
            for perm_key, perm_val in global_permissions.items():
                if perm_val in ("write", "write-all"):
                    excessive_perms.append(f"global:{perm_key}:{perm_val}")

        if isinstance(jobs, dict):
            for job_id, job_conf in jobs.items():
                if not isinstance(job_conf, dict):
                    continue

                steps = job_conf.get("steps", [])
                if isinstance(steps, list):
                    for step in steps:
                        if not isinstance(step, dict):
                            continue

                        uses = step.get("uses", "")
                        if uses and not uses.startswith("./"):
                            # Check action pinning
                            if "@" in uses:
                                tag_or_sha = uses.split("@")[1]
                                if not re.match(r"^[a-f0-9]{40}$", tag_or_sha, re.IGNORECASE):
                                    unpinned_actions.append(uses)
                            else:
                                unpinned_actions.append(uses)

                        run_cmd = step.get("run", "")
                        if run_cmd:
                            # Detect dangerous shell interpolation (e.g. ${{ github.event.issue.title }})
                            if re.search(r"\$\{\{\s*github\.event\.(?:issue|pull_request|head_commit|comment)", run_cmd):
                                dangerous_runs.append(run_cmd)

        res = InfrastructureResource(
            id=f"cicd::github_action::{file_path}",
            name=f"Workflow/{wf_name}",
            type=InfrastructureResourceType.GITHUB_ACTION_WORKFLOW,
            provider="GitHub",
            file_path=file_path,
            properties={
                "workflow_name": wf_name,
                "triggers": triggers,
                "unpinned_actions": unpinned_actions,
                "dangerous_runs": dangerous_runs,
                "excessive_permissions": excessive_perms,
                "raw_workflow": wf_data,
            },
        )

        ir.resources.append(res)
        ir.graph.add_resource(res)
        ir.cicd_workflows.append({"file_path": file_path, "name": wf_name, "resource": res})
