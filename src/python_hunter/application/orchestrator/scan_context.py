"""ScanContext and ScanResult model extensions for CI/CD metadata."""

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.graph.models import AttackPath, SecurityGraph, WholeProjectRisk
from python_hunter.infrastructure.repository.target_resolver import ScanTarget


class ExecutionStatus(str, Enum):
    """Status of scan execution engine."""

    PASSED = "PASSED"
    POLICY_FAILED = "POLICY_FAILED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    CONFIGURATION_FAILED = "CONFIGURATION_FAILED"
    INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"


@dataclass
class ScanContext:
    """Encapsulates metadata, configuration, CI environment, and execution timing for a scan session."""

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget | None = None
    workspace_path: str = ""
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    is_ci: bool = field(default_factory=lambda: os.getenv("CI", "false").lower() == "true")
    ci_metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "repository": os.getenv("GITHUB_REPOSITORY", ""),
            "ref": os.getenv("GITHUB_REF", ""),
            "sha": os.getenv("GITHUB_SHA", ""),
            "run_id": os.getenv("GITHUB_RUN_ID", ""),
            "actor": os.getenv("GITHUB_ACTOR", ""),
        }
    )


@dataclass
class ScanResult:
    """Complete aggregated results of a Python Hunter scan."""

    context: ScanContext
    findings: list[Finding] = field(default_factory=list)
    graph: SecurityGraph | None = None
    attack_paths: list[AttackPath] = field(default_factory=list)
    project_risk: WholeProjectRisk | None = None
    exit_code: int = 0
    execution_status: ExecutionStatus = ExecutionStatus.PASSED
