"""ScanContext and ScanResult data models."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.graph.models import AttackPath, SecurityGraph, WholeProjectRisk
from python_hunter.infrastructure.repository.target_resolver import ScanTarget


@dataclass
class ScanContext:
    """Encapsulates metadata, configuration, and execution timing for a scan session."""

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget | None = None
    workspace_path: str = ""
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str = ""
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete aggregated results of a Python Hunter scan."""

    context: ScanContext
    findings: list[Finding] = field(default_factory=list)
    graph: SecurityGraph | None = None
    attack_paths: list[AttackPath] = field(default_factory=list)
    project_risk: WholeProjectRisk | None = None
    exit_code: int = 0
