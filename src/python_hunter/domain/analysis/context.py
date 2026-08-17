"""Analysis Context Abstraction."""

from dataclasses import dataclass, field
from typing import Any
from python_hunter.domain.projects.project import Project
from python_hunter.domain.projects.target_file import TargetFile


@dataclass(frozen=True)
class AnalysisContext:
    """Context information provided to security analyzers during pipeline execution."""

    scan_id: str
    project: Project
    target_files: list[TargetFile] = field(default_factory=list)
    git_info: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
