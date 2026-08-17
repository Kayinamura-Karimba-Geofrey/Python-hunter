"""Analysis Result Contract."""

from dataclasses import dataclass, field
from typing import Any
from python_hunter.domain.findings.finding import Finding


@dataclass
class AnalysisResult:
    """Result returned by an analyzer after scanning a context."""

    analyzer_name: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
