"""Domain Exception Hierarchy."""

from python_hunter.domain.exceptions.base import (
    AnalyzerError,
    ConfigurationError,
    InfrastructureError,
    ProjectError,
    PythonHunterError,
    RuleError,
    ScanError,
    ValidationError,
)

__all__ = [
    "PythonHunterError",
    "ConfigurationError",
    "ProjectError",
    "ScanError",
    "AnalyzerError",
    "RuleError",
    "ValidationError",
    "InfrastructureError",
]
