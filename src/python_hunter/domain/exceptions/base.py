"""Domain Exception Hierarchy for Python Hunter."""

from typing import Any


class PythonHunterError(Exception):
    """Base exception for all Python Hunter domain, application, and infrastructure errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigurationError(PythonHunterError):
    """Raised when application or scan configuration is invalid or missing required values."""


class ProjectError(PythonHunterError):
    """Raised when a target project structure, file, or path is invalid or unreadable."""


class ScanError(PythonHunterError):
    """Raised when an invalid scan lifecycle transition or execution error occurs."""


class AnalyzerError(PythonHunterError):
    """Raised when an analyzer fails or encounters an unrecoverable execution error."""


class RuleError(PythonHunterError):
    """Raised when a security rule definition is invalid or fails parsing."""


class ValidationError(PythonHunterError):
    """Raised when domain entity validation fails."""


class InfrastructureError(PythonHunterError):
    """Raised when an external infrastructure component (database, queue, storage) fails."""
