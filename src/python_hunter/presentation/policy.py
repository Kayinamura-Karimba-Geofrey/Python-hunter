"""Exit Code and Policy Engine for Python Hunter CLI."""

from enum import IntEnum
from python_hunter.application.orchestrator.scan_context import ScanResult
from python_hunter.domain.common.enums import Severity


class ExitCode(IntEnum):
    """Documented Exit Codes for Python Hunter CLI."""

    SUCCESS = 0
    POLICY_VIOLATION = 1
    USAGE_ERROR = 2
    TARGET_REPO_ERROR = 3
    CONFIG_ERROR = 4
    INTERNAL_ERROR = 5


class PolicyEngine:
    """Evaluates scan findings against user-configured severity, confidence, and exploitability thresholds."""

    SEVERITY_ORDER = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    def evaluate(self, result: ScanResult, fail_on: str = "high") -> int:
        """Determines CLI exit code based on project risk and severity thresholds."""
        threshold = self.SEVERITY_ORDER.get(fail_on.lower(), 3)

        if result.project_risk and result.project_risk.overall_score >= 80.0 and threshold <= 3:
            return ExitCode.POLICY_VIOLATION

        for finding in result.findings:
            f_severity = finding.severity.value.lower()
            if self.SEVERITY_ORDER.get(f_severity, 0) >= threshold:
                return ExitCode.POLICY_VIOLATION

        return ExitCode.SUCCESS
