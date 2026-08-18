"""CSV Security Report Exporter."""

import csv
import io
from typing import Any

from python_hunter.domain.reporting.models import SecurityReport
from python_hunter.infrastructure.reporting.base import BaseReporter, ReporterRegistry
from python_hunter.infrastructure.reporting.redaction import SecretRedactor


class CsvReporter(BaseReporter):
    """Exports finding records into structured CSV format."""

    def render(self, report: SecurityReport, options: dict[str, Any] | None = None) -> str:
        """Render SecurityReport findings into CSV string."""
        opts = options or {}
        redact = opts.get("redact_secrets", True)
        findings = SecretRedactor.redact_findings(report.findings, enabled=redact)

        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow(
            [
                "finding_id",
                "rule_id",
                "severity",
                "confidence",
                "risk_score",
                "status",
                "file",
                "line",
                "component",
                "category",
                "title",
            ]
        )

        for f in findings:
            parts = [p for p in f.file_path.replace("\\", "/").split("/") if p and p != "."]
            comp = parts[0] if len(parts) > 1 else ("root" if parts else "default")
            line_no = f.location.line_start if f.location else 0

            writer.writerow(
                [
                    f.fingerprint,
                    f.rule_id,
                    f.severity.value,
                    f.confidence.value,
                    f.risk_score,
                    f.lifecycle_state.value,
                    f.file_path,
                    line_no,
                    comp,
                    f.category.value,
                    f.title,
                ]
            )

        return output.getvalue()


ReporterRegistry.register("csv", CsvReporter)
