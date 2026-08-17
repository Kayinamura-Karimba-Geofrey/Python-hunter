"""SARIF 2.1.0 Security Report Exporter."""

import json
from typing import Any

from python_hunter import __version__
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding


class SARIFExporter:
    """Exports normalized security findings to GitHub Code Scanning SARIF 2.1.0 format."""

    @staticmethod
    def export(findings: list[Finding]) -> dict[str, Any]:
        """Convert findings to SARIF 2.1.0 format dict."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for f in findings:
            if f.rule_id not in rules_map:
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {
                        "text": f"{f.description}\n\nRemediation:\n{f.remediation}",
                        "markdown": f"### {f.title}\n\n{f.description}\n\n**Remediation:**\n{f.remediation}",
                    },
                    "properties": {
                        "category": f.category.value,
                        "defaultSeverity": f.severity.value,
                        "tags": f.tags or [f.category.value.lower()],
                    },
                }

            sarif_level = "note"
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                sarif_level = "error"
            elif f.severity == Severity.MEDIUM:
                sarif_level = "warning"

            line_start = f.location.line_start if f.location else 1
            col_start = f.location.column_start if f.location else 1

            res = {
                "ruleId": f.rule_id,
                "ruleIndex": list(rules_map.keys()).index(f.rule_id),
                "level": sarif_level,
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": line_start,
                                "startColumn": col_start,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": f.fingerprint,
                },
                "properties": {
                    "riskScore": f.risk_score,
                    "exposure": f.exposure.value,
                    "reachability": f.reachability.value,
                    "lifecycleState": f.lifecycle_state.value,
                },
            }
            results.append(res)

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Python Hunter",
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/Kayinamura-Karimba-Geofrey/Python-hunter",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_doc

    @classmethod
    def export_json(cls, findings: list[Finding], indent: int = 2) -> str:
        """Export SARIF formatted string JSON."""
        return json.dumps(cls.export(findings), indent=indent)
