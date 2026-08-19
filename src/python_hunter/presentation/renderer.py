"""Terminal and JSON Output Renderers implementation."""

import json
from typing import Any
from python_hunter.application.orchestrator.scan_context import ScanResult


class OutputRenderer:
    """Base interface for CLI Output Renderers."""

    def render(self, result: ScanResult) -> str:
        raise NotImplementedError


class TerminalRenderer(OutputRenderer):
    """Renders professional rich colored terminal output summary."""

    def render(self, result: ScanResult) -> str:
        target_name = result.context.target.source if result.context.target else "Unknown"
        risk_score = result.project_risk.overall_score if result.project_risk else 0.0
        risk_str = "HIGH" if risk_score >= 70.0 else ("MEDIUM" if risk_score >= 40.0 else "LOW")
        paths_count = len(result.attack_paths)

        lines = [
            "──────────────────────────────────────────────",
            "          PYTHON HUNTER SECURITY SCAN         ",
            "──────────────────────────────────────────────",
            f" Target:       {target_name}",
            f" Scan ID:      {result.context.scan_id}",
            f" Attack Paths: {paths_count}",
            f" Project Risk: {risk_str} ({risk_score:.1f}/100)",
            "──────────────────────────────────────────────",
        ]
        if result.exit_code != 0:
            lines.append(" Result:       [!] SECURITY POLICY VIOLATION FAILED")
        else:
            lines.append(" Result:       [✓] SECURITY SCAN PASSED")
        lines.append("──────────────────────────────────────────────")
        return "\n".join(lines)


class JsonRenderer(OutputRenderer):
    """Renders structured JSON report output."""

    def render(self, result: ScanResult) -> str:
        data = {
            "scan_id": result.context.scan_id,
            "target": result.context.target.source if result.context.target else "",
            "target_type": result.context.target.target_type.value if result.context.target else "",
            "risk_score": result.project_risk.overall_score if result.project_risk else 0.0,
            "attack_paths_count": len(result.attack_paths),
            "findings_count": len(result.findings),
            "exit_code": result.exit_code,
        }
        return json.dumps(data, indent=2)
