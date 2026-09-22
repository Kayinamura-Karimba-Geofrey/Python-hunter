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

        langs = ", ".join(result.context.options.get("detected_languages", ["python"]))
        lines = [
            "──────────────────────────────────────────────",
            "          PYTHON HUNTER SECURITY SCAN         ",
            "──────────────────────────────────────────────",
            f" Target:       {target_name}",
            f" Languages:    {langs}",
            f" Scan ID:      {result.context.scan_id}",
            f" Attack Paths: {paths_count}",
            f" Project Risk: {risk_str} ({risk_score:.1f}/100)",
            "──────────────────────────────────────────────",
        ]
        malware_findings = [f for f in result.findings if getattr(f, "category", None) and f.category.value == "MALWARE_RISK"]
        if malware_findings:
            lines.append("──────────────────────────────────────────────")
            lines.append(f" [!] MALWARE DETECTED: {len(malware_findings)} PolinRider / Supply-Chain Threats")
            lines.append("──────────────────────────────────────────────")
            for f in malware_findings:
                lines.append(f"  • [{f.severity.value}] {f.title}")
                lines.append(f"    File:     {f.file_path}")
                if f.evidence:
                    lines.append(f"    Evidence: {f.evidence[:70]}")
            lines.append("──────────────────────────────────────────────")

        cleanup = result.context.options.get("cleanup_result")
        if cleanup:
            lines.append("──────────────────────────────────────────────")
            lines.append("        AUTOMATED DISINFECTION APPLIED        ")
            lines.append("──────────────────────────────────────────────")
            lines.append(f" VS Code Tasks Disinfected:   {cleanup.tasks_sanitized}")
            lines.append(f" VS Code Settings Sanitized:  {cleanup.settings_sanitized}")
            lines.append(f" Dropper Scripts Deleted:     {len(cleanup.droppers_deleted)}")
            lines.append(f" Trojan Fonts Deleted:        {len(cleanup.trojan_fonts_deleted)}")
            lines.append(f" Build Configurations Cleaned:{len(cleanup.build_configs_cleaned)}")
            if cleanup.gitignore_cleaned:
                lines.append(" .gitignore Rules Restored:   YES")
            lines.append("──────────────────────────────────────────────")

        if result.exit_code != 0:
            lines.append(" Result:       [!] SECURITY POLICY VIOLATION FAILED")
        else:
            lines.append(" Result:       [✓] SECURITY SCAN PASSED")
        lines.append("──────────────────────────────────────────────")
        return "\n".join(lines)


class JsonRenderer(OutputRenderer):
    """Renders structured JSON report output."""

    def render(self, result: ScanResult) -> str:
        cleanup = result.context.options.get("cleanup_result")
        cleanup_data = None
        if cleanup:
            cleanup_data = {
                "tasks_sanitized": cleanup.tasks_sanitized,
                "settings_sanitized": cleanup.settings_sanitized,
                "droppers_deleted": cleanup.droppers_deleted,
                "trojan_fonts_deleted": cleanup.trojan_fonts_deleted,
                "build_configs_cleaned": cleanup.build_configs_cleaned,
                "gitignore_cleaned": cleanup.gitignore_cleaned,
            }

        data = {
            "scan_id": result.context.scan_id,
            "target": result.context.target.source if result.context.target else "",
            "target_type": result.context.target.target_type.value if result.context.target else "",
            "risk_score": result.project_risk.overall_score if result.project_risk else 0.0,
            "attack_paths_count": len(result.attack_paths),
            "findings_count": len(result.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file_path": f.file_path,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
            "cleanup": cleanup_data,
            "exit_code": result.exit_code,
        }
        return json.dumps(data, indent=2)
