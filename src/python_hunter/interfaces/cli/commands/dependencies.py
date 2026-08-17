"""CLI Command Handler for Dependency & Supply-Chain Analysis."""

import json
import sys
from python_hunter.application.use_cases.analyze_dependencies import AnalyzeDependenciesUseCase
from python_hunter.domain.dependencies.models import DependencyInventory
from python_hunter.domain.findings.finding import Finding


def run_dependencies_command(args: list[str]) -> int:
    """Execute python-hunter dependencies command."""
    import argparse

    parser = argparse.ArgumentParser(prog="python-hunter dependencies", description="Analyze project dependencies and supply-chain security.")
    parser.add_argument("target", nargs="?", default=".", help="Target project path or manifest file")
    parser.add_argument("--tree", action="store_true", help="Display ascii dependency tree")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (text, json)")

    parsed_args = parser.parse_args(args)
    use_case = AnalyzeDependenciesUseCase()
    result = use_case.execute(parsed_args.target)

    if parsed_args.format == "json":
        _output_json(result)
    else:
        _output_text(result, show_tree=parsed_args.tree)

    return 0


def _output_json(result: dict[str, object]) -> None:
    inventory: DependencyInventory = result["inventory"]  # type: ignore
    findings: list[Finding] = result["findings"]  # type: ignore

    out = {
        "project_name": result["project_name"],
        "project_path": result["project_path"],
        "package_manager": inventory.package_manager.value,
        "manifests": inventory.manifests,
        "counts": {
            "total": inventory.total_count,
            "direct": inventory.direct_count,
            "transitive": inventory.transitive_count,
            "development": inventory.development_count,
            "optional": inventory.optional_count,
            "vcs": inventory.vcs_count,
            "url": inventory.url_count,
            "local": inventory.local_count,
        },
        "findings_count": len(findings),
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "location": {"line_start": f.location.line_start, "line_end": f.location.line_end} if f.location else None,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    print(json.dumps(out, indent=2))


def _output_text(result: dict[str, object], show_tree: bool = False) -> None:
    inventory: DependencyInventory = result["inventory"]  # type: ignore
    findings: list[Finding] = result["findings"]  # type: ignore

    print("==================================================")
    print("Python Hunter Dependency Analysis")
    print("==================================================")
    print(f"Project:            {result['project_name']}")
    print(f"Package Manager:    {inventory.package_manager.value}")
    print(f"Manifests Scanned:  {len(inventory.manifests)}")
    print(f"Direct Deps:        {inventory.direct_count}")
    print(f"Transitive Deps:    {inventory.transitive_count}")
    print(f"Dev Deps:           {inventory.development_count}")
    print(f"VCS Deps:           {inventory.vcs_count}")
    print(f"URL Deps:           {inventory.url_count}")
    print(f"Findings Identified:{len(findings)}")
    print("==================================================\n")

    if show_tree and inventory.graph.root_dependencies:
        print("Dependency Tree:")
        print(inventory.graph.to_tree_str())
        print("──────────────────────────────────────────────────\n")

    if not findings:
        print("No dependency or supply-chain security issues detected.")
        return

    for idx, finding in enumerate(findings, start=1):
        print(f"[{idx}] Finding: {finding.rule_id} ({finding.severity.value.upper()})")
        print(f"Title:       {finding.title}")
        loc_str = f"{finding.file_path}:{finding.location.line_start}" if finding.location else finding.file_path
        print(f"Location:    {loc_str}")
        print(f"Description: {finding.description}")
        print(f"Evidence:    {finding.evidence}")
        print("Remediation: ")
        print(f"  {finding.remediation}")
        print("──────────────────────────────────────────────────")
