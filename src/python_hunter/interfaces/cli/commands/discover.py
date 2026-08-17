"""CLI Command handler for Project Discovery."""

import json
import sys
from typing import Any
from python_hunter.application.use_cases.discover_project import DiscoverProjectUseCase
from python_hunter.domain.discovery.manifest import ProjectManifest


def format_text_manifest(manifest: ProjectManifest) -> str:
    """Format ProjectManifest into clean human-readable text."""
    lines: list[str] = []
    lines.append("\n=== Python Hunter Project Discovery ===")
    lines.append(f"Project:            {manifest.project_name}")
    lines.append(f"Root:               {manifest.root_path}")
    lines.append(f"Project Type:       {manifest.project_type.value} (Confidence: {manifest.type_confidence:.2f})")
    lines.append(f"Package Layout:     {manifest.package_layout.value}")
    lines.append(f"Python Files:       {manifest.statistics.python_files}")
    lines.append(f"Configuration Files:{manifest.statistics.configuration_files}")
    lines.append(f"Dependency Files:   {manifest.statistics.dependency_files}")
    lines.append(f"Test Files:         {manifest.statistics.test_files}")
    lines.append(f"Total Files:        {manifest.statistics.total_files}")
    lines.append(f"Total Directories:  {manifest.statistics.total_directories}")
    lines.append(f"Ignored Files:      {manifest.statistics.ignored_files}")
    lines.append(f"Git Repository:     {'Yes' if manifest.is_git_repository else 'No'}")
    lines.append(f"Docker / Containers:{'Yes' if manifest.has_docker else 'No'}")
    lines.append(f"CI/CD Configured:   {'Yes' if manifest.has_ci_cd else 'No'}")
    lines.append(f"Virtual Env:        {'Yes' if manifest.has_virtual_env else 'No'}")

    if manifest.frameworks:
        lines.append(f"Frameworks:         {', '.join(manifest.frameworks)}")
    if manifest.test_frameworks:
        lines.append(f"Test Frameworks:    {', '.join(manifest.test_frameworks)}")
    if manifest.entry_points:
        lines.append(f"Entry Points:       {', '.join(manifest.entry_points)}")

    lines.append("Discovery completed successfully.\n")
    return "\n".join(lines)


def format_json_manifest(manifest: ProjectManifest) -> str:
    """Format ProjectManifest into structured JSON."""
    data: dict[str, Any] = {
        "project_name": manifest.project_name,
        "root_path": manifest.root_path,
        "project_type": manifest.project_type.value,
        "type_confidence": manifest.type_confidence,
        "package_layout": manifest.package_layout.value,
        "is_git_repository": manifest.is_git_repository,
        "has_docker": manifest.has_docker,
        "has_ci_cd": manifest.has_ci_cd,
        "has_virtual_env": manifest.has_virtual_env,
        "entry_points": manifest.entry_points,
        "frameworks": manifest.frameworks,
        "test_frameworks": manifest.test_frameworks,
        "dependency_files": manifest.dependency_files,
        "configuration_files": manifest.configuration_files,
        "ci_files": manifest.ci_files,
        "container_files": manifest.container_files,
        "statistics": {
            "total_files": manifest.statistics.total_files,
            "python_files": manifest.statistics.python_files,
            "configuration_files": manifest.statistics.configuration_files,
            "dependency_files": manifest.statistics.dependency_files,
            "test_files": manifest.statistics.test_files,
            "total_bytes": manifest.statistics.total_bytes,
            "ignored_files": manifest.statistics.ignored_files,
            "total_directories": manifest.statistics.total_directories,
        },
    }
    return json.dumps(data, indent=2)


def run_discover_command(target_path: str, output_format: str = "text") -> int:
    """Execute discover CLI command."""
    try:
        use_case = DiscoverProjectUseCase()
        manifest = use_case.discover(target_path)

        if output_format.lower() == "json":
            sys.stdout.write(format_json_manifest(manifest) + "\n")
        else:
            sys.stdout.write(format_text_manifest(manifest) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"Error during project discovery: {e}\n")
        return 1
