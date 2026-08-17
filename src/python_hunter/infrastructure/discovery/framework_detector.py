"""Static Framework and Package Layout Detector."""

import os
from typing import Any
from python_hunter.domain.discovery.enums import PackageLayout, ProjectType


class FrameworkDetector:
    """Static framework, test runner, package layout, and project type classifier."""

    KNOWN_WEB_FRAMEWORKS = {
        "django": "Django",
        "flask": "Flask",
        "fastapi": "FastAPI",
        "starlette": "Starlette",
        "djangorestframework": "Django REST Framework",
        "tornado": "Tornado",
        "bottle": "Bottle",
        "pyramid": "Pyramid",
    }

    KNOWN_CLI_FRAMEWORKS = {
        "click": "Click",
        "typer": "Typer",
        "argparse": "argparse",
        "fire": "Fire",
    }

    KNOWN_ASYNC_FRAMEWORKS = {
        "celery": "Celery",
        "rq": "RQ",
        "dramatiq": "Dramatiq",
    }

    KNOWN_TEST_FRAMEWORKS = {
        "pytest": "pytest",
        "unittest": "unittest",
        "nose": "nose",
        "doctest": "doctest",
    }

    @classmethod
    def detect_frameworks(cls, dependencies: list[str], file_contents_sample: str = "") -> tuple[list[str], list[str]]:
        """Detect web/CLI/background frameworks and test runners statically."""
        detected_frameworks: set[str] = set()
        detected_test_frameworks: set[str] = set()

        deps_lower = {d.lower() for d in dependencies}

        # Check dependencies
        for dep_key, name in cls.KNOWN_WEB_FRAMEWORKS.items():
            if dep_key in deps_lower:
                detected_frameworks.add(name)

        for dep_key, name in cls.KNOWN_CLI_FRAMEWORKS.items():
            if dep_key in deps_lower:
                detected_frameworks.add(name)

        for dep_key, name in cls.KNOWN_ASYNC_FRAMEWORKS.items():
            if dep_key in deps_lower:
                detected_frameworks.add(name)

        for dep_key, name in cls.KNOWN_TEST_FRAMEWORKS.items():
            if dep_key in deps_lower:
                detected_test_frameworks.add(name)

        # Static import inspection in file sample
        if file_contents_sample:
            sample_lower = file_contents_sample.lower()
            if "import django" in sample_lower or "from django" in sample_lower:
                detected_frameworks.add("Django")
            if "import fastapi" in sample_lower or "from fastapi" in sample_lower:
                detected_frameworks.add("FastAPI")
            if "import flask" in sample_lower or "from flask" in sample_lower:
                detected_frameworks.add("Flask")
            if "import pytest" in sample_lower or "from pytest" in sample_lower:
                detected_test_frameworks.add("pytest")
            if "import unittest" in sample_lower or "from unittest" in sample_lower:
                detected_test_frameworks.add("unittest")

        return sorted(list(detected_frameworks)), sorted(list(detected_test_frameworks))

    @classmethod
    def detect_package_layout(cls, directories: list[str], py_files: list[str]) -> PackageLayout:
        """Classify package layout (SRC_LAYOUT vs FLAT_LAYOUT vs SINGLE_MODULE)."""
        has_src = any(d == "src" or d.startswith(f"src{os.sep}") for d in directories)
        if has_src:
            return PackageLayout.SRC_LAYOUT

        if len(py_files) == 1:
            return PackageLayout.SINGLE_MODULE

        if py_files:
            return PackageLayout.FLAT_LAYOUT

        return PackageLayout.UNKNOWN

    @classmethod
    def detect_project_type(
        cls,
        frameworks: list[str],
        has_pyproject: bool,
        has_setup: bool,
        package_layout: PackageLayout,
        entry_points: list[str],
    ) -> tuple[ProjectType, float]:
        """Classify project type and confidence score."""
        web_fw = {"Django", "Flask", "FastAPI", "Starlette", "Django REST Framework", "Tornado", "Pyramid"}
        if any(f in web_fw for f in frameworks):
            return ProjectType.WEB_APPLICATION, 0.90

        cli_fw = {"Click", "Typer", "Fire"}
        if any(f in cli_fw for f in frameworks) or any("cli" in ep.lower() for ep in entry_points):
            return ProjectType.CLI_APPLICATION, 0.85

        if has_pyproject or has_setup:
            if package_layout == PackageLayout.SRC_LAYOUT:
                return ProjectType.PACKAGE, 0.85
            return ProjectType.LIBRARY, 0.75

        if entry_points:
            return ProjectType.APPLICATION, 0.70

        return ProjectType.UNKNOWN, 0.30
