"""Pytest Configuration and Fixtures."""

import pytest
from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.projects.project import Project
from python_hunter.domain.projects.scan import Scan
from python_hunter.domain.projects.target_file import TargetFile
from python_hunter.infrastructure.config.settings import Settings


@pytest.fixture
def sample_project() -> Project:
    """Fixture providing a sample domain Project entity."""
    return Project(name="sample-target", root_path="/workspace/sample-target")


@pytest.fixture
def sample_scan(sample_project: Project) -> Scan:
    """Fixture providing a sample domain Scan aggregate root."""
    return Scan(project=sample_project)


@pytest.fixture
def sample_context(sample_project: Project, sample_scan: Scan) -> AnalysisContext:
    """Fixture providing a sample AnalysisContext."""
    files = [
        TargetFile(relative_path="main.py", size_bytes=150, mime_type="text/x-python", is_python=True),
        TargetFile(relative_path="utils.py", size_bytes=300, mime_type="text/x-python", is_python=True),
    ]
    return AnalysisContext(scan_id=sample_scan.id, project=sample_project, target_files=files)


@pytest.fixture
def default_settings() -> Settings:
    """Fixture providing default application Settings."""
    return Settings.load_from_env({})
