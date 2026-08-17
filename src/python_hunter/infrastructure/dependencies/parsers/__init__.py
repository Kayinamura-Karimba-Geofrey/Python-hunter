"""Manifest Parsers Registry and Factories."""

from python_hunter.infrastructure.dependencies.parsers.base import BaseManifestParser
from python_hunter.infrastructure.dependencies.parsers.pipfile import PipfileParser
from python_hunter.infrastructure.dependencies.parsers.poetry_lock import PoetryLockParser
from python_hunter.infrastructure.dependencies.parsers.pyproject import PyProjectParser
from python_hunter.infrastructure.dependencies.parsers.requirements import RequirementsParser
from python_hunter.infrastructure.dependencies.parsers.setuptools import SetuptoolsParser
from python_hunter.infrastructure.dependencies.parsers.uv_lock import UVLockParser


def get_all_manifest_parsers() -> list[BaseManifestParser]:
    """Return instances of all supported manifest parsers."""
    return [
        RequirementsParser(),
        PyProjectParser(),
        PipfileParser(),
        PoetryLockParser(),
        UVLockParser(),
        SetuptoolsParser(),
    ]


__all__ = [
    "BaseManifestParser",
    "RequirementsParser",
    "PyProjectParser",
    "PipfileParser",
    "PoetryLockParser",
    "UVLockParser",
    "SetuptoolsParser",
    "get_all_manifest_parsers",
]
