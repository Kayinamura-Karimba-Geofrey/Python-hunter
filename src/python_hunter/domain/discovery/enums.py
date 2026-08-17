"""Project Discovery Domain Enums."""

from enum import Enum


class ProjectType(str, Enum):
    """Classification of Python project architecture."""

    STANDARD_LIBRARY_PROJECT = "STANDARD_LIBRARY_PROJECT"
    PACKAGE = "PACKAGE"
    APPLICATION = "APPLICATION"
    WEB_APPLICATION = "WEB_APPLICATION"
    CLI_APPLICATION = "CLI_APPLICATION"
    LIBRARY = "LIBRARY"
    SINGLE_MODULE = "SINGLE_MODULE"
    UNKNOWN = "UNKNOWN"


class PackageLayout(str, Enum):
    """Python package structural layout."""

    SRC_LAYOUT = "SRC_LAYOUT"
    FLAT_LAYOUT = "FLAT_LAYOUT"
    NAMESPACE_PACKAGE = "NAMESPACE_PACKAGE"
    SINGLE_MODULE = "SINGLE_MODULE"
    UNKNOWN = "UNKNOWN"


class FileCategory(str, Enum):
    """File classification categories."""

    PYTHON_SOURCE = "PYTHON_SOURCE"
    PYTHON_STUB = "PYTHON_STUB"
    CONFIGURATION = "CONFIGURATION"
    DEPENDENCY_MANIFEST = "DEPENDENCY_MANIFEST"
    TEST = "TEST"
    DOCUMENTATION = "DOCUMENTATION"
    CI_CD = "CI_CD"
    CONTAINER = "CONTAINER"
    GIT_METADATA = "GIT_METADATA"
    ENV_FILE = "ENV_FILE"
    OTHER = "OTHER"


class DirectoryCategory(str, Enum):
    """Directory classification categories."""

    SOURCE = "SOURCE"
    TESTS = "TESTS"
    DOCUMENTATION = "DOCUMENTATION"
    CONFIGURATION = "CONFIGURATION"
    BUILD = "BUILD"
    DISTRIBUTION = "DISTRIBUTION"
    VIRTUAL_ENV = "VIRTUAL_ENV"
    CACHE = "CACHE"
    GIT_METADATA = "GIT_METADATA"
    CI_CD = "CI_CD"
    UNKNOWN = "UNKNOWN"
