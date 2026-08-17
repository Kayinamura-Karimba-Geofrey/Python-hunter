"""PEP 503 Package Name Normalization Engine."""

import re


def normalize_package_name(name: str) -> str:
    """Normalize a Python package name per PEP 503 specification.

    Replaces any run of '.', '-', or '_' with a single '-' and lowercases.
    """
    if not name:
        return ""
    return re.sub(r"[-_.]+", "-", name).lower()
