"""Architectural Enforcement Tests."""

import importlib
import pkgutil
import unittest
import python_hunter.domain


class TestArchitectureBoundaries(unittest.TestCase):
    """Test suite ensuring strict Clean Architecture dependency direction."""

    FORBIDDEN_DOMAIN_IMPORTS = (
        "python_hunter.infrastructure",
        "python_hunter.interfaces",
        "fastapi",
        "sqlalchemy",
        "celery",
        "redis",
        "click",
    )

    def test_domain_does_not_import_forbidden_modules(self) -> None:
        """Enforce that core domain packages do not import infrastructure or delivery frameworks."""
        domain_pkg = python_hunter.domain
        for _, module_name, _ in pkgutil.walk_packages(domain_pkg.__path__, prefix="python_hunter.domain."):
            module = importlib.import_module(module_name)
            with open(module.__file__, "r", encoding="utf-8") as f:
                code_text = f.read()

            for forbidden in self.FORBIDDEN_DOMAIN_IMPORTS:
                self.assertNotIn(
                    f"import {forbidden}",
                    code_text,
                    f"Architecture Violation: Domain module {module_name} imports forbidden dependency '{forbidden}'",
                )
                self.assertNotIn(
                    f"from {forbidden}",
                    code_text,
                    f"Architecture Violation: Domain module {module_name} imports forbidden dependency '{forbidden}'",
                )


if __name__ == "__main__":
    unittest.main()
