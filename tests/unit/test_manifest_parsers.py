"""Unit tests for static manifest parsers."""

import unittest
from python_hunter.infrastructure.dependencies.parsers import (
    PoetryLockParser,
    PyProjectParser,
    RequirementsParser,
    SetuptoolsParser,
)


class TestManifestParsers(unittest.TestCase):
    """Test suite for static dependency manifest parsers."""

    def test_requirements_parser(self) -> None:
        """Verify parsing of requirements.txt files."""
        content = """
        requests==2.31.0
        flask>=2.0.0
        git+https://github.com/example/lib.git@main#egg=example-lib
        https://example.com/pkg.tar.gz
        """
        parser = RequirementsParser()
        deps = parser.parse("requirements.txt", content)

        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        self.assertIn("example-lib", names)
        self.assertIn("pkg", names)

    def test_pyproject_parser(self) -> None:
        """Verify parsing of pyproject.toml files."""
        content = """
        [project]
        name = "foo"
        dependencies = [
            "pydantic>=2.0",
        ]
        """
        parser = PyProjectParser()
        deps = parser.parse("pyproject.toml", content)

        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "pydantic")
        self.assertEqual(deps[0].version_constraint, ">=2.0")

    def test_poetry_lock_parser(self) -> None:
        """Verify parsing of poetry.lock files."""
        content = """
        [[package]]
        name = "starlette"
        version = "0.36.3"
        category = "main"
        """
        parser = PoetryLockParser()
        deps = parser.parse("poetry.lock", content)

        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "starlette")
        self.assertEqual(deps[0].version, "0.36.3")

    def test_setuptools_ast_parser(self) -> None:
        """Verify static AST parsing of setup.py without code execution."""
        content = """
        from setuptools import setup

        setup(
            name="my-package",
            install_requires=[
                "requests>=2.25.0",
                "urllib3<2.0",
            ]
        )
        """
        parser = SetuptoolsParser()
        deps = parser.parse("setup.py", content)

        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("urllib3", names)


if __name__ == "__main__":
    unittest.main()
