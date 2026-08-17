# Contributing to Python Hunter

Thank you for your interest in contributing to **Python Hunter**!

## Development Workflow

1. Fork the repository and create your feature branch from `main`.
2. Ensure Python 3.12+ is installed on your local environment.
3. Set up the development environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev,api,worker]"
   pre-commit install
   ```

## Code Standards

* **Strict Static Typing:** All code must pass `mypy --strict` with zero type errors or `type: ignore` suppressions.
* **Formatting & Linting:** All code must pass `ruff check` and `ruff format`.
* **Testing:** Every feature must include corresponding unit and/or integration tests under `tests/`. Minimum 90% codebase test coverage is required.

## Pull Request Guidelines

1. Open an issue describing the proposed change or bug fix.
2. Ensure all CI pipeline checks pass cleanly before requesting review.
3. Keep commits atomic, well-described, and signed if possible.
