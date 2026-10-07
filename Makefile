.PHONY: dev test test-fast lint typecheck benchmark dashboard api clean

PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

## dev: create .venv and install the package with API and dev extras
dev: $(BIN)/python
	$(BIN)/pip install -e ".[dev]"
	$(BIN)/pre-commit install

## test: run the full test suite with coverage
test:
	$(BIN)/pytest

## test-fast: run unit tests only, without coverage
test-fast:
	$(BIN)/pytest tests/unit -o addopts="" -q

## benchmark: run rule precision/recall benchmarks
benchmark:
	$(BIN)/pytest tests/benchmarks -o addopts="" -q

## lint: check style and lint rules
lint:
	$(BIN)/ruff check src tests

## typecheck: run mypy over the package
typecheck:
	$(BIN)/mypy src

## api: run the REST API locally (needs PYH_API_USERNAME and PYH_API_PASSWORD_HASH to log in)
api:
	$(BIN)/uvicorn python_hunter.application.api.app:app --reload

## dashboard: install and start the React dashboard dev server
dashboard:
	cd apps/dashboard && npm ci && npm run dev

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
