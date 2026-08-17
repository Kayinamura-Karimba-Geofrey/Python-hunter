# Python Hunter

**Python Security & Code Intelligence Platform**

[![Python 3.12](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: MyPy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)

---

## Overview

**Python Hunter** is an enterprise-grade Python Security & Code Intelligence Platform designed to analyze Python repositories for security vulnerabilities, malicious or suspicious code, dependency risks, secret leakages, Git history regressions, and software supply-chain attacks.

Built adhering strictly to **Clean Architecture**, **Domain-Driven Design (DDD)**, and **SOLID** principles, Python Hunter operates both as a fast local CLI scanner and a centralized multi-tenant REST API with asynchronous background processing.

---

## Key Capabilities

* **Multi-Layer Analysis Pipeline:** Integrates AST parsing, data-flow (taint analysis), regex/entropy secret detection, dependency tree auditing, Git diff tracking, and behavioral supply-chain risk scoring.
* **Declarative Security Rules:** Taxonomically organized security rules mapped to **CWE** and **OWASP Top 10**.
* **Standards Compliant Outputs:** Export findings to **SARIF v2.1.0**, **CycloneDX / SPDX SBOM**, **HTML**, and **JSON**.
* **Untrusted Input Sandboxing:** Guards against Zip bombs, path traversals, CPU starvation, and untrusted `setup.py` execution.

---

## Quickstart

```bash
# Clone the repository
git clone https://github.com/your-org/python-hunter.git
cd python-hunter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## Architecture & Documentation

Detailed architecture specifications, component designs, REST API specs, and development roadmaps are available in the [docs](docs/) directory.

* [Architecture Specification](docs/architecture/)
* [API Guide](docs/api/)
* [CLI Reference](docs/cli/)
* [Rule Taxonomy](docs/rules/)
* [Contributing Guide](CONTRIBUTING.md)

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
# Python-hunter
