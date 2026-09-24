"""Static PyPI Supply-Chain Security & Setup.py Malicious Hook Analyzer."""

import ast
import json
import os
import re
from typing import Any, List, Optional, Set, Tuple

from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding


class PyPISupplyChainAnalyzer:
    """Statically inspects PyPI package setup scripts, packaging hooks, obfuscation, exfiltration, and typosquatting signals."""

    POPULAR_PYPI_PACKAGES: Set[str] = {
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "colorama",
        "pydantic",
        "cryptography",
        "flask",
        "django",
        "pytest",
        "boto3",
        "scipy",
        "setuptools",
        "wheel",
        "pip",
        "click",
        "jinja2",
        "sqlalchemy",
        "fastapi",
        "black",
        "celery",
        "paramiko",
        "fabric",
        "scikit-learn",
        "torch",
        "transformers",
        "redis",
        "pillow",
        "matplotlib",
        "beautifulsoup4",
        "virtualenv",
        "pipenv",
        "poetry",
        "psutil",
        "certifi",
        "idna",
        "charset-normalizer",
    }

    # Known exfiltration endpoints & webhook patterns frequently used by PyPI malware
    MALICIOUS_ENDPOINTS: List[Tuple[str, str]] = [
        ("DISCORD_WEBHOOK", r"https://(?:discord(?:app)?\.com)/api/webhooks/"),
        ("TELEGRAM_BOT", r"https://api\.telegram\.org/bot"),
        ("WEBHOOK_SITE", r"https://webhook\.site/"),
        ("TRANSFER_SH", r"https://transfer\.sh/"),
        ("NGROK_TUNNEL", r"https://[a-zA-Z0-9-]+\.(?:ngrok-free\.app|ngrok\.io)"),
        ("PASTEBIN_RAW", r"https://pastebin\.com/raw/"),
    ]

    # Obfuscation and dynamic execution patterns
    SUSPICIOUS_EXEC_PATTERNS: List[Tuple[str, str]] = [
        ("BASE64_EXEC", r"(?:eval|exec)\s*\(\s*(?:base64\.)?b64decode\("),
        ("HEX_EXEC", r"(?:eval|exec)\s*\(\s*(?:bytes\.)?fromhex\("),
        ("ZLIB_EXEC", r"(?:eval|exec)\s*\(\s*zlib\.decompress\("),
        ("CODECS_EXEC", r"(?:eval|exec)\s*\(\s*codecs\.decode\("),
        ("CHR_JOIN_EXEC", r"(?:eval|exec)\s*\(\s*['\"]\s*\.join\(\s*(?:chr\(|\[chr\()"),
        ("RAW_SOCKET_CONNECT", r"socket\.socket\(.*?\)\s*\.\s*connect\("),
    ]

    def analyze_workspace(self, workspace_path: str) -> list[Finding]:
        """Analyzes a project workspace for PyPI supply chain threats, malicious setup hooks, and typosquatting."""
        findings: list[Finding] = []

        # 1. Analyze setup.py and packaging files
        setup_files = ["setup.py", "setup_legacy.py"]
        for setup_file in setup_files:
            setup_path = os.path.join(workspace_path, setup_file)
            if os.path.exists(setup_path):
                findings.extend(self._analyze_setup_py(setup_path, rel_path=setup_file))

        # 2. Analyze requirements and dependency manifests for typosquatting
        findings.extend(self._analyze_dependencies(workspace_path))

        # 3. Analyze top-level package __init__.py files for disguised dropper/exfiltration payloads
        findings.extend(self._analyze_init_scripts(workspace_path))

        return findings

    def _analyze_setup_py(self, setup_path: str, rel_path: str) -> list[Finding]:
        """Inspects setup.py for malicious cmdclass overrides, module-level execution, obfuscation, or exfiltration."""
        findings: list[Finding] = []
        try:
            with open(setup_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return findings

        # Check regex-based suspicious execution patterns
        for cat_name, pat in self.SUSPICIOUS_EXEC_PATTERNS:
            match = re.search(pat, content, re.IGNORECASE)
            if match:
                lineno = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="PYHUNTER-PYPI-OBFUSC-001",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        title=f"Obfuscated Dynamic Execution in Setup Script ({cat_name})",
                        description=(
                            f"Setup script '{rel_path}' contains suspicious dynamic code execution "
                            f"pattern ({cat_name}) commonly observed in PyPI droppers and trojans."
                        ),
                        file_path=rel_path,
                        location=Location(lineno, 1),
                        evidence=match.group(0),
                        remediation="Remove dynamic exec/eval payloads from setup and build scripts.",
                    )
                )

        # Check exfiltration endpoints
        for ep_name, pat in self.MALICIOUS_ENDPOINTS:
            match = re.search(pat, content)
            if match:
                lineno = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="PYHUNTER-PYPI-EXFIL-001",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        title=f"Malicious Exfiltration Endpoint in Setup Script ({ep_name})",
                        description=(
                            f"Setup script '{rel_path}' references known data exfiltration / C2 endpoint "
                            f"pattern ({ep_name}): {match.group(0)}"
                        ),
                        file_path=rel_path,
                        location=Location(lineno, 1),
                        evidence=match.group(0),
                        remediation="Audit outbound network requests in packaging scripts and verify package authenticity.",
                    )
                )

        # Static AST analysis for packaging hooks and install-time execution
        try:
            tree = ast.parse(content, filename=setup_path)
            findings.extend(self._analyze_setup_ast(tree, rel_path, content))
        except Exception:
            pass

        return findings

    def _analyze_setup_ast(self, tree: ast.AST, rel_path: str, content: str) -> list[Finding]:
        """Performs structural AST checks on setup.py for install hooks and module-level process execution."""
        findings: list[Finding] = []
        suspicious_classes: set[str] = set()

        for node in ast.walk(tree):
            # Check for custom classes subclassing install, develop, or egg_info
            if isinstance(node, ast.ClassDef):
                base_names = [self._get_name(b) for b in node.bases]
                hook_bases = {"install", "develop", "egg_info", "build_py", "PostInstallCommand", "PreInstallCommand"}
                if any(any(h.lower() in b.lower() for h in hook_bases) for b in base_names):
                    # Check if class overrides run() or __init__() and has dangerous calls
                    has_dangerous_call = False
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            for subnode in ast.walk(item):
                                if isinstance(subnode, ast.Call):
                                    func_name = self._get_name(subnode.func)
                                    if self._is_dangerous_call(func_name):
                                        has_dangerous_call = True
                                        findings.append(
                                            Finding(
                                                rule_id="PYHUNTER-PYPI-SETUP-001",
                                                severity=Severity.CRITICAL,
                                                confidence=Confidence.HIGH,
                                                category=Category.SUPPLY_CHAIN,
                                                title=f"Malicious Installation Hook: {node.name}.{item.name}",
                                                description=(
                                                    f"Class '{node.name}' subclasses setuptools installation command and executes "
                                                    f"potentially malicious operations ({func_name}) during package installation."
                                                ),
                                                file_path=rel_path,
                                                location=Location(item.lineno, item.col_offset + 1),
                                                evidence=f"class {node.name} -> def {item.name}: calls {func_name}()",
                                                remediation="Do not execute shell commands or network requests during package installation.",
                                            )
                                        )
                    if has_dangerous_call:
                        suspicious_classes.add(node.name)

            # Check for direct module-level execution (outside of functions)
            if isinstance(node, ast.Call):
                func_name = self._get_name(node.func)
                if self._is_dangerous_call(func_name):
                    # Check if this call is at top level
                    if node in tree.body:  # type: ignore[attr-defined]
                        findings.append(
                            Finding(
                                rule_id="PYHUNTER-PYPI-SETUP-001",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category=Category.SUPPLY_CHAIN,
                                title=f"Top-Level Execution in Packaging Script: {func_name}",
                                description=(
                                    f"Setup script '{rel_path}' executes dangerous operation '{func_name}' directly at import time. "
                                    "This runs automatically whenever the package is inspected or installed."
                                ),
                                file_path=rel_path,
                                location=Location(node.lineno, node.col_offset + 1),
                                evidence=f"Top-level call: {func_name}()",
                                remediation="Remove side-effects and dangerous top-level execution from setup.py.",
                            )
                        )

        return findings

    def _analyze_dependencies(self, workspace_path: str) -> list[Finding]:
        """Extracts dependency names from requirements.txt, pyproject.toml, and Pipfile and detects typosquatting."""
        findings: list[Finding] = []
        deps_found: list[Tuple[str, str, int]] = []  # (dep_name, source_file, line_num)

        # 1. requirements.txt / requirements-dev.txt
        req_files = ["requirements.txt", "requirements-dev.txt", "requirements.in"]
        for rf in req_files:
            p = os.path.join(workspace_path, rf)
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            line = line.strip()
                            if not line or line.startswith("#") or line.startswith("-"):
                                continue
                            match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                            if match:
                                deps_found.append((match.group(1).lower(), rf, lineno))
                except Exception:
                    pass

        # 2. pyproject.toml
        pyproj_path = os.path.join(workspace_path, "pyproject.toml")
        if os.path.exists(pyproj_path):
            try:
                with open(pyproj_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Simple regex extraction of dependencies list in [project.dependencies] or [tool.poetry.dependencies]
                    for match in re.finditer(r'["\']([a-zA-Z0-9_-]+)(?:[><=~!^].*?)?["\']', content):
                        dep_candidate = match.group(1).lower()
                        lineno = content[: match.start()].count("\n") + 1
                        deps_found.append((dep_candidate, "pyproject.toml", lineno))
            except Exception:
                pass

        # Check all extracted dependencies against popular PyPI packages for typosquatting
        seen_typos: set[Tuple[str, str]] = set()
        for dep_name, source_file, lineno in deps_found:
            for pop_pkg in self.POPULAR_PYPI_PACKAGES:
                if dep_name != pop_pkg and self._is_typosquat(dep_name, pop_pkg):
                    key = (dep_name, pop_pkg)
                    if key not in seen_typos:
                        seen_typos.add(key)
                        findings.append(
                            Finding(
                                rule_id="PYHUNTER-PYPI-TYPO-001",
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category=Category.SUPPLY_CHAIN,
                                title=f"Potential PyPI Typosquatting Package: {dep_name}",
                                description=(
                                    f"Dependency '{dep_name}' in '{source_file}' closely resembles popular PyPI package '{pop_pkg}'. "
                                    "Attackers publish typosquatted packages to execute trojans upon installation."
                                ),
                                file_path=source_file,
                                location=Location(lineno, 1),
                                evidence=f"Package: {dep_name} (Similar to: {pop_pkg})",
                                remediation=f"Confirm if '{dep_name}' was intended or replace with official '{pop_pkg}'.",
                            )
                        )

        return findings

    def _analyze_init_scripts(self, workspace_path: str) -> list[Finding]:
        """Inspects package __init__.py files for dropper or webhook patterns."""
        findings: list[Finding] = []
        for root, dirs, files in os.walk(workspace_path):
            # Skip hidden and test directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("tests", "venv", ".venv", "node_modules")]
            for file_name in files:
                if file_name == "__init__.py":
                    init_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(init_path, workspace_path)
                    try:
                        with open(init_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        # Check for obfuscated execution patterns
                        for cat_name, pat in self.SUSPICIOUS_EXEC_PATTERNS:
                            match = re.search(pat, content, re.IGNORECASE)
                            if match:
                                lineno = content[: match.start()].count("\n") + 1
                                findings.append(
                                    Finding(
                                        rule_id="PYHUNTER-PYPI-OBFUSC-001",
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.HIGH,
                                        category=Category.SUPPLY_CHAIN,
                                        title=f"Obfuscated Execution in Package Init ({cat_name})",
                                        description=f"Package init file '{rel_path}' contains suspicious obfuscated code execution ({cat_name}).",
                                        file_path=rel_path,
                                        location=Location(lineno, 1),
                                        evidence=match.group(0),
                                        remediation="Audit package initialization and remove obfuscated payloads.",
                                    )
                                )

                        # Check for exfiltration endpoints
                        for ep_name, pat in self.MALICIOUS_ENDPOINTS:
                            match = re.search(pat, content)
                            if match:
                                lineno = content[: match.start()].count("\n") + 1
                                findings.append(
                                    Finding(
                                        rule_id="PYHUNTER-PYPI-EXFIL-001",
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.HIGH,
                                        category=Category.SUPPLY_CHAIN,
                                        title=f"Malicious Exfiltration Endpoint in Package Init ({ep_name})",
                                        description=f"Package init file '{rel_path}' references exfiltration endpoint ({ep_name}): {match.group(0)}",
                                        file_path=rel_path,
                                        location=Location(lineno, 1),
                                        evidence=match.group(0),
                                        remediation="Remove suspicious telemetry / exfiltration endpoints from package modules.",
                                    )
                                )
                    except Exception:
                        pass

        return findings

    @staticmethod
    def _is_dangerous_call(func_name: str) -> bool:
        """Determines if a function call performs shell execution, downloads, or process spawning."""
        dangerous_calls = {
            "system",
            "popen",
            "spawn",
            "run",
            "call",
            "check_call",
            "check_output",
            "urlopen",
            "urlretrieve",
            "get",
            "post",
            "exec",
            "eval",
            "compile",
            "fork",
        }
        leaf = func_name.split(".")[-1].lower()
        full = func_name.lower()
        if leaf in dangerous_calls:
            if any(mod in full for mod in ("os.", "subprocess.", "urllib.", "requests.", "posix.", "pty.")):
                return True
            if leaf in ("exec", "eval", "system"):
                return True
        return False

    @staticmethod
    def _get_name(node: ast.AST) -> str:
        """Helper to get dot-separated name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{PyPISupplyChainAnalyzer._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return PyPISupplyChainAnalyzer._get_name(node.func)
        return ""

    @staticmethod
    def _is_typosquat(name1: str, name2: str) -> bool:
        """Check for single-character edits, transpositions, or insertions/deletions between package names."""
        name1 = name1.lower()
        name2 = name2.lower()
        if name1 == name2 or abs(len(name1) - len(name2)) > 1:
            return False

        # Case 1: Same length (substitution or adjacent transposition)
        if len(name1) == len(name2):
            mismatches = [i for i, (a, b) in enumerate(zip(name1, name2)) if a != b]
            if len(mismatches) == 1:
                return True
            if len(mismatches) == 2:
                i, j = mismatches
                return j == i + 1 and name1[i] == name2[j] and name1[j] == name2[i]
            return False

        # Case 2: Length difference of 1 (insertion or deletion)
        short, long = (name1, name2) if len(name1) < len(name2) else (name2, name1)
        i, j, diffs = 0, 0, 0
        while i < len(short) and j < len(long):
            if short[i] == long[j]:
                i += 1
                j += 1
            else:
                diffs += 1
                if diffs > 1:
                    return False
                j += 1
        return True
