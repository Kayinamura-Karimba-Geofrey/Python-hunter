"""LSP Security Analyzer Engine.

Performs real-time, in-editor security analysis across:
- Python AST security rules (eval, exec, subprocess, yaml, pickle, credentials)
- PolinRider / TasksJacker malware & build config injection signatures
- Secrets & leaked credentials in code, config, workflows, and .env files
- Dependency vulnerabilities & unpinned versions in requirements.txt, pyproject.toml, package.json
"""

import json
import os
import re
from typing import Any
import uuid

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.ast.models import ASTAnalysisSummary
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.dependencies.fixer import DependencyFixEngine
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.malware.analyzers.polinrider_detector import PolinRiderDetector
from python_hunter.domain.projects.project import Project
from python_hunter.domain.rules.engine import SecurityRuleEngine
from python_hunter.domain.secrets.engine import SecretDetectionEngine
from python_hunter.infrastructure.ast.parser import StandardASTParser
from python_hunter.interfaces.lsp.protocol import (
    CodeActionKind,
    DiagnosticSeverity,
    uri_to_path,
)
from python_hunter.rules.ast import get_default_registry


class LSPSecurityAnalyzer:
    """Performs real-time in-editor security linting and translates findings to LSP diagnostics."""

    PYTHON_RECOMMENDATIONS: dict[str, str] = DependencyFixEngine.DEFAULT_PINNED_VERSIONS
    NPM_RECOMMENDATIONS: dict[str, str] = {
        "lodash": "4.17.21",
        "express": "4.19.2",
        "axios": "1.6.8",
        "jsonwebtoken": "9.0.0",
        "semver": "7.5.4",
        "minimist": "1.2.8",
        "tar": "6.2.1",
        "ws": "8.17.1",
        "undici": "5.28.4",
        "next": "14.1.1",
    }

    def __init__(self) -> None:
        self.parser = StandardASTParser()
        self.rule_engine = SecurityRuleEngine(registry=get_default_registry())
        self.secret_engine = SecretDetectionEngine()
        self.polinrider_detector = PolinRiderDetector()
        self.fixer = DependencyFixEngine()

    def analyze_document(self, uri: str, content: str | None = None) -> list[dict[str, Any]]:
        """Analyzes document identified by URI and returns standard LSP Diagnostic objects."""
        file_path = uri_to_path(uri)
        if content is None:
            if not os.path.isfile(file_path):
                return []
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                return []

        findings: list[Finding] = []
        base_name = os.path.basename(file_path).lower()
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        # 1. Dependency manifest analysis
        if base_name in ("requirements.txt", "requirements-dev.txt", "requirements.in") or base_name.startswith("requirements"):
            findings.extend(self._analyze_requirements_content(file_path, content))
        elif base_name == "package.json":
            findings.extend(self._analyze_package_json_content(file_path, content))
        elif base_name == "pyproject.toml":
            findings.extend(self._analyze_pyproject_content(file_path, content))
        elif ext in (".py", ".pyw", ".pyi"):
            # 2. Python Source SAST + Secrets + Malware
            findings.extend(self._analyze_python_content(file_path, content))
        else:
            # 3. Generic Secrets & Malware detection
            findings.extend(self._analyze_generic_content(file_path, content))

        # Convert findings to LSP diagnostics
        return [self._finding_to_diagnostic(f, content) for f in findings]

    def _analyze_python_content(self, file_path: str, content: str) -> list[Finding]:
        """Runs SAST rules, secret detection, and malware IoCs on Python code."""
        findings: list[Finding] = []

        # SAST AST Rules
        try:
            doc = self.parser.parse_string(content, file_path=file_path)
            summary = ASTAnalysisSummary()
            summary.files_analyzed = 1
            summary.documents.append(doc)

            context = AnalysisContext(
                scan_id=str(uuid.uuid4()),
                project=Project(name="editor_session", root_path=os.path.dirname(file_path) or "."),
            )

            rule_findings, _ = self.rule_engine.evaluate_rules(summary, context)
            findings.extend(rule_findings)
        except Exception:
            pass

        # Secrets Detection
        try:
            dummy_ctx = AnalysisContext(scan_id=str(uuid.uuid4()), project=Project(name="editor_session", root_path="."))
            sec_findings = self.secret_engine.scan_file(file_path, content, dummy_ctx)
            findings.extend(sec_findings)
        except Exception:
            pass

        # Malware IoCs
        findings.extend(self._check_ioc_signatures(file_path, content))
        return findings

    def _analyze_requirements_content(self, file_path: str, content: str) -> list[Finding]:
        """Analyzes requirements.txt for unpinned and vulnerable packages."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([<>=!~].*)?$", stripped)
            if not match:
                continue

            pkg_name = match.group(1).lower()
            spec = match.group(2) or ""

            # Check unpinned
            if not spec or (not spec.startswith("==") and not spec.startswith("===")):
                rec_ver = self.PYTHON_RECOMMENDATIONS.get(pkg_name, "pinned-version")
                findings.append(
                    Finding(
                        rule_id="PYH-DEP-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        title=f"Unpinned Python Dependency: {pkg_name}",
                        description=f"Package '{pkg_name}' is declared without a strict version pin ('=='). Unpinned dependencies invite supply-chain tampering and breaking changes.",
                        file_path=file_path,
                        location=Location(line_start=idx + 1, line_end=idx + 1, column_start=0, column_end=len(line)),
                        evidence=line,
                        remediation=f"Pin to a verified secure version: {pkg_name}=={rec_ver}",
                    )
                )

            # Check known vulnerable Python package
            if pkg_name in self.PYTHON_RECOMMENDATIONS:
                safe_ver = self.PYTHON_RECOMMENDATIONS[pkg_name]
                is_vuln = False
                if "==" in spec:
                    curr_ver = spec.replace("==", "").strip()
                    if curr_ver < safe_ver:
                        is_vuln = True
                elif spec.startswith("<"):
                    curr_ver = spec.lstrip("<=").strip()
                    is_vuln = True

                if is_vuln:
                    findings.append(
                        Finding(
                            rule_id="PYH-DEP-002",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=Category.SUPPLY_CHAIN,
                            title=f"Vulnerable Dependency Version: {pkg_name}{spec}",
                            description=f"Declared version {spec} contains known security vulnerabilities. Safe patched release is {safe_ver}+.",
                            file_path=file_path,
                            location=Location(line_start=idx + 1, line_end=idx + 1, column_start=0, column_end=len(line)),
                            evidence=line,
                            remediation=f"Bump '{pkg_name}' to '=={safe_ver}'",
                        )
                    )

        return findings

    def _analyze_package_json_content(self, file_path: str, content: str) -> list[Finding]:
        """Analyzes package.json for unpinned, compromised, and vulnerable NPM packages."""
        findings: list[Finding] = []
        lines = content.splitlines()

        # Known malicious / compromised NPM packages
        known_malicious_npm = {
            "flatmap-stream": "Attributed to event-stream cryptocurrency theft backdoor.",
            "fallguys": "Typosquatted malware package.",
            "discord-selfbot-v14": "Token stealer malware package.",
            "node-ipc-peacenik": "Protestware wiper.",
        }

        try:
            data = json.loads(content)
        except Exception:
            return findings

        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                pkg_lower = pkg.lower()
                # Find line number of package in JSON
                line_idx = 0
                for idx, line in enumerate(lines):
                    if f'"{pkg}"' in line:
                        line_idx = idx
                        break

                loc = Location(line_start=line_idx + 1, line_end=line_idx + 1, column_start=0, column_end=len(lines[line_idx]) if line_idx < len(lines) else 80)

                # Check malicious
                if pkg_lower in known_malicious_npm:
                    findings.append(
                        Finding(
                            rule_id="PYH-DEP-004",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=Category.SUPPLY_CHAIN,
                            title=f"Compromised / Malicious NPM Package: {pkg}",
                            description=f"Package '{pkg}' is documented malware: {known_malicious_npm[pkg_lower]}",
                            file_path=file_path,
                            location=loc,
                            evidence=lines[line_idx] if line_idx < len(lines) else f'"{pkg}": "{ver}"',
                            remediation=f"Immediately uninstall '{pkg}' and audit repository for persistent backdoors.",
                        )
                    )

                # Check unpinned / wildcards
                if str(ver).strip() in ("*", "latest") or str(ver).startswith("^") or str(ver).startswith("~"):
                    rec_ver = self.NPM_RECOMMENDATIONS.get(pkg_lower, "pinned-version")
                    findings.append(
                        Finding(
                            rule_id="PYH-DEP-001",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category=Category.SUPPLY_CHAIN,
                            title=f"Unpinned NPM Dependency: {pkg}@{ver}",
                            description=f"Dependency '{pkg}' uses wildcard or non-strict version range '{ver}'. Pin with exact version.",
                            file_path=file_path,
                            location=loc,
                            evidence=lines[line_idx] if line_idx < len(lines) else f'"{pkg}": "{ver}"',
                            remediation=f"Pin to exact version: \"{pkg}\": \"{rec_ver}\"",
                        )
                    )

                # Check known vulnerable NPM package
                if pkg_lower in self.NPM_RECOMMENDATIONS:
                    safe_ver = self.NPM_RECOMMENDATIONS[pkg_lower]
                    clean_ver = str(ver).lstrip("^~= ")
                    if clean_ver and clean_ver < safe_ver:
                        findings.append(
                            Finding(
                                rule_id="PYH-DEP-002",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category=Category.SUPPLY_CHAIN,
                                title=f"Vulnerable NPM Dependency: {pkg}@{ver}",
                                description=f"NPM package '{pkg}@{ver}' is vulnerable. Safe patched version is {safe_ver}.",
                                file_path=file_path,
                                location=loc,
                                evidence=lines[line_idx] if line_idx < len(lines) else f'"{pkg}": "{ver}"',
                                remediation=f"Bump to '{safe_ver}'",
                            )
                        )

        return findings

    def _analyze_pyproject_content(self, file_path: str, content: str) -> list[Finding]:
        """Analyzes pyproject.toml for unpinned or vulnerable dependencies."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            stripped = line.strip()
            # Look for lines like "requests>=2.20" or "requests = "^2.20""
            match = re.search(r'["\']([a-zA-Z0-9_\-\.]+)([<>=!~^].*)?["\']', stripped)
            if not match:
                continue

            pkg_name = match.group(1).lower()
            spec = match.group(2) or ""

            if pkg_name in self.PYTHON_RECOMMENDATIONS:
                safe_ver = self.PYTHON_RECOMMENDATIONS[pkg_name]
                loc = Location(line_start=idx + 1, line_end=idx + 1, column_start=0, column_end=len(line))
                if not spec or "^" in spec or "~=" in spec or ">=" in spec or "<" in spec:
                    findings.append(
                        Finding(
                            rule_id="PYH-DEP-001",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=Category.SUPPLY_CHAIN,
                            title=f"Unpinned / Vulnerable Dependency in pyproject.toml: {pkg_name}",
                            description=f"Package '{pkg_name}' has non-strict or outdated constraint '{spec}'. Recommended patched release is >={safe_ver}.",
                            file_path=file_path,
                            location=loc,
                            evidence=line,
                            remediation=f"Specify '{pkg_name}=={safe_ver}'",
                        )
                    )

        return findings

    def _analyze_generic_content(self, file_path: str, content: str) -> list[Finding]:
        """Analyzes generic configuration, workflows, or scripts for secrets and malware."""
        findings: list[Finding] = []

        # Secrets scanning
        try:
            dummy_ctx = AnalysisContext(scan_id=str(uuid.uuid4()), project=Project(name="editor_session", root_path="."))
            sec_findings = self.secret_engine.scan_file(file_path, content, dummy_ctx)
            findings.extend(sec_findings)
        except Exception:
            pass

        # PolinRider IoC signatures
        findings.extend(self._check_ioc_signatures(file_path, content))

        # Check VS Code tasks hijacking if editing tasks.json
        if file_path.endswith("tasks.json"):
            findings.extend(self._check_tasks_json(file_path, content))

        return findings

    def _check_ioc_signatures(self, file_path: str, content: str) -> list[Finding]:
        """Detects known PolinRider / TasksJacker string signatures."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, desc in self.polinrider_detector.IOC_SIGNATURES:
            for idx, line in enumerate(lines):
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=Category.MALWARE,
                            title=f"Malware Signature Detected: {desc}",
                            description=f"File contains known PolinRider / TasksJacker campaign IoC matching signature '{pattern}'.",
                            file_path=file_path,
                            location=Location(line_start=idx + 1, line_end=idx + 1, column_start=0, column_end=len(line)),
                            evidence=line.strip(),
                            remediation="Immediately isolate this file and purge unauthorized dropper scripts.",
                        )
                    )
        return findings

    def _check_tasks_json(self, file_path: str, content: str) -> list[Finding]:
        """Detects malicious VS Code task hijacking in tasks.json."""
        findings: list[Finding] = []
        clean_content = re.sub(r"//.*", "", content)
        try:
            data = json.loads(clean_content)
        except Exception:
            return findings

        tasks = data.get("tasks", [])
        if isinstance(tasks, list):
            for idx, task in enumerate(tasks):
                if not isinstance(task, dict):
                    continue
                run_on = (task.get("runOptions", {}) if isinstance(task.get("runOptions"), dict) else {}).get("runOn") or task.get("runOn")
                cmd = str(task.get("command", ""))
                label = str(task.get("label", ""))

                if run_on == "folderOpen":
                    findings.append(
                        Finding(
                            rule_id="PYH-MAL-001",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=Category.MALWARE,
                            title="VS Code FolderOpen Task Hijack Detected",
                            description=f"Task '{label}' automatically executes command '{cmd}' upon opening folder in VS Code.",
                            file_path=file_path,
                            location=Location(line_start=1, line_end=1, column_start=0, column_end=80),
                            evidence=f"runOn: {run_on}, command: {cmd}",
                            remediation="Remove 'runOn: folderOpen' from .vscode/tasks.json immediately.",
                        )
                    )
        return findings

    def _finding_to_diagnostic(self, finding: Finding, content: str) -> dict[str, Any]:
        """Converts an internal Finding to an LSP 3.17 Diagnostic dictionary."""
        lines = content.splitlines()
        line_start = (finding.location.line_start - 1) if finding.location and finding.location.line_start > 0 else 0
        line_end = (finding.location.line_end - 1) if finding.location and finding.location.line_end > 0 else line_start

        col_start = finding.location.column_start if finding.location else 0
        col_end = finding.location.column_end if finding.location and finding.location.column_end > 0 else (
            len(lines[line_start]) if line_start < len(lines) else 80
        )

        # Severity mapping
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            sev_code = DiagnosticSeverity.ERROR
        elif finding.severity == Severity.MEDIUM:
            sev_code = DiagnosticSeverity.WARNING
        elif finding.severity == Severity.LOW:
            sev_code = DiagnosticSeverity.INFORMATION
        else:
            sev_code = DiagnosticSeverity.HINT

        msg = f"[{finding.severity.value}] {finding.title}\n{finding.description}"
        if finding.remediation:
            msg += f"\nRemediation: {finding.remediation}"

        return {
            "range": {
                "start": {"line": line_start, "character": col_start},
                "end": {"line": line_end, "character": max(col_end, col_start + 1)},
            },
            "severity": int(sev_code),
            "code": finding.rule_id,
            "source": "python-hunter",
            "message": msg,
            "data": {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "remediation": finding.remediation,
                "file_path": finding.file_path,
            },
        }

    def generate_code_actions(
        self,
        uri: str,
        range_dict: dict[str, Any],
        diagnostics: list[dict[str, Any]],
        document_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generates LSP CodeActions (QuickFixes) for security diagnostics."""
        actions: list[dict[str, Any]] = []

        for diag in diagnostics:
            code = diag.get("code", "")
            data = diag.get("data", {})
            remediation = data.get("remediation", "")
            diag_range = diag.get("range", range_dict)

            # QuickFix for dependency pinning/upgrade
            if str(code).startswith("PYH-DEP") and remediation:
                actions.append(
                    {
                        "title": f"Security Fix: {remediation}",
                        "kind": CodeActionKind.QUICK_FIX,
                        "diagnostics": [diag],
                        "isPreferred": True,
                        "command": {
                            "title": "Apply Security Fix",
                            "command": "python-hunter.applyFix",
                            "arguments": [uri, diag],
                        },
                    }
                )

            # QuickFix: Suppress with comment
            actions.append(
                {
                    "title": f"Suppress finding [{code}] with # noqa: python-hunter",
                    "kind": CodeActionKind.QUICK_FIX,
                    "diagnostics": [diag],
                    "isPreferred": False,
                    "edit": {
                        "changes": {
                            uri: [
                                {
                                    "range": {
                                        "start": {"line": diag_range["start"]["line"], "character": 9999},
                                        "end": {"line": diag_range["start"]["line"], "character": 9999},
                                    },
                                    "newText": "  # noqa: python-hunter",
                                }
                            ]
                        }
                    },
                }
            )

        return actions
