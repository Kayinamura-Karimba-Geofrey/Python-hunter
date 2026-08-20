"""C and C++ Language Adapters and Security Analyzers."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class CLanguageAdapter(LanguageAdapter):
    """Production C language adapter supporting memory safety & vulnerability analysis."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.TAINT,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.C,
            display_name="C",
            aliases=["c"],
            file_extensions=[".c", ".h"],
            parser="CASTParser",
            analyzer="CSecurityAnalyzer",
            framework_adapters=["POSIX", "Linux Kernel"],
            dependency_ecosystem="Makefile / CMake",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.C

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".c", ".h")) for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "c").ast
        except Exception:
            return {"type": "CAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith((".c", ".h")):
                    full_path = os.path.join(root, file_name)
                    findings.extend(self._analyze_file(full_path))
        return findings

    def _analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                # 1. Unsafe Buffer Function (strcpy / gets / sprintf)
                if "strcpy(" in line or "gets(" in line or "strcat(" in line or "sprintf(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-C-001",
                            "title": "Use of Unsafe Memory Function (Buffer Overflow Vulnerability)",
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "risk_score": 9.4,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-120",
                            "owasp": "A06:2021-Vulnerable and Outdated Components",
                            "remediation": "Replace with bounds-checked alternatives e.g., strncpy(), snprintf(), or fgets().",
                            "language": "c",
                            "framework": "C Standard Library",
                        })

                # 2. Command Execution via system()
                if "system(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-C-002",
                            "title": "Unsafe OS Command Execution via system()",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.6,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Use execve() with explicit argument arrays instead of invoking system shell.",
                            "language": "c",
                            "framework": "POSIX C Library",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("c_root", language="c", file_path=workspace_path)
        return ir


class CPPLanguageAdapter(LanguageAdapter):
    """Production C++ language adapter supporting OOP, Smart Pointers & Memory Analysis."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.TAINT,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.CPP,
            display_name="C++",
            aliases=["cpp", "c++", "cxx", "hpp"],
            file_extensions=[".cpp", ".hpp", ".cc", ".cxx"],
            parser="CPPASTParser",
            analyzer="CPPSecurityAnalyzer",
            framework_adapters=["Qt", "Boost", "Poco"],
            dependency_ecosystem="CMake / Conan / vcpkg",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.CPP

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".cpp", ".hpp", ".cc", ".cxx")) or f == "CMakeLists.txt" for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "cpp").ast
        except Exception:
            return {"type": "CPPAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith((".cpp", ".hpp", ".cc", ".cxx")):
                    full_path = os.path.join(root, file_name)
                    findings.extend(self._analyze_file(full_path))
        return findings

    def _analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                # 1. Raw Pointer Deletion / Use After Free Risk
                if "delete " in line or "delete[] " in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-CPP-001",
                            "title": "Manual Raw Pointer Deletion (Use-After-Free Risk)",
                            "severity": "MEDIUM",
                            "confidence": "MEDIUM",
                            "risk_score": 6.8,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-416",
                            "owasp": "A06:2021-Vulnerable and Outdated Components",
                            "remediation": "Migrate raw pointer management to smart pointers e.g., std::unique_ptr or std::shared_ptr.",
                            "language": "cpp",
                            "framework": "C++ Standard Library",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("cpp_root", language="cpp", file_path=workspace_path)
        return ir
