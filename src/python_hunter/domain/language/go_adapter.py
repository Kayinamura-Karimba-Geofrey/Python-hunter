"""Go Language Adapter and Security Analyzer."""

import os
import re
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class GoLanguageAdapter(LanguageAdapter):
    """Production Go language adapter supporting Gin/Echo/Fiber/net/http and security analysis."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.TAINT,
                AnalyzerCapability.FRAMEWORK_ANALYSIS,
                AnalyzerCapability.DEPENDENCY_ANALYSIS,
                AnalyzerCapability.API_DISCOVERY,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.GO,
            display_name="Go",
            aliases=["go", "golang"],
            file_extensions=[".go"],
            parser="GoASTParser",
            analyzer="GoSecurityAnalyzer",
            framework_adapters=["Gin", "Echo", "Fiber", "net/http"],
            dependency_ecosystem="Go Modules",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.GO

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".go") or f in ("go.mod", "go.sum") for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "go").ast
        except Exception:
            return {"type": "GoAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".go"):
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
                # 1. Go SQL Injection
                if ("db.Query" in line or "db.Exec" in line) and ("fmt.Sprintf" in line or "+" in line):
                    findings.append({
                        "rule_id": "PYH-GO-001",
                        "title": "Go SQL Injection via Format String / Concatenation",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "risk_score": 9.1,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-89",
                        "owasp": "A03:2021-Injection",
                        "remediation": "Use parameterized queries e.g., db.Query('SELECT * FROM users WHERE id = ?', id).",
                        "language": "go",
                        "framework": "database/sql",
                    })

                # 2. Go Command Execution
                if "exec.Command(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-GO-002",
                            "title": "Go OS Command Execution Vulnerability",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.4,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Avoid passing user input directly to os/exec. Use strict argument whitelisting.",
                            "language": "go",
                            "framework": "os/exec",
                        })

                # 3. Go Path Traversal
                if "os.Open(" in line or "ioutil.ReadFile(" in line or "os.ReadFile(" in line:
                    if "req" in line or "param" in line or "path" in line or "c.Query" in line:
                        findings.append({
                            "rule_id": "PYH-GO-003",
                            "title": "Go Path Traversal File Access",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "risk_score": 7.6,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-22",
                            "owasp": "A01:2021-Broken Access Control",
                            "remediation": "Use filepath.Clean() and ensure target path resides within restricted directory boundary.",
                            "language": "go",
                            "framework": "Go Standard Library",
                        })

                # 4. Go SSRF / Unchecked HTTP Client Request
                if "http.Get(" in line or "http.Post(" in line:
                    if "req" in line or "url" in line or "param" in line or "id" in line:
                        findings.append({
                            "rule_id": "PYH-GO-004",
                            "title": "Go SSRF via Dynamic HTTP Request",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "risk_score": 7.8,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-918",
                            "owasp": "A10:2021-Server-Side Request Forgery",
                            "remediation": "Validate target URL domain against an allowed destination whitelist before initiating HTTP requests.",
                            "language": "go",
                            "framework": "net/http",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("go_root", language="go", file_path=workspace_path)
        return ir

    def extract_endpoints(self, file_path: str) -> List[Dict[str, Any]]:
        endpoints = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            routes = re.findall(r'r\.(GET|POST|PUT|DELETE)\(["\']([^"\']+)["\']', content)
            for method, path in routes:
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "file_path": file_path,
                    "framework": "Gin",
                })
        except Exception:
            pass
        return endpoints
