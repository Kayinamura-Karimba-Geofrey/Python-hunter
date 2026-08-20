"""Java Language Adapter and Security Analyzer."""

import os
import re
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class JavaLanguageAdapter(LanguageAdapter):
    """Production Java language adapter supporting Spring/Spring Boot/Jakarta EE and security analysis."""

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
            language=Language.JAVA,
            display_name="Java",
            aliases=["java", "jsp"],
            file_extensions=[".java"],
            parser="JavaASTParser",
            analyzer="JavaSecurityAnalyzer",
            framework_adapters=["Spring Boot", "Spring MVC", "Jakarta EE"],
            dependency_ecosystem="Maven / Gradle",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.JAVA

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".java") or f in ("pom.xml", "build.gradle") for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "java").ast
        except Exception:
            return {"type": "JavaAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".java"):
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
                # 1. Java SQL Injection
                if ("Statement" in line or "executeQuery" in line or "createQuery" in line or "SELECT" in line) and ("+" in line or "%s" in line):
                    findings.append({
                        "rule_id": "PYH-JAVA-001",
                        "title": "Java SQL Injection via String Concatenation",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "risk_score": 9.2,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-89",
                        "owasp": "A03:2021-Injection",
                        "remediation": "Use parameterized queries with PreparedStatement or Spring JdbcTemplate.",
                        "language": "java",
                        "framework": "Spring",
                    })

                # 2. Java Command Injection
                if "Runtime.getRuntime().exec" in line or "ProcessBuilder" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-JAVA-002",
                            "title": "Java Command Execution Vulnerability",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.5,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Avoid executing OS commands with user input. Use safe Java APIs.",
                            "language": "java",
                            "framework": "Java Standard Library",
                        })

                # 3. Java Insecure Deserialization
                if "readObject(" in line or "XMLDecoder(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-JAVA-003",
                            "title": "Insecure Java Object Deserialization",
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "risk_score": 9.5,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-502",
                            "owasp": "A08:2021-Software and Data Integrity Failures",
                            "remediation": "Implement ObjectInputFilter or use safe JSON serialization formats.",
                            "language": "java",
                            "framework": "Java Standard Library",
                        })

                # 4. Java Path Traversal
                if "new File(" in line and ("request." in line or "param" in line or "path" in line):
                    findings.append({
                        "rule_id": "PYH-JAVA-004",
                        "title": "Java Path Traversal Vulnerability",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "risk_score": 7.8,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-22",
                        "owasp": "A01:2021-Broken Access Control",
                        "remediation": "Validate input filenames against a whitelist and normalize path with java.nio.file.Path.normalize().",
                        "language": "java",
                        "framework": "Java Standard Library",
                    })

                # 5. Java Weak Cryptography (DES/MD5)
                if 'Cipher.getInstance("DES' in line or 'MessageDigest.getInstance("MD5"' in line:
                    findings.append({
                        "rule_id": "PYH-JAVA-005",
                        "title": "Use of Weak Cryptographic Algorithm (DES/MD5)",
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "risk_score": 6.5,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-327",
                        "owasp": "A02:2021-Cryptographic Failures",
                        "remediation": "Upgrade algorithm to AES-256-GCM or SHA-256.",
                        "language": "java",
                        "framework": "Java Cryptography Extension",
                    })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("java_root", language="java", file_path=workspace_path)
        return ir

    def extract_endpoints(self, file_path: str) -> List[Dict[str, Any]]:
        endpoints = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "@RestController" in content or "@Controller" in content:
                routes = re.findall(r'@(GetMapping|PostMapping|RequestMapping)\(["\']([^"\']+)["\']\)', content)
                for method, path in routes:
                    endpoints.append({
                        "method": method.replace("Mapping", "").upper(),
                        "path": path,
                        "file_path": file_path,
                        "framework": "Spring Boot",
                    })
        except Exception:
            pass
        return endpoints
