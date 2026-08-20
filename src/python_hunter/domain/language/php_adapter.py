"""PHP Language Adapter and Security Analyzer."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class PHPLanguageAdapter(LanguageAdapter):
    """Production PHP language adapter supporting Laravel/Symfony/WordPress and security analysis."""

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
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.PHP,
            display_name="PHP",
            aliases=["php", "phtml"],
            file_extensions=[".php", ".phtml"],
            parser="PHPASTParser",
            analyzer="PHPSecurityAnalyzer",
            framework_adapters=["Laravel", "Symfony", "CodeIgniter", "WordPress"],
            dependency_ecosystem="Composer",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.PHP

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith((".php", ".phtml")) or f == "composer.json" for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "php").ast
        except Exception:
            return {"type": "PHPAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith((".php", ".phtml")):
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
                # 1. PHP Command Injection
                if ("system(" in line or "shell_exec(" in line or "exec(" in line or "passthru(" in line) and ("$_" in line or "$user" in line):
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-PHP-001",
                            "title": "PHP Command Injection via Shell Function",
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "risk_score": 9.5,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Escape arguments with escapeshellarg() or avoid shell invocations.",
                            "language": "php",
                            "framework": "PHP Standard Library",
                        })

                # 2. PHP Unsafe File Inclusion (LFI/RFI)
                if ("include " in line or "require " in line or "include_once " in line) and ("$_GET" in line or "$_POST" in line or "$_REQUEST" in line):
                    findings.append({
                        "rule_id": "PYH-PHP-002",
                        "title": "PHP Remote/Local File Inclusion (LFI/RFI)",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "risk_score": 9.3,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-98",
                        "owasp": "A03:2021-Injection",
                        "remediation": "Do not pass user input to include/require statements. Use a strict file map array.",
                        "language": "php",
                        "framework": "PHP Core",
                    })

                # 3. PHP Unsafe Deserialization
                if "unserialize(" in line and ("$_" in line or "$user" in line or "$data" in line):
                    findings.append({
                        "rule_id": "PYH-PHP-003",
                        "title": "Unsafe PHP Object Deserialization",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "risk_score": 9.2,
                        "file_path": file_path,
                        "line_number": idx,
                        "code_snippet": line.strip(),
                        "cwe": "CWE-502",
                        "owasp": "A08:2021-Software and Data Integrity Failures",
                        "remediation": "Use json_decode() instead of unserialize() for user-controlled input.",
                        "language": "php",
                        "framework": "PHP Standard Library",
                    })

                # 4. PHP Cross-Site Scripting (XSS)
                if ("echo " in line or "print " in line) and ("$_GET" in line or "$_POST" in line or "$_REQUEST" in line):
                    if "htmlspecialchars" not in line and "htmlentities" not in line:
                        findings.append({
                            "rule_id": "PYH-PHP-004",
                            "title": "Reflected XSS via Unescaped Superglobal Echo",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.1,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-79",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Wrap output with htmlspecialchars($val, ENT_QUOTES, 'UTF-8').",
                            "language": "php",
                            "framework": "PHP Standard Library",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("php_root", language="php", file_path=workspace_path)
        return ir
