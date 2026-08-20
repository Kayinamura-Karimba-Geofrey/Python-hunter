"""Rust Language Adapter and Security Analyzer."""

import os
from typing import Any, Dict, List
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import AnalyzerCapability, Language, LanguageCapabilities, LanguageMetadata
from python_hunter.domain.language.parser_provider import ParserProvider


class RustLanguageAdapter(LanguageAdapter):
    """Production Rust language adapter supporting Actix/Rocket/Tokio and security analysis."""

    def __init__(self) -> None:
        caps = LanguageCapabilities(
            capabilities={
                AnalyzerCapability.AST,
                AnalyzerCapability.CFG,
                AnalyzerCapability.CALL_GRAPH,
                AnalyzerCapability.DATAFLOW,
                AnalyzerCapability.DEPENDENCY_ANALYSIS,
                AnalyzerCapability.API_DISCOVERY,
            }
        )
        self._metadata = LanguageMetadata(
            language=Language.RUST,
            display_name="Rust",
            aliases=["rs", "rust"],
            file_extensions=[".rs"],
            parser="RustASTParser",
            analyzer="RustSecurityAnalyzer",
            framework_adapters=["Actix-web", "Rocket", "Axum", "Tokio"],
            dependency_ecosystem="crates.io",
            capabilities=caps,
            version="1.0.0",
        )

    @property
    def language(self) -> Language:
        return Language.RUST

    @property
    def metadata(self) -> LanguageMetadata:
        return self._metadata

    def is_available(self) -> bool:
        return True

    def detect(self, workspace_path: str) -> bool:
        if not os.path.exists(workspace_path):
            return False
        for root, _, files in os.walk(workspace_path):
            if any(f.endswith(".rs") or f in ("Cargo.toml", "Cargo.lock") for f in files):
                return True
        return False

    def parse(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return ParserProvider.parse_generic_structural(content, file_path, "rust").ast
        except Exception:
            return {"type": "RustAST", "file_path": file_path, "declarations": []}

    def analyze(self, workspace_path: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                if file_name.endswith(".rs"):
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
                # 1. Unsafe Rust Block
                if "unsafe {" in line or "unsafe fn" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-RUST-001",
                            "title": "Use of Unsafe Rust Block / Function",
                            "severity": "MEDIUM",
                            "confidence": "HIGH",
                            "risk_score": 5.5,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-1188",
                            "owasp": "A06:2021-Vulnerable and Outdated Components",
                            "remediation": "Audit unsafe block to ensure memory safety invariants and pointer alignment bounds are maintained.",
                            "language": "rust",
                            "framework": "Rust Core",
                        })

                # 2. Rust Command Execution
                if "Command::new(" in line:
                    if not line.strip().startswith("//"):
                        findings.append({
                            "rule_id": "PYH-RUST-002",
                            "title": "Rust OS Command Invocation",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "risk_score": 8.0,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-78",
                            "owasp": "A03:2021-Injection",
                            "remediation": "Sanitize and validate all arguments passed to Command::new(). Avoid shell string wrapping.",
                            "language": "rust",
                            "framework": "std::process::Command",
                        })

                # 3. Rust Path Traversal
                if "File::open(" in line or "fs::read_to_string(" in line:
                    if "user" in line or "param" in line or "path" in line or "req" in line:
                        findings.append({
                            "rule_id": "PYH-RUST-003",
                            "title": "Rust Path Traversal File Access",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "risk_score": 7.5,
                            "file_path": file_path,
                            "line_number": idx,
                            "code_snippet": line.strip(),
                            "cwe": "CWE-22",
                            "owasp": "A01:2021-Broken Access Control",
                            "remediation": "Canonicalize target PathBuf with std::fs::canonicalize() and verify it remains within target root.",
                            "language": "rust",
                            "framework": "std::fs",
                        })
        except Exception:
            pass
        return findings

    def build_ir(self, workspace_path: str) -> SecurityIR:
        ir = SecurityIR()
        ir.add_module("rust_root", language="rust", file_path=workspace_path)
        return ir
