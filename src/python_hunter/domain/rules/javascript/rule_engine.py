"""JavaScript and TypeScript Security Rules Suite."""

import re
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.ir.models import SecurityIR
from python_hunter.domain.language.models import Language


class JSSecurityRuleEngine:
    """Evaluates JavaScript and TypeScript source files and SecurityIR against security rules."""

    RULES = [
        ("PYHUNTER-JS-SQL-001", Severity.HIGH, Category.INJECTION, "SQL Injection", r"(?:query|exec|execute)\s*\(\s*.*?\+.*?"),
        ("PYHUNTER-JS-CMD-001", Severity.CRITICAL, Category.INJECTION, "Command Injection", r"(?:exec|execSync|spawn|spawnSync)\s*\(\s*.*?\+.*?\)|(?:exec|execSync)\s*\(\s*`.*?`"),
        ("PYHUNTER-JS-CODE-001", Severity.CRITICAL, Category.CODE_INJECTION, "Code Injection / Eval", r"\beval\s*\(|Function\s*\(|vm\.runIn"),
        ("PYHUNTER-JS-PATH-001", Severity.HIGH, Category.PATH_TRAVERSAL, "Path Traversal", r"fs\.(?:readFile|writeFile|open|unlink)\s*\(\s*.*?\+.*?"),
        ("PYHUNTER-JS-SSRF-001", Severity.HIGH, Category.CONFIGURATION, "SSRF Vulnerability", r"(?:axios|fetch|http\.request)\s*\(\s*.*?\+.*?"),
        ("PYHUNTER-JS-XSS-001", Severity.HIGH, Category.INJECTION, "DOM Cross-Site Scripting (XSS)", r"innerHTML\s*=|\bdocument\.write\s*\("),
        ("PYHUNTER-JS-PROTOTYPE-001", Severity.HIGH, Category.INJECTION, "Prototype Pollution", r"__proto__|constructor\.prototype"),
    ]

    def analyze_file(self, file_path: str, content: str, language: Language) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            for rule_id, severity, category, title, pattern in self.RULES:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            category=category,
                            title=f"{title} ({language.value.upper()})",
                            description=f"Potential {title} vulnerability detected in {language.value} source code.",
                            file_path=file_path,
                            location=Location(idx, idx),
                            evidence=line.strip(),
                            remediation="Sanitize input or use safe parameterization APIs.",
                        )
                    )

        return findings
