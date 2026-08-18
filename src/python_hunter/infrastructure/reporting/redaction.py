"""Secret Redaction Subsystem for Security Reports."""

import re
from typing import Any

from python_hunter.domain.common.enums import Category
from python_hunter.domain.findings.finding import Finding


class SecretRedactor:
    """Masks secret values and credentials in finding evidence and descriptions."""

    SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # AWS Access Keys
        (re.compile(r"(AKIA[0-9A-Z]{16})"), r"\1"[:4] + "*" * 16),
        (re.compile(r"(aws_secret_access_key\s*=\s*)([A-Za-z0-9/+=]{40})"), r"\1[REDACTED_AWS_SECRET]"),
        # Generic API Keys / Tokens
        (re.compile(r"(sk_live_[0-9a-zA-Z]{24,})"), r"sk_live_********************"),
        (re.compile(r"(ghp_[0-9a-zA-Z]{36})"), r"ghp_************************************"),
        (re.compile(r"(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+)"), r"[REDACTED_JWT_TOKEN]"),
        # Private Keys
        (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----"), r"[REDACTED_PRIVATE_KEY]"),
        # Database Connection Strings
        (re.compile(r"(postgres(?:ql)?|mysql|mongodb)://([^:]+):([^@]+)@"), r"\1://\2:********@"),
    ]

    @classmethod
    def redact_text(cls, text: str | None) -> str:
        """Redact sensitive credentials from input text."""
        if not text:
            return ""
        result = text
        for pattern, replacement in cls.SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    @classmethod
    def redact_finding(cls, finding: Finding) -> Finding:
        """Return a copy of finding with secret fields redacted."""
        if finding.category != Category.SECRET and not finding.evidence:
            return finding

        f_copy = Finding(
            rule_id=finding.rule_id,
            severity=finding.severity,
            confidence=finding.confidence,
            category=finding.category,
            title=finding.title,
            description=cls.redact_text(finding.description),
            file_path=finding.file_path,
            location=finding.location,
            evidence=cls.redact_text(finding.evidence),
            remediation=finding.remediation,
            source=cls.redact_text(finding.source),
            sink=cls.redact_text(finding.sink),
            references=finding.references,
            tags=finding.tags,
            risk_score=finding.risk_score,
            exposure=finding.exposure,
            reachability=finding.reachability,
            lifecycle_state=finding.lifecycle_state,
            attack_path_id=finding.attack_path_id,
            related_findings=finding.related_findings,
            secondary_evidence=[cls.redact_text(s) for s in finding.secondary_evidence],
            metadata=dict(finding.metadata),
        )
        return f_copy

    @classmethod
    def redact_findings(cls, findings: list[Finding], enabled: bool = True) -> list[Finding]:
        """Redact secrets across finding collection if enabled."""
        if not enabled:
            return findings
        return [cls.redact_finding(f) for f in findings]
