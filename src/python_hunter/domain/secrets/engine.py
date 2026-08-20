"""Secret Detection Pipeline Orchestrator."""

import os
from typing import Any

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.secrets.context_analyzer import SecretContextAnalyzer
from python_hunter.domain.secrets.entropy import EntropyCalculator
from python_hunter.domain.secrets.models import (
    ExposureType,
    SecretCandidate,
    SecretDetector,
    SecretExposure,
    compute_secret_fingerprint,
)
from python_hunter.domain.secrets.placeholders import PlaceholderFilter
from python_hunter.domain.secrets.redaction import Redactor
from python_hunter.domain.secrets.registry import SecretDetectorRegistry
from python_hunter.domain.secrets.validation import SecretValidator


class SecretDetectionEngine:
    """Orchestrates candidate extraction, context analysis, validation, fingerprinting, redaction, and finding creation."""

    SCANNABLE_EXTENSIONS = {
        ".py", ".pyi", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".env", ".txt", ".md", ".xml", ".conf", ".pem", ".key"
    }

    BINARY_MAGIC_BYTES = [
        b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff", b"PK\x03\x04", b"\x1f\x8b\x08"
    ]

    def __init__(self, registry: SecretDetectorRegistry | None = None) -> None:
        from python_hunter.detectors.secrets import create_default_secret_registry
        self.registry = registry or create_default_secret_registry()

    @classmethod
    def is_eligible_file(cls, file_path: str) -> bool:
        """Check if file is scannable text file and not a binary or ignored file."""
        basename = os.path.basename(file_path).lower()
        if basename.startswith(".env") or basename in ("credentials", "secrets"):
            return True

        ext = os.path.splitext(file_path)[1].lower()
        if ext and ext not in cls.SCANNABLE_EXTENSIONS:
            return False

        if not os.path.exists(file_path):
            return True

        # Binary check by reading header bytes
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
                if not header:
                    return True
                for magic in cls.BINARY_MAGIC_BYTES:
                    if header.startswith(magic):
                        return False
                # Null byte heuristic for binary files
                if b"\x00" in header:
                    return False
        except Exception:
            return False

        return True

    def scan_file(
        self, file_path: str, content: str, context: AnalysisContext
    ) -> list[Finding]:
        """Scan file content text and return redacted security findings."""
        if not content or not self.is_eligible_file(file_path):
            return []

        raw_candidates: list[SecretCandidate] = []
        for detector in self.registry.enabled_detectors():
            try:
                candidates = detector.detect(content, file_path, context)
                raw_candidates.extend(candidates)
            except Exception:
                continue

        findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for cand in raw_candidates:
            raw_secret_str = cand.value

            # 1. Placeholder check
            if PlaceholderFilter.is_placeholder(raw_secret_str):
                cand.is_placeholder = True
                continue

            # 2. Offline Structural Validation
            is_valid_format = SecretValidator.validate_structurally(cand)
            if not is_valid_format:
                continue

            # 3. Entropy calculation
            cand.entropy = EntropyCalculator.calculate(raw_secret_str)

            # 4. Context & Environment Analysis
            cand.is_test_file = SecretContextAnalyzer.is_test_file(file_path)
            env = SecretContextAnalyzer.infer_environment(file_path, cand.evidence_snippet)
            priv = SecretContextAnalyzer.infer_privilege(cand.secret_type, cand.evidence_snippet)
            eval_conf, is_test_match = SecretContextAnalyzer.evaluate_context_confidence(
                raw_secret_str, cand.context_key, file_path
            )

            detector = self.registry.get(cand.detector_id)
            severity = detector.severity if detector else Severity.HIGH
            confidence = eval_conf if detector else Confidence.HIGH

            # If in test file or mock, lower severity to MEDIUM/LOW
            if is_test_match or cand.is_test_file:
                severity = Severity.MEDIUM if severity in (Severity.CRITICAL, Severity.HIGH) else Severity.LOW

            # 5. Non-reversible Secret Fingerprint
            fp = cand.fingerprint or compute_secret_fingerprint(raw_secret_str)

            # 6. Immediate Redaction (Zero Raw Secret Leakage Guarantee)
            redacted_preview = Redactor.redact_value(raw_secret_str)
            sanitized_evidence = Redactor.sanitize_evidence(cand.evidence_snippet, raw_secret_str)

            loc = Location(
                line_start=cand.line,
                line_end=cand.line,
                column_start=cand.column,
                column_end=cand.column + len(redacted_preview),
            )

            title = f"Exposed {cand.secret_type.value.replace('_', ' ').title()} Secret Detected"
            description = (
                f"Potentially exposed credential of type '{cand.secret_type.value}' detected "
                f"by detector '{cand.detector_id}' (Fingerprint: {fp}, Entropy: {cand.entropy}, Env: {env.value}, Priv: {priv.value})."
            )

            finding = Finding(
                rule_id=cand.detector_id,
                severity=severity,
                confidence=confidence,
                category=Category.SECRET_LEAK,
                title=title,
                description=description,
                file_path=cand.file_path,
                location=loc,
                evidence=sanitized_evidence,
                remediation=(
                    "1. Revoke/rotate the exposed credential immediately.\n"
                    "2. Remove raw secret string from repository source code.\n"
                    "3. Store credentials in environment variables or secret managers (e.g. HashiCorp Vault, AWS Secrets Manager)."
                ),
            )
            # Override finding fingerprint with non-reversible secret fingerprint
            finding.fingerprint = fp

            # Deduplication by secret fingerprint with specificity preference
            existing_idx = None
            for idx, existing in enumerate(findings):
                if existing.fingerprint == fp:
                    existing_idx = idx
                    break

            if existing_idx is None:
                findings.append(finding)
            else:
                # Upgrade existing generic finding if new finding is provider-specific
                existing_finding = findings[existing_idx]
                generic_ids = ("PYH-SECRET-010", "PYH-SECRET-001", "PYH-SECRET-008", "PYH-SECRET-002")
                if existing_finding.rule_id in generic_ids and finding.rule_id not in generic_ids:
                    findings[existing_idx] = finding

        return findings
