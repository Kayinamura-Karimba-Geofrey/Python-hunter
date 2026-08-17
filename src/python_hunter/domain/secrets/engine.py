"""Secret Detection Pipeline Orchestrator."""

import os
from typing import Any

from python_hunter.domain.analysis.context import AnalysisContext
from python_hunter.domain.common.enums import Category, Confidence, Severity
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.secrets.entropy import EntropyCalculator
from python_hunter.domain.secrets.models import SecretCandidate, SecretDetector
from python_hunter.domain.secrets.placeholders import PlaceholderFilter
from python_hunter.domain.secrets.redaction import Redactor
from python_hunter.domain.secrets.registry import SecretDetectorRegistry


class SecretDetectionEngine:
    """Orchestrates candidate extraction, entropy analysis, placeholder filtering, redaction, and finding creation."""

    SCANNABLE_EXTENSIONS = {
        ".py", ".pyi", ".js", ".ts", ".jsx", ".tsx",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".env", ".txt", ".md", ".xml", ".conf", ".pem", ".key"
    }

    BINARY_MAGIC_BYTES = [
        b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff", b"PK\x03\x04", b"\x1f\x8b\x08"
    ]

    def __init__(self, registry: SecretDetectorRegistry | None = None) -> None:
        self.registry = registry or SecretDetectorRegistry()

    @classmethod
    def is_eligible_file(cls, file_path: str) -> bool:
        """Check if file is scannable text file and not a binary or ignored file."""
        basename = os.path.basename(file_path).lower()
        if basename.startswith(".env") or basename in ("credentials", "secrets"):
            return True

        ext = os.path.splitext(file_path)[1].lower()
        if ext and ext not in cls.SCANNABLE_EXTENSIONS:
            return False

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
        if not content:
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
            # 1. Placeholder check
            if PlaceholderFilter.is_placeholder(cand.value):
                continue

            # 2. Entropy calculation
            cand.entropy = EntropyCalculator.calculate(cand.value)

            # 3. Detector metadata lookup
            detector = self.registry.get(cand.detector_id)
            severity = detector.severity if detector else Severity.HIGH
            confidence = detector.confidence if detector else Confidence.HIGH

            # 4. Immediate Redaction (Zero Raw Secret Leakage Guarantee)
            redacted_preview = Redactor.redact_value(cand.value)
            sanitized_evidence = Redactor.sanitize_evidence(cand.evidence_snippet, cand.value)

            loc = Location(
                line_start=cand.line,
                line_end=cand.line,
                column_start=cand.column,
                column_end=cand.column + len(redacted_preview),
            )

            title = f"Exposed {cand.secret_type.value.replace('_', ' ').title()} Secret Detected"
            description = (
                f"Potentially exposed credential of type '{cand.secret_type.value}' detected "
                f"by detector '{cand.detector_id}' (Shannon entropy: {cand.entropy})."
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

            # 5. Deduplication
            if finding.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(finding.fingerprint)
                findings.append(finding)

        return findings
