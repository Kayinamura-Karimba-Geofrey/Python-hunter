"""Tamper-Evident Evidence Engine for Automated & Manual Evidence Collection."""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from python_hunter.domain.compliance.models import ComplianceEvidenceModel


class EvidenceEngine:
    """Collects, stores, validates, and manages tamper-evident compliance evidence."""

    MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
    ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".json", ".csv", ".txt", ".md"}

    def __init__(self) -> None:
        self._evidence_store: Dict[str, ComplianceEvidenceModel] = {}

    def collect_automated_scan_evidence(
        self,
        control_id: str,
        scan_result_summary: Dict[str, Any],
        organization_id: str = "org-default"
    ) -> ComplianceEvidenceModel:
        """Automated evidence collection from Python Hunter scan outputs."""
        ev_id = f"evd-auto-{uuid.uuid4().hex[:8]}"
        evidence = ComplianceEvidenceModel(
            evidence_id=ev_id,
            control_id=control_id,
            source="Python Hunter Automated Scanner",
            details=scan_result_summary,
            organization_id=organization_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            status="VALID",
            collected_by="system-automated-collector"
        )
        self._evidence_store[ev_id] = evidence
        return evidence

    def store_manual_evidence(
        self,
        control_id: str,
        file_name: str,
        content_bytes: bytes,
        uploaded_by: str,
        organization_id: str = "org-default"
    ) -> ComplianceEvidenceModel:
        """Stores manually uploaded evidence document or attestation with validation."""
        # 1. File extension validation
        ext = os.path.splitext(file_name)[1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"Unsupported evidence file extension '{ext}'. Allowed: {self.ALLOWED_EXTENSIONS}")

        # 2. File size validation
        if len(content_bytes) > self.MAX_FILE_SIZE_BYTES:
            raise ValueError(f"Evidence file size ({len(content_bytes)} bytes) exceeds maximum limit of 10MB.")

        ev_id = f"evd-manual-{uuid.uuid4().hex[:8]}"
        details = {
            "file_name": file_name,
            "size_bytes": len(content_bytes),
            "type": "Manual Upload / Attestation"
        }
        evidence = ComplianceEvidenceModel(
            evidence_id=ev_id,
            control_id=control_id,
            source=f"Manual Upload ({file_name})",
            details=details,
            organization_id=organization_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
            status="VALID",
            collected_by=uploaded_by
        )
        self._evidence_store[ev_id] = evidence
        return evidence

    def verify_integrity(self, evidence_id: str) -> bool:
        """Verifies tamper-evident content hash for evidence records."""
        ev = self._evidence_store.get(evidence_id)
        if not ev:
            return False
        import hashlib
        raw_str = f"{ev.evidence_id}:{ev.control_id}:{ev.source}:{str(ev.details)}"
        calculated = hashlib.sha256(raw_str.encode('utf-8')).hexdigest()
        return calculated == ev.content_hash

    def list_evidence_for_control(self, control_id: str, org_id: str = "org-default") -> List[ComplianceEvidenceModel]:
        return [
            ev for ev in self._evidence_store.values()
            if ev.control_id == control_id and ev.organization_id == org_id
        ]
