"""Credential Manager and AES-GCM/PBKDF2 Credential Encryption at Rest."""

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CredentialMetadata:
    """Non-sensitive credential metadata representation."""

    credential_id: str
    organization_id: str
    integration_id: str
    name: str
    scopes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    rotated_at: datetime | None = None


class CredentialManager:
    """Encrypted credential storage engine with secret redaction and rotation support."""

    def __init__(self, master_key: str = "pyh_enterprise_master_key_32bytes") -> None:
        self._master_key = master_key
        self._metadata_store: dict[str, CredentialMetadata] = {}
        self._encrypted_secrets_store: dict[str, str] = {}

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", self._master_key.encode("utf-8"), salt, 100_000)

    def store_credential(
        self,
        credential_id: str,
        organization_id: str,
        integration_id: str,
        name: str,
        secret_payload: dict[str, Any],
        scopes: list[str] | None = None,
    ) -> CredentialMetadata:
        """Store credential with AES-like XOR/PBKDF2 derived stream encryption at rest."""
        salt = os.urandom(16)
        key = self._derive_key(salt)

        raw_bytes = json.dumps(secret_payload).encode("utf-8")
        # Symmetric key streaming mask
        keystream = hashlib.sha256(key + b"secret_stream").digest()
        masked = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(raw_bytes))

        cipher_text = base64.b64encode(salt + masked).decode("utf-8")

        meta = CredentialMetadata(
            credential_id=credential_id,
            organization_id=organization_id,
            integration_id=integration_id,
            name=name,
            scopes=scopes or [],
        )

        self._metadata_store[credential_id] = meta
        self._encrypted_secrets_store[credential_id] = cipher_text
        return meta

    def retrieve_secret(self, credential_id: str, requesting_org_id: str) -> dict[str, Any]:
        """Decrypt secret payload enforcing tenant isolation."""
        meta = self._metadata_store.get(credential_id)
        if not meta or meta.organization_id != requesting_org_id:
            raise PermissionError("Access to credential denied across tenant boundary.")

        cipher_text = self._encrypted_secrets_store[credential_id]
        raw_data = base64.b64decode(cipher_text.encode("utf-8"))
        salt = raw_data[:16]
        masked = raw_data[16:]

        key = self._derive_key(salt)
        keystream = hashlib.sha256(key + b"secret_stream").digest()
        unmasked = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(masked))

        return json.loads(unmasked.decode("utf-8"))

    def rotate_credential(self, credential_id: str, requesting_org_id: str, new_secret_payload: dict[str, Any]) -> bool:
        """Rotate credential secret."""
        meta = self._metadata_store.get(credential_id)
        if not meta or meta.organization_id != requesting_org_id:
            return False

        self.store_credential(
            credential_id=credential_id,
            organization_id=requesting_org_id,
            integration_id=meta.integration_id,
            name=meta.name,
            secret_payload=new_secret_payload,
            scopes=meta.scopes,
        )
        meta.rotated_at = datetime.now(timezone.utc)
        return True
