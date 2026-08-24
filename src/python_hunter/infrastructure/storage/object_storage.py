"""Object Storage Service for SARIF artifacts, scan logs, and reports."""

import os
from abc import ABC, abstractmethod


class ObjectStorageService(ABC):
    """Abstract Object Storage interface (Local FS / S3 compatible)."""

    @abstractmethod
    def put_artifact(self, artifact_key: str, content: bytes) -> str:
        pass

    @abstractmethod
    def get_artifact(self, artifact_key: str) -> bytes:
        pass


class LocalObjectStorage(ObjectStorageService):
    """Local Filesystem Object Storage implementation."""

    def __init__(self, base_dir: str = "/tmp/pyh_artifacts") -> None:
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def put_artifact(self, artifact_key: str, content: bytes) -> str:
        file_path = os.path.join(self.base_dir, artifact_key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(content)
        return file_path

    def get_artifact(self, artifact_key: str) -> bytes:
        file_path = os.path.join(self.base_dir, artifact_key)
        with open(file_path, "rb") as f:
            return f.read()
