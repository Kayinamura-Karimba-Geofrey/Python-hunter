"""API Pydantic Schemas for Python Hunter REST API."""

from enum import Enum
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Local path or Git repository URL to scan")
    profile: str = Field("strict", description="Scan profile (strict, default, production)")


class ScanResponse(BaseModel):
    scan_id: str
    status: JobStatus
    message: str


class SystemInfoResponse(BaseModel):
    name: str
    version: str
    supported_languages: list[str]
    supported_frameworks: list[str]
    status: str
