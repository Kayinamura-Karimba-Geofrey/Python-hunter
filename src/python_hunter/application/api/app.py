"""FastAPI Application providing REST endpoints for Python Hunter."""

import uuid
from fastapi import FastAPI, HTTPException
from python_hunter.application.api.api_models import JobStatus, ScanRequest, ScanResponse, SystemInfoResponse
from python_hunter.application.services.security_app_service import SecurityApplicationService

app = FastAPI(
    title="Python Hunter Security Intelligence API",
    version="1.0.0",
    description="REST API for multi-language static application security testing, risk engine, policy enforcement, and historical regression intelligence.",
)

app_service = SecurityApplicationService()
jobs_store: dict[str, dict] = {}


@app.get("/health")
def health():
    return {"status": "HEALTHY", "version": "1.0.0"}


@app.get("/api/v1/system", response_model=SystemInfoResponse)
def get_system():
    return app_service.get_system_info()


@app.post("/api/v1/scans", response_model=ScanResponse)
def create_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())
    jobs_store[scan_id] = {
        "scan_id": scan_id,
        "status": JobStatus.COMPLETED,
        "result": app_service.execute_scan(req.target_path, req.profile),
    }
    return ScanResponse(scan_id=scan_id, status=JobStatus.COMPLETED, message="Scan executed successfully.")


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in jobs_store:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    return jobs_store[scan_id]
