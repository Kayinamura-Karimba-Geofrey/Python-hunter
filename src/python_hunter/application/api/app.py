"""FastAPI Application providing REST endpoints for Python Hunter."""

import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from python_hunter.application.api.api_models import (
    ApiEndpointModel,
    AttackPathModel,
    AuditLogModel,
    ComplianceControlModel,
    DashboardSummaryResponse,
    DependencyModel,
    FindingModel,
    GitHubInstallationModel,
    JobStatus,
    LoginRequest,
    LoginResponse,
    PolicyModel,
    PullRequestSummaryModel,
    RegressionModel,
    ReportModel,
    RepositoryModel,
    ScanRequest,
    ScanResponse,
    SecurityHistorySnapshotModel,
    ServiceModel,
    SystemInfoResponse,
    WebhookStatusModel,
    LanguageMetadataModel,
    FrameworkMetadataModel,
    PolyglotScanRequest,
    PolyglotScanResponse,
)
from python_hunter.application.services.security_app_service import SecurityApplicationService

app = FastAPI(
    title="Python Hunter Security Intelligence API",
    version="1.0.0",
    description="REST API for multi-language static application security testing, risk engine, policy enforcement, and historical regression intelligence.",
)

# Enable CORS for Vite frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app_service = SecurityApplicationService()
jobs_store: dict[str, dict] = {}


@app.get("/health")
def health():
    return {"status": "HEALTHY", "version": "1.0.0"}


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    if req.username and req.password:
        return LoginResponse(
            token="pyh_secret_jwt_token_demo_987654321",
            user={
                "id": "usr-1",
                "username": req.username,
                "role": "Security Engineer",
                "email": f"{req.username}@pythonhunter.io",
            },
        )
    raise HTTPException(status_code=401, detail="Invalid username or password.")


@app.get("/api/v1/system", response_model=SystemInfoResponse)
def get_system():
    return app_service.get_system_info()


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary():
    return app_service.get_dashboard_summary()


@app.get("/api/v1/repositories", response_model=list[RepositoryModel])
def list_repositories():
    return app_service.list_repositories()


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


@app.get("/api/v1/findings", response_model=list[FindingModel])
def list_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    return app_service.list_findings(severity=severity, status=status, search=search)


@app.get("/api/v1/findings/{finding_id}", response_model=FindingModel)
def get_finding_detail(finding_id: str):
    findings = app_service.list_findings()
    for f in findings:
        if f["id"] == finding_id:
            return f
    raise HTTPException(status_code=404, detail="Finding not found.")


@app.get("/api/v1/attack-paths", response_model=list[AttackPathModel])
def list_attack_paths():
    return app_service.list_attack_paths()


@app.get("/api/v1/dependencies", response_model=list[DependencyModel])
def list_dependencies():
    return app_service.list_dependencies()


@app.get("/api/v1/services", response_model=list[ServiceModel])
def list_services():
    return app_service.list_services()


@app.get("/api/v1/apis", response_model=list[ApiEndpointModel])
def list_apis():
    return app_service.list_apis()


@app.get("/api/v1/history", response_model=list[SecurityHistorySnapshotModel])
def list_history():
    return app_service.list_history()


@app.get("/api/v1/regressions", response_model=list[RegressionModel])
def list_regressions():
    return app_service.list_regressions()


@app.get("/api/v1/policies", response_model=list[PolicyModel])
def list_policies():
    return app_service.list_policies()


@app.get("/api/v1/compliance", response_model=list[ComplianceControlModel])
def list_compliance():
    return app_service.list_compliance()


@app.get("/api/v1/reports", response_model=list[ReportModel])
def list_reports():
    return app_service.list_reports()


@app.get("/api/v1/audit", response_model=list[AuditLogModel])
def list_audit_logs():
    return app_service.list_audit_logs()


@app.get("/api/v1/github/installations", response_model=list[GitHubInstallationModel])
def list_github_installations():
    return app_service.list_github_installations()


@app.get("/api/v1/github/webhooks/status", response_model=WebhookStatusModel)
def get_webhook_status():
    return app_service.get_webhook_status()


@app.post("/api/v1/github/webhooks")
async def handle_github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
    x_github_event: Optional[str] = Header("ping", alias="X-GitHub-Event"),
):
    raw_body = await request.body()
    try:
        res = app_service.process_github_webhook(
            raw_body=raw_body,
            signature_header=x_hub_signature_256,
            delivery_id=x_github_delivery,
            event_type=x_github_event or "ping",
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/github/pull-requests", response_model=list[PullRequestSummaryModel])
def list_pull_requests():
    return app_service.list_pull_requests()


@app.get("/api/v1/github/pull-requests/{pr_id}")
def get_pull_request_detail(pr_id: str):
    return app_service.get_pull_request_detail(pr_id)


@app.get("/api/v1/languages", response_model=list[LanguageMetadataModel])
def list_languages(language: Optional[str] = Query(None, description="Filter by language identifier or alias")):
    return app_service.list_languages(language)


@app.get("/api/v1/languages/{language}", response_model=LanguageMetadataModel)
def get_language(language: str):
    langs = app_service.list_languages(language)
    if not langs:
        raise HTTPException(status_code=404, detail=f"Language '{language}' not supported")
    return langs[0]


@app.get("/api/v1/frameworks", response_model=list[FrameworkMetadataModel])
def list_frameworks(language: Optional[str] = Query(None, description="Filter frameworks by language")):
    return app_service.list_frameworks(language)


@app.get("/api/v1/frameworks/{framework}", response_model=FrameworkMetadataModel)
def get_framework(framework: str):
    fws = [f for f in app_service.list_frameworks() if f["name"].lower() == framework.lower()]
    if not fws:
        raise HTTPException(status_code=404, detail=f"Framework '{framework}' not found")
    return fws[0]


@app.post("/api/v1/languages/polyglot-scan", response_model=PolyglotScanResponse)
def polyglot_scan(req: PolyglotScanRequest):
    return app_service.scan_polyglot_workspace(
        workspace_path=req.workspace_path,
        selected_languages=req.selected_languages,
        selected_frameworks=req.selected_frameworks,
    )

