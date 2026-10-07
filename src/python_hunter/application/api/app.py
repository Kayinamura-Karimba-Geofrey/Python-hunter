"""FastAPI Application providing REST endpoints for Python Hunter."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from python_hunter import __version__
from python_hunter.application.api.api_models import (
    ApiEndpointModel,
    AttackPathModel,
    AuditLogModel,
    ComplianceControlModel,
    DashboardSummaryResponse,
    DependencyModel,
    FindingModel,
    FrameworkMetadataModel,
    GitHubInstallationModel,
    JobStatus,
    LanguageMetadataModel,
    LoginRequest,
    LoginResponse,
    PolicyModel,
    PolyglotScanRequest,
    PolyglotScanResponse,
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
)
from python_hunter.application.api.scan_jobs import ScanJobManager
from python_hunter.application.api.security import (
    AuthenticationError,
    Authenticator,
    ScanTargetPolicy,
    TargetNotAllowedError,
)
from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.domain.github.webhook_handler import WebhookValidationError
from python_hunter.infrastructure.config.settings import Settings

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    service: SecurityApplicationService | None = None,
) -> FastAPI:
    """Build the API with authentication, CORS, and scan-target policy taken from settings."""
    settings = settings or Settings.load_from_env()
    app_service = service or SecurityApplicationService()
    authenticator = Authenticator(settings)
    target_policy = ScanTargetPolicy(settings.api.workspace_root, settings.api.allow_remote_targets)
    jobs = ScanJobManager(app_service, max_workers=settings.api.max_concurrent_scans)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        jobs.shutdown()

    app = FastAPI(
        title="Python Hunter Security Intelligence API",
        version=__version__,
        lifespan=lifespan,
        description="REST API for multi-language static application security testing, risk engine, policy enforcement, and historical regression intelligence.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=False,  # bearer tokens, not cookies
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    def require_user(authorization: str | None = Header(None)) -> str:
        try:
            return authenticator.authenticate(authorization)
        except AuthenticationError:
            raise HTTPException(
                status_code=401, detail="Not authenticated.", headers={"WWW-Authenticate": "Bearer"}
            ) from None

    def allowed_target(target: str) -> str:
        try:
            return target_policy.resolve(target)
        except TargetNotAllowedError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

    def run_workspace_scan(fn: Callable[..., dict[str, Any]], workspace_path: str, **kwargs: Any) -> dict[str, Any]:
        path = allowed_target(workspace_path)
        try:
            return fn(path, **kwargs)
        except Exception:
            logger.exception("Workspace scan failed for %s", path)
            raise HTTPException(status_code=500, detail="Scan failed; see server logs.") from None

    # Public endpoints

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "HEALTHY", "version": __version__}

    @app.post("/api/v1/auth/login", response_model=LoginResponse)
    def login(req: LoginRequest) -> LoginResponse:
        if not authenticator.configured:
            raise HTTPException(
                status_code=503,
                detail="API authentication is not configured. Set PYH_API_USERNAME and PYH_API_PASSWORD_HASH.",
            )
        try:
            token = authenticator.login(req.username, req.password)
        except AuthenticationError:
            app_service.store.append_audit("LOGIN", req.username[:128], "api", "FAILURE")
            raise HTTPException(status_code=401, detail="Invalid username or password.") from None
        app_service.store.append_audit("LOGIN", req.username, "api", "SUCCESS")
        return LoginResponse(token=token, user={"id": req.username, "username": req.username, "role": "Security Engineer"})

    @app.post("/api/v1/github/webhooks")
    async def handle_github_webhook(
        request: Request,
        x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
        x_github_delivery: str | None = Header(None, alias="X-GitHub-Delivery"),
        x_github_event: str | None = Header("ping", alias="X-GitHub-Event"),
    ) -> dict[str, Any]:
        # Authenticated by the HMAC signature rather than a bearer token.
        raw_body = await request.body()
        try:
            return app_service.process_github_webhook(
                raw_body=raw_body,
                signature_header=x_hub_signature_256,
                delivery_id=x_github_delivery,
                event_type=x_github_event or "ping",
            )
        except WebhookValidationError as e:
            # These messages are written by the validator and describe only the request.
            raise HTTPException(status_code=400, detail=str(e)) from None
        except Exception:
            logger.exception("Webhook delivery %s failed", x_github_delivery)
            raise HTTPException(status_code=500, detail="Webhook processing failed.") from None

    # Authenticated endpoints

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(require_user)])

    @api.get("/system", response_model=SystemInfoResponse)
    def get_system() -> dict[str, Any]:
        return app_service.get_system_info()

    @api.get("/dashboard/summary", response_model=DashboardSummaryResponse)
    def get_dashboard_summary() -> dict[str, Any]:
        return app_service.get_dashboard_summary()

    @api.get("/repositories", response_model=list[RepositoryModel])
    def list_repositories() -> list[dict[str, Any]]:
        return app_service.list_repositories()

    @api.post("/scans", response_model=ScanResponse, status_code=202)
    def create_scan(req: ScanRequest, user: str = Depends(require_user)) -> ScanResponse:
        target = allowed_target(req.target_path)
        record = jobs.submit(target, req.profile, actor=user)
        return ScanResponse(scan_id=record["scan_id"], status=JobStatus.QUEUED, message="Scan queued.")

    @api.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, Any]:
        record = jobs.get(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Scan ID not found.")
        return record

    @api.get("/findings", response_model=list[FindingModel])
    def list_findings(
        severity: str | None = Query(None),
        status: str | None = Query(None),
        search: str | None = Query(None),
    ) -> list[dict[str, Any]]:
        return app_service.list_findings(severity=severity, status=status, search=search)

    @api.get("/findings/{finding_id}", response_model=FindingModel)
    def get_finding_detail(finding_id: str) -> dict[str, Any]:
        finding = app_service.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        return finding

    @api.get("/attack-paths", response_model=list[AttackPathModel])
    def list_attack_paths() -> list[dict[str, Any]]:
        return app_service.list_attack_paths()

    @api.get("/dependencies", response_model=list[DependencyModel])
    def list_dependencies() -> list[dict[str, Any]]:
        return app_service.list_dependencies()

    @api.get("/services", response_model=list[ServiceModel])
    def list_services() -> list[dict[str, Any]]:
        return app_service.list_services()

    @api.get("/apis", response_model=list[ApiEndpointModel])
    def list_apis() -> list[dict[str, Any]]:
        return app_service.list_apis()

    @api.get("/history", response_model=list[SecurityHistorySnapshotModel])
    def list_history() -> list[dict[str, Any]]:
        return app_service.list_history()

    @api.get("/regressions", response_model=list[RegressionModel])
    def list_regressions() -> list[dict[str, Any]]:
        return app_service.list_regressions()

    @api.get("/policies", response_model=list[PolicyModel])
    def list_policies() -> list[dict[str, Any]]:
        return app_service.list_policies()

    @api.get("/compliance", response_model=list[ComplianceControlModel])
    def list_compliance() -> list[dict[str, Any]]:
        return app_service.list_compliance()

    @api.get("/reports", response_model=list[ReportModel])
    def list_reports() -> list[dict[str, Any]]:
        return app_service.list_reports()

    @api.get("/audit", response_model=list[AuditLogModel])
    def list_audit_logs() -> list[dict[str, Any]]:
        return app_service.list_audit_logs()

    @api.get("/github/installations", response_model=list[GitHubInstallationModel])
    def list_github_installations() -> list[dict[str, Any]]:
        return app_service.list_github_installations()

    @api.get("/github/webhooks/status", response_model=WebhookStatusModel)
    def get_webhook_status() -> dict[str, Any]:
        return app_service.get_webhook_status()

    @api.get("/github/pull-requests", response_model=list[PullRequestSummaryModel])
    def list_pull_requests() -> list[dict[str, Any]]:
        return app_service.list_pull_requests()

    @api.get("/github/pull-requests/{pr_id}")
    def get_pull_request_detail(pr_id: str) -> dict[str, Any]:
        detail = app_service.get_pull_request_detail(pr_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Pull request not found.")
        return detail

    @api.get("/languages", response_model=list[LanguageMetadataModel])
    def list_languages(
        language: str | None = Query(None, description="Filter by language identifier or alias"),
    ) -> list[dict[str, Any]]:
        return app_service.list_languages(language)

    @api.get("/languages/{language}", response_model=LanguageMetadataModel)
    def get_language(language: str) -> dict[str, Any]:
        langs = app_service.list_languages(language)
        if not langs:
            raise HTTPException(status_code=404, detail="Language not supported.")
        return langs[0]

    @api.get("/frameworks", response_model=list[FrameworkMetadataModel])
    def list_frameworks(
        language: str | None = Query(None, description="Filter frameworks by language"),
    ) -> list[dict[str, Any]]:
        return app_service.list_frameworks(language)

    @api.get("/frameworks/{framework}", response_model=FrameworkMetadataModel)
    def get_framework(framework: str) -> dict[str, Any]:
        fws = [f for f in app_service.list_frameworks() if f["name"].lower() == framework.lower()]
        if not fws:
            raise HTTPException(status_code=404, detail="Framework not found.")
        return fws[0]

    @api.post("/languages/polyglot-scan", response_model=PolyglotScanResponse)
    def polyglot_scan(req: PolyglotScanRequest) -> dict[str, Any]:
        return run_workspace_scan(
            app_service.scan_polyglot_workspace,
            req.workspace_path,
            selected_languages=req.selected_languages,
            selected_frameworks=req.selected_frameworks,
        )

    @api.post("/sast/interprocedural-scan")
    def interprocedural_scan(req: PolyglotScanRequest) -> dict[str, Any]:
        return run_workspace_scan(
            app_service.execute_interprocedural_scan,
            req.workspace_path,
            options={"selected_languages": req.selected_languages},
        )

    @api.post("/sca/scan")
    def sca_scan(req: PolyglotScanRequest) -> dict[str, Any]:
        return run_workspace_scan(
            app_service.execute_sca_scan,
            req.workspace_path,
            options={"selected_languages": req.selected_languages},
        )

    @api.get("/dependencies/vulnerabilities")
    def sca_vulnerabilities(workspace_path: str = Query(".")) -> dict[str, Any]:
        return run_workspace_scan(app_service.execute_sca_scan, workspace_path)

    @api.post("/secrets/scan")
    def secrets_scan(req: PolyglotScanRequest) -> dict[str, Any]:
        return run_workspace_scan(app_service.execute_secrets_scan, req.workspace_path, scan_history=True)

    @api.get("/secrets")
    @api.get("/secrets/history")
    @api.get("/secrets/exposures")
    def secrets_view(workspace_path: str = Query(".")) -> dict[str, Any]:
        return run_workspace_scan(app_service.execute_secrets_scan, workspace_path, scan_history=True)

    @api.post("/infrastructure/scan")
    def infrastructure_scan(req: PolyglotScanRequest) -> dict[str, Any]:
        return run_workspace_scan(app_service.execute_infrastructure_scan, req.workspace_path)

    @api.get("/infrastructure")
    @api.get("/infrastructure/resources")
    @api.get("/infrastructure/findings")
    @api.get("/infrastructure/graph")
    def infrastructure_view(workspace_path: str = Query(".")) -> dict[str, Any]:
        return run_workspace_scan(app_service.execute_infrastructure_scan, workspace_path)

    app.include_router(api)
    return app


app = create_app()
