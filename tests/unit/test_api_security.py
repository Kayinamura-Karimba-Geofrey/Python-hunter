"""Tests for REST API authentication, CORS, scan-target policy, and background scan jobs."""

import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from python_hunter.application.api.app import create_app
from python_hunter.application.api.security import (
    AuthenticationError,
    ScanTargetPolicy,
    TargetNotAllowedError,
    TokenService,
    hash_password,
    verify_password,
)
from python_hunter.application.services.security_app_service import SecurityApplicationService
from python_hunter.infrastructure.config.settings import Settings
from python_hunter.infrastructure.storage.scan_store import ScanResultStore

PASSWORD = "correct horse battery staple"
PASSWORD_HASH = hash_password(PASSWORD, iterations=1_000)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "project").mkdir(parents=True)
    (root / "project" / "app.py").write_text("print('hello')\n")
    return root


def _client(workspace: Path, **env: str) -> TestClient:
    base = {
        "PYH_ENV": "test",
        "PYH_SECRET_KEY": "unit-test-signing-key",
        "PYH_API_USERNAME": "analyst",
        "PYH_API_PASSWORD_HASH": PASSWORD_HASH,
        "PYH_API_WORKSPACE_ROOT": str(workspace),
    }
    base.update(env)
    settings = Settings.load_from_env(base)
    store = ScanResultStore(tempfile.mkdtemp(prefix="pyh-api-test-"))
    return TestClient(create_app(settings, SecurityApplicationService(store=store)))


def _token(client: TestClient) -> str:
    res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": PASSWORD})
    assert res.status_code == 200
    return str(res.json()["token"])


def test_password_hash_roundtrip() -> None:
    assert verify_password(PASSWORD, PASSWORD_HASH)
    assert not verify_password("wrong", PASSWORD_HASH)
    assert not verify_password(PASSWORD, "garbage")


def test_token_expiry_and_tampering() -> None:
    tokens = TokenService("k", ttl_minutes=1)
    token = tokens.issue("analyst", now=1_000)
    assert tokens.verify(token, now=1_030)["sub"] == "analyst"
    with pytest.raises(AuthenticationError):
        tokens.verify(token, now=1_061)
    header, claims, sig = token.split(".")
    with pytest.raises(AuthenticationError):
        tokens.verify(f"{header}.{claims}x.{sig}", now=1_030)
    with pytest.raises(AuthenticationError):
        TokenService("other-key", ttl_minutes=1).verify(token, now=1_030)


def test_login_rejects_any_credentials_when_unconfigured(workspace: Path) -> None:
    client = _client(workspace, PYH_API_USERNAME="", PYH_API_PASSWORD_HASH="")
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    assert res.status_code == 503


def test_login_rejects_wrong_password(workspace: Path) -> None:
    client = _client(workspace)
    res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "nope"})
    assert res.status_code == 401


def test_protected_endpoints_require_token(workspace: Path) -> None:
    client = _client(workspace)
    for path in ("/api/v1/findings", "/api/v1/dashboard/summary", "/api/v1/system"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    token = _token(client)
    res = client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json() == []


def test_health_is_public(workspace: Path) -> None:
    assert _client(workspace).get("/health").status_code == 200


def test_scan_target_outside_workspace_is_rejected(workspace: Path) -> None:
    client = _client(workspace)
    headers = {"Authorization": f"Bearer {_token(client)}"}
    for target in ("/etc", "../", "https://github.com/org/repo.git"):
        res = client.post("/api/v1/scans", json={"target_path": target}, headers=headers)
        assert res.status_code == 400, target
    res = client.post("/api/v1/secrets/scan", json={"workspace_path": "/etc"}, headers=headers)
    assert res.status_code == 400


def test_scan_runs_in_background_and_is_recorded(workspace: Path) -> None:
    client = _client(workspace)
    headers = {"Authorization": f"Bearer {_token(client)}"}
    res = client.post("/api/v1/scans", json={"target_path": "project"}, headers=headers)
    assert res.status_code == 202
    scan_id = res.json()["scan_id"]

    record = {}
    for _ in range(300):
        record = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()
        if record["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.1)
    assert record["status"] == "COMPLETED"
    assert record["target"] == str((workspace / "project").resolve())

    repos = client.get("/api/v1/repositories", headers=headers).json()
    assert [r["url_or_path"] for r in repos] == [record["target"]]
    audit = client.get("/api/v1/audit", headers=headers).json()
    assert any(a["event"] == "SCAN_EXECUTED" for a in audit)


def test_cors_allows_only_configured_origins(workspace: Path) -> None:
    client = _client(workspace, PYH_API_CORS_ORIGINS="https://dash.example.com")
    allowed = client.options(
        "/api/v1/findings",
        headers={"Origin": "https://dash.example.com", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "https://dash.example.com"
    denied = client.options(
        "/api/v1/findings",
        headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers


def test_wildcard_cors_is_refused(workspace: Path) -> None:
    with pytest.raises(Exception, match="Wildcard CORS"):
        Settings.load_from_env({"PYH_API_CORS_ORIGINS": "*"})


def test_target_policy_resolves_relative_paths(workspace: Path) -> None:
    policy = ScanTargetPolicy(str(workspace), allow_remote=False)
    assert policy.resolve("project") == str((workspace / "project").resolve())
    with pytest.raises(TargetNotAllowedError):
        policy.resolve("project/../../")
    remote = ScanTargetPolicy(str(workspace), allow_remote=True)
    assert remote.resolve("https://github.com/org/repo.git") == "https://github.com/org/repo.git"
    with pytest.raises(TargetNotAllowedError):
        remote.resolve("git@github.com:org/repo.git")
