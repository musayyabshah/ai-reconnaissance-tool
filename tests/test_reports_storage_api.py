from pathlib import Path

import httpx
import pytest

from ai_recon.api.server import create_app
from ai_recon.core.config import AppConfig
from ai_recon.models.entities import ScanReport, ScopeConfig, Target
from ai_recon.reporting.reports import write_html, write_json
from ai_recon.storage.database import ScanRepository


def test_reports_and_repository(tmp_path: Path) -> None:
    report = ScanReport(target=Target(value="example.com", authorized=True))
    json_path = write_json(report, tmp_path / "report.json")
    html_path = write_html(report, tmp_path / "report.html")
    assert json_path.exists() and "example.com" in json_path.read_text()
    assert html_path.exists() and "AI Reconnaissance Report" in html_path.read_text()
    repo = ScanRepository(f"sqlite:///{tmp_path / 'recon.db'}")
    repo.save(report)
    assert repo.get(report.scan_id).scan_id == report.scan_id


@pytest.mark.asyncio
async def test_api_multi_user_auth_and_tenant_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECON_BOOTSTRAP_KEY", "local-bootstrap-key-12345")
    config = AppConfig(
        scope=ScopeConfig(domains=["example.com"]),
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
    )
    app = create_app(config=config)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/me")).status_code == 401
        bootstrap = await client.post(
            "/auth/bootstrap",
            json={
                "organization_name": "Example Security",
                "email": "owner@example.com",
                "password": "correct-horse-battery-staple",
                "bootstrap_key": "local-bootstrap-key-12345",
            },
        )
        assert bootstrap.status_code == 200
        token = bootstrap.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        me = await client.get("/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["role"] == "owner"
        add_user = await client.post(
            "/users",
            headers=headers,
            json={
                "email": "analyst@example.com",
                "password": "another-correct-password",
                "role": "analyst",
            },
        )
        assert add_user.status_code == 200
        unauthenticated_scan = await client.post("/scans", json={"target": "example.com"})
        assert unauthenticated_scan.status_code == 401


@pytest.mark.asyncio
async def test_local_mode_rejects_out_of_scope_scan(tmp_path: Path) -> None:
    config = AppConfig(
        scope=ScopeConfig(domains=["example.com"]),
        database_url=f"sqlite:///{tmp_path / 'local.db'}",
    )
    app = create_app(config=config, auth_required=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        response = await client.post("/scans", json={"target": "outside.example.net"})
    assert response.status_code == 403
