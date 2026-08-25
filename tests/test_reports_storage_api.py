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
async def test_api_health_and_forbidden_scan(tmp_path: Path) -> None:
    config = AppConfig(
        scope=ScopeConfig(domains=["example.com"]),
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
    )
    app = create_app(config=config)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/health")).json()["status"] == "ok"
        response = await client.post("/scans", json={"target": "outside.example.net"})
    assert response.status_code == 403
