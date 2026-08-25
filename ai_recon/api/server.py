from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ai_recon.core.config import AppConfig
from ai_recon.core.orchestrator import ReconOrchestrator
from ai_recon.core.scope import ScopeViolation
from ai_recon.reporting.reports import write_html
from ai_recon.storage.database import ScanRepository


class ScanRequest(BaseModel):
    target: str
    config_path: str = "config.yaml"


def create_app(
    config: AppConfig | None = None, repository: ScanRepository | None = None
) -> FastAPI:
    app = FastAPI(title="AI Reconnaissance Tool", version="0.1.0")
    app.state.config = config or AppConfig.default()
    app.state.repository = repository or ScanRepository(app.state.config.database_url)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "ai-reconnaissance-tool"}

    @app.post("/scans")
    async def create_scan(request: ScanRequest) -> dict[str, str]:
        try:
            report = await ReconOrchestrator(app.state.config).scan(request.target)
        except ScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        app.state.repository.save(report)
        return {"scan_id": report.scan_id, "status": "completed"}

    @app.get("/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict:
        report = app.state.repository.get(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail="Scan not found")
        return report.model_dump(mode="json")

    @app.get("/scans/{scan_id}/assets")
    async def get_assets(scan_id: str) -> list[dict]:
        if not app.state.repository.get(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        return app.state.repository.list_assets(scan_id)

    @app.get("/scans/{scan_id}/findings")
    async def get_findings(scan_id: str) -> list[dict]:
        if not app.state.repository.get(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        return app.state.repository.list_findings(scan_id)

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    async def get_report(scan_id: str) -> HTMLResponse:
        report = app.state.repository.get(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail="Scan not found")
        path = write_html(report, f"/tmp/{scan_id}.html")
        return HTMLResponse(path.read_text())

    return app


app = create_app()
