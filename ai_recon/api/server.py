from __future__ import annotations

import hmac
import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ai_recon.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from ai_recon.core.audit import AuditStore
from ai_recon.core.auth import AuthError, AuthStore, Principal, Role
from ai_recon.core.config import AppConfig
from ai_recon.core.diff import diff_reports
from ai_recon.core.graph import build_asset_graph
from ai_recon.core.jobs import JobManager
from ai_recon.core.orchestrator import ReconOrchestrator
from ai_recon.core.scope import ScopeViolation
from ai_recon.models.entities import Asset
from ai_recon.reporting.reports import write_html
from ai_recon.storage.assets import AssetRegistry
from ai_recon.storage.database import ScanRepository


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


class BootstrapRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    bootstrap_key: str = Field(min_length=16, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class AddUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    role: Role = Role.ANALYST


class AssetMetadataRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    kind: str = Field(default="hostname", max_length=40)
    criticality: int = Field(default=50, ge=0, le=100)
    owner: str | None = Field(default=None, max_length=200)
    environment: str = Field(default="unknown", max_length=40)
    tags: list[str] = Field(default_factory=list, max_length=20)


def create_app(
    config: AppConfig | None = None,
    repository: ScanRepository | None = None,
    auth_required: bool = True,
) -> FastAPI:
    app = FastAPI(title="AI Reconnaissance Tool", version="0.4.0")
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("RECON_ALLOWED_HOSTS", "localhost,127.0.0.1").split(","),
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, limit=60, window_seconds=60)
    app.state.config = config or AppConfig.default()
    app.state.repository = repository or ScanRepository(app.state.config.database_url)
    app.state.auth = AuthStore(app.state.config.database_url)
    app.state.auth_required = auth_required
    app.state.jobs = JobManager(
        app.state.config, max_concurrency=app.state.config.limits.concurrency
    )
    app.state.audit = AuditStore(app.state.config.database_url)
    app.state.asset_registry = AssetRegistry(app.state.config.database_url)

    async def current_principal(
        authorization: Annotated[str | None, Header()] = None,
    ) -> Principal | None:
        if not app.state.auth_required:
            return None
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Bearer authentication required")
        try:
            return app.state.auth.resolve(authorization.split(" ", 1)[1].strip())
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require_principal(principal: Principal | None) -> Principal | None:
        if principal is None and app.state.auth_required:
            raise HTTPException(status_code=401, detail="Authentication required")
        return principal

    def organization_id(principal: Principal | None) -> str:
        actor = require_principal(principal)
        return actor.organization_id if actor else "local"

    def require_scan_role(principal: Principal | None) -> None:
        actor = require_principal(principal)
        if actor and actor.role not in {Role.OWNER, Role.ADMIN, Role.ANALYST}:
            raise HTTPException(status_code=403, detail="Viewer role cannot start scans")

    def scoped_report(scan_id: str, principal: Principal | None):
        report = app.state.repository.get(scan_id, organization_id(principal))
        if not report:
            raise HTTPException(status_code=404, detail="Scan not found")
        return report

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "ai-reconnaissance-tool", "version": "0.4.0"}

    @app.post("/auth/bootstrap")
    async def bootstrap(request: BootstrapRequest) -> dict[str, str]:
        configured_key = os.getenv("RECON_BOOTSTRAP_KEY")
        if not configured_key or not hmac.compare_digest(request.bootstrap_key, configured_key):
            raise HTTPException(
                status_code=403, detail="Bootstrap is disabled or the bootstrap key is invalid"
            )
        try:
            principal = app.state.auth.bootstrap(
                request.organization_name, str(request.email), request.password
            )
            token, _ = app.state.auth.authenticate(str(request.email), request.password)
        except (AuthError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        app.state.audit.record(principal.organization_id, "AUTH_BOOTSTRAP", principal.user_id)
        return {
            "access_token": token,
            "token_type": "bearer",
            "organization_id": principal.organization_id,
        }

    @app.post("/auth/login")
    async def login(request: LoginRequest) -> dict[str, str]:
        try:
            token, principal = app.state.auth.authenticate(str(request.email), request.password)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail="Invalid credentials") from exc
        app.state.audit.record(principal.organization_id, "AUTH_LOGIN", principal.user_id)
        return {
            "access_token": token,
            "token_type": "bearer",
            "organization_id": principal.organization_id,
            "role": principal.role.value,
        }

    @app.get("/me")
    async def me(principal: Principal | None = Depends(current_principal)) -> dict:
        actor = require_principal(principal)
        return (
            actor.model_dump(mode="json")
            if actor
            else {"mode": "local-development", "authenticated": False}
        )

    @app.post("/users")
    async def add_user(
        request: AddUserRequest, principal: Principal | None = Depends(current_principal)
    ) -> dict[str, str]:
        actor = require_principal(principal)
        if actor is None:
            raise HTTPException(status_code=403, detail="User management requires authentication")
        try:
            created = app.state.auth.add_user(
                actor, str(request.email), request.password, request.role
            )
        except (AuthError, ValueError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        app.state.audit.record(
            created.organization_id,
            "USER_CREATED",
            actor.user_id,
            str(created.email),
            {"role": created.role.value},
        )
        return {
            "user_id": created.user_id,
            "organization_id": created.organization_id,
            "email": str(created.email),
            "role": created.role.value,
        }

    @app.get("/assets")
    async def list_managed_assets(
        principal: Principal | None = Depends(current_principal),
    ) -> list[dict]:
        return [
            asset.model_dump(mode="json")
            for asset in app.state.asset_registry.list(organization_id(principal))
        ]

    @app.post("/assets")
    async def upsert_managed_asset(
        request: AssetMetadataRequest, principal: Principal | None = Depends(current_principal)
    ) -> dict:
        actor = require_principal(principal)
        if actor is None or actor.role not in {Role.OWNER, Role.ADMIN}:
            raise HTTPException(
                status_code=403,
                detail="Only organization owners or admins may manage asset metadata",
            )
        asset = app.state.asset_registry.upsert(
            actor.organization_id, Asset(**request.model_dump())
        )
        app.state.audit.record(
            actor.organization_id,
            "ASSET_METADATA_UPDATED",
            actor.user_id,
            asset.name,
            {"criticality": asset.criticality, "environment": asset.environment},
        )
        return asset.model_dump(mode="json")

    @app.get("/audit/verify")
    async def verify_audit(
        principal: Principal | None = Depends(current_principal),
    ) -> dict[str, bool]:
        actor = require_principal(principal)
        if actor is None or actor.role not in {Role.OWNER, Role.ADMIN}:
            raise HTTPException(
                status_code=403,
                detail="Only organization owners or admins may verify the audit chain",
            )
        return {"valid": app.state.audit.verify_chain(actor.organization_id)}

    @app.post("/scans")
    async def create_scan(
        request: ScanRequest, principal: Principal | None = Depends(current_principal)
    ) -> dict[str, str]:
        require_scan_role(principal)
        try:
            report = await ReconOrchestrator(app.state.config).scan(request.target)
        except ScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        actor_org = organization_id(principal)
        app.state.repository.save(
            report,
            organization_id=actor_org,
            created_by=principal.user_id if principal else "local",
        )
        app.state.audit.record(
            actor_org,
            "SCAN_COMPLETED",
            principal.user_id if principal else "local",
            request.target,
            {"scan_id": report.scan_id},
        )
        return {"scan_id": report.scan_id, "status": "completed"}

    @app.post("/jobs/scans")
    async def create_scan_job(
        request: ScanRequest, principal: Principal | None = Depends(current_principal)
    ) -> dict:
        require_scan_role(principal)
        actor = require_principal(principal)
        job = app.state.jobs.create(
            request.target, organization_id(principal), actor.user_id if actor else "local"
        )
        app.state.audit.record(
            job.organization_id,
            "SCAN_JOB_CREATED",
            job.created_by,
            request.target,
            {"job_id": job.job_id},
        )
        return job.model_dump(mode="json")

    @app.get("/jobs/{job_id}")
    async def get_job(
        job_id: str, principal: Principal | None = Depends(current_principal)
    ) -> dict:
        actor_org = organization_id(principal)
        job = app.state.jobs.get(job_id, actor_org)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        report = app.state.jobs.report(job_id, actor_org)
        if report:
            app.state.repository.save(report, organization_id=actor_org, created_by=job.created_by)
        app.state.audit.record(
            actor_org,
            "SCAN_JOB_VIEWED",
            job.created_by,
            job.target,
            {"job_id": job.job_id, "status": job.status.value},
        )
        return job.model_dump(mode="json")

    @app.delete("/jobs/{job_id}")
    async def cancel_job(
        job_id: str, principal: Principal | None = Depends(current_principal)
    ) -> dict[str, bool]:
        cancelled = await app.state.jobs.cancel(job_id, organization_id(principal))
        if not cancelled:
            raise HTTPException(status_code=404, detail="Active job not found")
        actor = require_principal(principal)
        app.state.audit.record(
            organization_id(principal),
            "SCAN_JOB_CANCELLED",
            actor.user_id if actor else "local",
            job_id,
        )
        return {"cancelled": True}

    @app.get("/scans/{scan_id}")
    async def get_scan(
        scan_id: str, principal: Principal | None = Depends(current_principal)
    ) -> dict:
        report = scoped_report(scan_id, principal)
        app.state.audit.record(
            organization_id(principal),
            "SCAN_VIEWED",
            principal.user_id if principal else "local",
            scan_id,
        )
        return report.model_dump(mode="json")

    @app.get("/scans/{scan_id}/assets")
    async def get_assets(
        scan_id: str, principal: Principal | None = Depends(current_principal)
    ) -> list[dict]:
        scoped_report(scan_id, principal)
        return app.state.repository.list_assets(scan_id, organization_id(principal))

    @app.get("/scans/{scan_id}/findings")
    async def get_findings(
        scan_id: str, principal: Principal | None = Depends(current_principal)
    ) -> list[dict]:
        scoped_report(scan_id, principal)
        return app.state.repository.list_findings(scan_id, organization_id(principal))

    @app.get("/scans/{scan_id}/graph")
    async def get_graph(
        scan_id: str, principal: Principal | None = Depends(current_principal)
    ) -> dict:
        return build_asset_graph(scoped_report(scan_id, principal)).to_cytoscape()

    @app.get("/scans/{scan_id}/diff/{previous_scan_id}")
    async def get_diff(
        scan_id: str,
        previous_scan_id: str,
        principal: Principal | None = Depends(current_principal),
    ) -> dict:
        current = scoped_report(scan_id, principal)
        previous = scoped_report(previous_scan_id, principal)
        return diff_reports(previous, current).model_dump(mode="json")

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    async def get_report(
        scan_id: str, principal: Principal | None = Depends(current_principal)
    ) -> HTMLResponse:
        report = scoped_report(scan_id, principal)
        path = write_html(report, f"/tmp/{scan_id}.html")
        app.state.audit.record(
            organization_id(principal),
            "REPORT_VIEWED",
            principal.user_id if principal else "local",
            scan_id,
        )
        return HTMLResponse(path.read_text())

    return app


app = create_app()
