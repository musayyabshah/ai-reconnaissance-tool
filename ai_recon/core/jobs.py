from __future__ import annotations

import asyncio
import secrets
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel

from ai_recon.core.config import AppConfig
from ai_recon.core.orchestrator import ReconOrchestrator
from ai_recon.core.scope import ScopeViolation
from ai_recon.models.entities import ScanReport


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanJob(BaseModel):
    job_id: str
    organization_id: str
    created_by: str
    target: str
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime
    updated_at: datetime
    scan_id: str | None = None
    error: str | None = None


class JobManager:
    def __init__(self, config: AppConfig, max_concurrency: int = 2) -> None:
        self.config = config
        self._jobs: dict[str, ScanJob] = {}
        self._reports: dict[str, ScanReport] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def create(self, target: str, organization_id: str, created_by: str) -> ScanJob:
        now = datetime.now(timezone.utc)
        job = ScanJob(
            job_id=f"job-{secrets.token_hex(8)}",
            organization_id=organization_id,
            created_by=created_by,
            target=target,
            created_at=now,
            updated_at=now,
        )
        self._jobs[job.job_id] = job
        self._tasks[job.job_id] = asyncio.create_task(self._run(job.job_id))
        return job

    async def _run(self, job_id: str) -> None:
        job = self._jobs[job_id]
        self._jobs[job_id] = job.model_copy(
            update={"status": JobStatus.RUNNING, "updated_at": datetime.now(timezone.utc)}
        )
        try:
            async with self._semaphore:
                report = await ReconOrchestrator(self.config).scan(job.target)
            self._reports[job_id] = report
            self._jobs[job_id] = self._jobs[job_id].model_copy(
                update={
                    "status": JobStatus.COMPLETED,
                    "scan_id": report.scan_id,
                    "updated_at": datetime.now(timezone.utc),
                }
            )
        except asyncio.CancelledError:
            self._jobs[job_id] = self._jobs[job_id].model_copy(
                update={"status": JobStatus.CANCELLED, "updated_at": datetime.now(timezone.utc)}
            )
        except (ScopeViolation, Exception) as exc:
            self._jobs[job_id] = self._jobs[job_id].model_copy(
                update={
                    "status": JobStatus.FAILED,
                    "error": str(exc),
                    "updated_at": datetime.now(timezone.utc),
                }
            )

    def get(self, job_id: str, organization_id: str) -> ScanJob | None:
        job = self._jobs.get(job_id)
        return job if job and job.organization_id == organization_id else None

    def report(self, job_id: str, organization_id: str) -> ScanReport | None:
        job = self.get(job_id, organization_id)
        return self._reports.get(job_id) if job else None

    async def cancel(self, job_id: str, organization_id: str) -> bool:
        job = self.get(job_id, organization_id)
        task = self._tasks.get(job_id)
        if not job or not task or task.done():
            return False
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return True
