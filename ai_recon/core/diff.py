from __future__ import annotations

from pydantic import BaseModel, Field

from ai_recon.models.entities import ScanReport


class ScanDiff(BaseModel):
    previous_scan_id: str | None = None
    current_scan_id: str
    added_assets: list[str] = Field(default_factory=list)
    removed_assets: list[str] = Field(default_factory=list)
    added_services: list[str] = Field(default_factory=list)
    removed_services: list[str] = Field(default_factory=list)
    added_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)


def diff_reports(previous: ScanReport | None, current: ScanReport) -> ScanDiff:
    previous_assets = {asset.name for asset in previous.assets} if previous else set()
    current_assets = {asset.name for asset in current.assets}
    previous_service_items = list(previous.services) if previous else []
    if previous:
        previous_service_items.extend(
            service for asset in previous.assets for service in asset.services
        )
    current_service_items = list(current.services)
    current_service_items.extend(service for asset in current.assets for service in asset.services)
    previous_services = {
        f"{service.asset}:{service.protocol}/{service.port}" for service in previous_service_items
    }
    current_services = {
        f"{service.asset}:{service.protocol}/{service.port}" for service in current_service_items
    }
    previous_findings = (
        {finding.type + ":" + finding.target for finding in previous.findings}
        if previous
        else set()
    )
    current_findings = {finding.type + ":" + finding.target for finding in current.findings}
    return ScanDiff(
        previous_scan_id=previous.scan_id if previous else None,
        current_scan_id=current.scan_id,
        added_assets=sorted(current_assets - previous_assets),
        removed_assets=sorted(previous_assets - current_assets),
        added_services=sorted(current_services - previous_services),
        removed_services=sorted(previous_services - current_services),
        added_findings=sorted(current_findings - previous_findings),
        resolved_findings=sorted(previous_findings - current_findings),
    )
