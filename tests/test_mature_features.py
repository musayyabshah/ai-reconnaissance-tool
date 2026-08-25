from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import respx

from ai_recon.analyzers.vulnerability import SafeVulnerabilityIndicatorEngine
from ai_recon.collectors.http import HTTPCollector
from ai_recon.collectors.threatintel import ThreatIntelEnricher
from ai_recon.core.audit import AuditStore
from ai_recon.core.auth import AuthStore, Role
from ai_recon.core.diff import diff_reports
from ai_recon.core.graph import build_asset_graph
from ai_recon.core.scope import ScopeEngine
from ai_recon.models.entities import (
    Asset,
    HTTPObservation,
    ScanReport,
    ScopeConfig,
    Service,
    Target,
)
from ai_recon.models.vulnerability import DetectionRule


def test_auth_store_hashes_passwords_and_enforces_roles(tmp_path: Path) -> None:
    store = AuthStore(f"sqlite:///{tmp_path / 'auth.db'}")
    owner = store.bootstrap("Acme", "owner@example.com", "correct-horse-battery-staple")
    token, principal = store.authenticate("owner@example.com", "correct-horse-battery-staple")
    assert store.resolve(token).user_id == owner.user_id
    assert principal.role is Role.OWNER
    analyst = store.add_user(
        principal, "analyst@example.com", "another-correct-password", Role.ANALYST
    )
    assert analyst.organization_id == owner.organization_id
    with pytest.raises(ValueError):
        store.authenticate("owner@example.com", "wrong-password")
    with pytest.raises(ValueError):
        store.add_user(analyst, "viewer@example.com", "third-correct-password", Role.VIEWER)


def test_graph_and_scan_diff() -> None:
    previous = ScanReport(target=Target(value="example.com"), assets=[Asset(name="example.com")])
    current = ScanReport(
        target=Target(value="example.com"),
        assets=[
            Asset(
                name="example.com",
                services=[Service(asset="example.com", port=443, service="https")],
            ),
            Asset(name="api.example.com"),
        ],
    )
    graph = build_asset_graph(current)
    assert any(edge.relationship == "EXPOSES" for edge in graph.edges)
    diff = diff_reports(previous, current)
    assert "api.example.com" in diff.added_assets
    assert "example.com:tcp/443" in diff.added_services


@pytest.mark.asyncio
@respx.mock
async def test_safe_rule_engine_matches_bounded_read_only_response() -> None:
    respx.get("https://example.com/openapi.json").mock(
        return_value=httpx.Response(200, text='{"openapi":"3.0.0"}')
    )
    observation = HTTPObservation(host="example.com", url="https://example.com/")
    rule = DetectionRule(
        rule_id="api-docs",
        name="EXPOSED_API_DOCUMENTATION",
        description="API docs exposed",
        path="/openapi.json",
        body_contains=["openapi"],
        severity="MEDIUM",
    )
    findings = await SafeVulnerabilityIndicatorEngine().evaluate(observation, [rule])
    assert len(findings) == 1
    assert findings[0].evidence_hash
    assert findings[0].kind.value == "INDICATOR"


@pytest.mark.asyncio
@respx.mock
async def test_threat_intelligence_enrichment_is_dated_and_normalized() -> None:
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "metrics": {
                                "cvssMetricV40": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "vectorString": "CVSS:4.0/AV:N",
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ]
            },
        )
    )
    respx.get("https://api.first.org/data/v1/epss").mock(
        return_value=httpx.Response(200, json={"data": [{"epss": "0.91", "percentile": "0.99"}]})
    )
    respx.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited-vulnerabilities.json"
    ).mock(
        return_value=httpx.Response(
            200, json={"vulnerabilities": [{"cveID": "CVE-2099-0001", "dueDate": "2099-01-01"}]}
        )
    )
    enrichment = await ThreatIntelEnricher().enrich("CVE-2099-0001")
    assert enrichment.cvss_score == 9.8
    assert enrichment.epss_score == 0.91
    assert enrichment.kev_listed is True
    assert enrichment.retrieved_at


@pytest.mark.asyncio
@respx.mock
async def test_http_redirect_to_private_destination_is_blocked() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/"})
    )
    scope = ScopeEngine(ScopeConfig(domains=["example.com"]))
    result = await HTTPCollector(scope).collect("example.com")
    assert result is None


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    audit = AuditStore(f"sqlite:///{tmp_path / 'audit.db'}")
    audit.record("org-1", "SCAN_STARTED", "user-1", "example.com")
    audit.record("org-1", "REPORT_VIEWED", "user-1", "scan-1")
    assert audit.verify_chain("org-1") is True


@pytest.mark.asyncio
async def test_rule_registry_rejects_non_read_only_rules(tmp_path: Path) -> None:
    from ai_recon.core.rules import RuleLoadError, load_rules

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - rule_id: safe\n    name: SAFE\n    description: safe\n    path: /health\n    method: GET\n"
    )
    assert len(load_rules(rules_path)) == 1
    rules_path.write_text(
        "rules:\n  - rule_id: unsafe\n    name: UNSAFE\n    description: unsafe\n    method: POST\n"
    )
    with pytest.raises(RuleLoadError):
        load_rules(rules_path)


@pytest.mark.asyncio
async def test_owned_background_job_lifecycle() -> None:
    from ai_recon.core.config import AppConfig, LimitsConfig, ModuleConfig, VulnerabilityConfig
    from ai_recon.core.jobs import JobManager, JobStatus

    config = AppConfig(
        scope=ScopeConfig(domains=["example.com"]),
        recon=ModuleConfig(
            osint=False,
            dns=False,
            subdomains=False,
            network=False,
            http=False,
            shodan=False,
            censys=False,
            ai_analysis=False,
        ),
        vulnerability=VulnerabilityConfig(enabled=False),
        limits=LimitsConfig(concurrency=1),
    )
    manager = JobManager(config)
    job = manager.create("example.com", "org-1", "user-1")
    for _ in range(20):
        current = manager.get(job.job_id, "org-1")
        if current and current.status in {JobStatus.COMPLETED, JobStatus.FAILED}:
            break
        await asyncio.sleep(0.01)
    assert manager.get(job.job_id, "org-1").status is JobStatus.COMPLETED
    assert manager.get(job.job_id, "other-org") is None
