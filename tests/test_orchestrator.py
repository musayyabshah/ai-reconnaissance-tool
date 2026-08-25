import pytest

from ai_recon.core.config import AppConfig, ModuleConfig
from ai_recon.core.orchestrator import ReconOrchestrator
from ai_recon.models.entities import DNSRecord, HTTPObservation, ScopeConfig, Service


@pytest.mark.asyncio
async def test_orchestrator_full_pipeline_with_mocked_collectors() -> None:
    config = AppConfig(
        scope=ScopeConfig(domains=["example.com"]),
        recon=ModuleConfig(
            osint=False,
            dns=True,
            subdomains=False,
            network=True,
            http=True,
            shodan=False,
            censys=False,
            ai_analysis=False,
        ),
    )
    orchestrator = ReconOrchestrator(config)
    orchestrator.dns.collect = lambda value: _dns(value)  # type: ignore[method-assign]
    orchestrator.nmap.collect = lambda value: _nmap(value)  # type: ignore[method-assign]
    orchestrator.http.collect = lambda value: _http(value)  # type: ignore[method-assign]
    report = await orchestrator.scan("example.com")
    assert report.completed_at is not None
    assert len(report.assets) == 1
    assert report.services[0].port == 443
    assert report.http_observations[0].title == "Login"
    assert report.findings


async def _dns(value: str) -> list[DNSRecord]:
    return [DNSRecord(name=value, record_type="A", values=["203.0.113.10"])]


async def _nmap(value: str) -> list[Service]:
    return [Service(asset=value, ip="203.0.113.10", port=443, service="https", state="open")]


async def _http(value: str) -> HTTPObservation:
    return HTTPObservation(
        host=value,
        url=f"https://{value}/login",
        status=200,
        title="Login",
        content_type="text/html",
        headers={"server": "test"},
    )
