from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import respx

from ai_recon.analyzers.analysis import (
    HeaderAnalyzer,
    MetadataAnalyzer,
    RiskScorer,
    TechnologyAnalyzer,
)
from ai_recon.analyzers.headers import HeaderAnalyzer as HeaderFacade
from ai_recon.analyzers.metadata import MetadataAnalyzer as MetadataFacade
from ai_recon.analyzers.risk import RiskScorer as RiskFacade
from ai_recon.analyzers.technologies import TechnologyAnalyzer as TechnologyFacade
from ai_recon.collectors.dns import DNSCollector
from ai_recon.collectors.http import HTTPCollector, SSRFBlocked, _public_host
from ai_recon.collectors.nmap import SAFE_PROFILES
from ai_recon.collectors.osint import PassiveOSINTCollector
from ai_recon.collectors.providers import CensysProvider, ShodanProvider
from ai_recon.collectors.subdomains import SubdomainCollector
from ai_recon.core.config import AppConfig, write_example
from ai_recon.core.reliability import TTLCache, retry_async
from ai_recon.core.scope import ScopeEngine, ScopeViolation
from ai_recon.models.asset import Asset
from ai_recon.models.finding import Finding
from ai_recon.models.report import ScanReport
from ai_recon.models.service import Service
from ai_recon.models.target import ScopeConfig, Target
from ai_recon.storage.database import ScanRepository


def test_all_public_module_facades_and_profiles() -> None:
    assert HeaderFacade is HeaderAnalyzer
    assert MetadataFacade is MetadataAnalyzer
    assert RiskFacade is RiskScorer
    assert TechnologyFacade is TechnologyAnalyzer
    assert Asset(name="example.com").name == "example.com"
    assert (
        Finding(target="example.com", type="TEST", source="TEST", confidence=0.5).target
        == "example.com"
    )
    assert ScanReport(target=Target(value="example.com")).target.value == "example.com"
    assert Service(asset="example.com", port=443).port == 443
    assert set(SAFE_PROFILES) == {"top-ports", "web"}


def test_config_round_trip_and_database(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    write_example(config_path)
    config = AppConfig.from_file(config_path)
    assert config.scope.domains == ["example.com"]
    assert config.recon.osint is True
    repository = ScanRepository(f"sqlite:///{tmp_path / 'recon.db'}")
    report = ScanReport(target=Target(value="example.com", authorized=True))
    repository.save(report)
    assert repository.latest().scan_id == report.scan_id


def test_dns_helper_and_http_ssrf_boundary() -> None:
    assert DNSCollector.ips([]) == []
    assert _public_host("127.0.0.1") is False
    assert _public_host("example.com") is True
    scope = ScopeEngine(ScopeConfig(domains=["example.com"]))
    collector = HTTPCollector(scope)
    with pytest.raises(ScopeViolation):
        asyncio.run(collector.collect("outside.example.net"))
    with pytest.raises(SSRFBlocked):
        # A permissive test double reaches the separate SSRF boundary; production uses ScopeEngine.
        class AllowScope:
            def require_active(self, value: str) -> None:
                return None

        asyncio.run(HTTPCollector(AllowScope(), allow_private=False).collect("127.0.0.1"))


@pytest.mark.asyncio
async def test_reliability_and_provider_fallbacks() -> None:
    attempts = 0

    async def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise RuntimeError("transient")
        return "ok"

    assert await retry_async(flaky, retries=2) == "ok"
    assert attempts == 2
    cache = TTLCache(ttl_seconds=10)
    cache.set("key", "value")
    assert cache.get("key") == "value"
    assert await ShodanProvider(None).search("example.com") == []
    assert await CensysProvider(None, None).search("example.com") == []


@pytest.mark.asyncio
async def test_passive_collectors_reject_out_of_scope_without_network() -> None:
    scope = ScopeEngine(ScopeConfig(domains=["example.com"]))
    with pytest.raises(ScopeViolation):
        await PassiveOSINTCollector(scope).collect("outside.example.net")
    subdomains = SubdomainCollector.normalize("*.Api.Example.COM.")
    assert subdomains == "api.example.com"


@pytest.mark.asyncio
@respx.mock
async def test_provider_response_normalization() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "ip_str": "203.0.113.10",
                        "port": 443,
                        "transport": "tcp",
                        "product": "Example Server",
                        "version": "1.0",
                        "org": "Example Org",
                    }
                ]
            },
        )
    )
    respx.post("https://search.censys.io/api/v2/hosts/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "hits": [
                        {
                            "ip": "198.51.100.10",
                            "services": [
                                {
                                    "port": 443,
                                    "transport_protocol": "TCP",
                                    "service_name": "HTTP",
                                    "software": [{"product": "Example", "version": "2.0"}],
                                }
                            ],
                        }
                    ]
                }
            },
        )
    )
    shodan = await ShodanProvider("configured-key").search("example.com")
    censys = await CensysProvider("configured-id", "configured-secret").search("example.com")
    assert shodan[0].ip == "203.0.113.10"
    assert shodan[0].product == "Example Server"
    assert censys[0].ip == "198.51.100.10"
    assert censys[0].version == "2.0"
