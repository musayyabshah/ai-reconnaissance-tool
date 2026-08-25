from __future__ import annotations

from typing import Any

import httpx

from ai_recon.models.entities import IntelligenceObservation


class ProviderUnavailable(RuntimeError):
    pass


class ShodanProvider:
    def __init__(self, api_key: str | None, timeout: float = 10) -> None:
        self.api_key = api_key
        self.timeout = timeout

    async def search(self, query: str) -> list[IntelligenceObservation]:
        if not self.api_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.api_key, "query": query},
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError):
            return []
        return [
            IntelligenceObservation(
                provider="shodan",
                ip=item.get("ip_str"),
                port=item.get("port"),
                protocol=item.get("transport"),
                service=item.get("product") or item.get("_shodan", {}).get("module"),
                product=item.get("product"),
                version=item.get("version"),
                organization=item.get("org"),
                location=item.get("location", {}),
                raw_evidence_reference=f"shodan:{item.get('ip_str', 'unknown')}:{item.get('port', 'unknown')}",
            )
            for item in data.get("matches", [])
        ]


class CensysProvider:
    def __init__(self, api_id: str | None, api_secret: str | None, timeout: float = 10) -> None:
        self.api_id = api_id
        self.api_secret = api_secret
        self.timeout = timeout

    async def search(self, query: str) -> list[IntelligenceObservation]:
        if not self.api_id or not self.api_secret:
            return []
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, auth=(self.api_id, self.api_secret)
            ) as client:
                response = await client.post(
                    "https://search.censys.io/api/v2/hosts/search",
                    json={"q": query, "per_page": 100},
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError):
            return []
        observations: list[IntelligenceObservation] = []
        for hit in data.get("result", {}).get("hits", []):
            services = hit.get("services", [])
            for service in services:
                observations.append(
                    IntelligenceObservation(
                        provider="censys",
                        ip=hit.get("ip"),
                        port=service.get("port"),
                        protocol=service.get("transport_protocol"),
                        service=service.get("service_name"),
                        product=service.get("software", [{}])[0].get("product")
                        if service.get("software")
                        else None,
                        version=service.get("software", [{}])[0].get("version")
                        if service.get("software")
                        else None,
                        location=hit.get("location", {}),
                        raw_evidence_reference=f"censys:{hit.get('ip', 'unknown')}:{service.get('port', 'unknown')}",
                    )
                )
        return observations
