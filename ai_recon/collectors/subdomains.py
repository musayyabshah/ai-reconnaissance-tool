from __future__ import annotations

import json
from urllib.parse import quote

import httpx

from ai_recon.core.reliability import retry_async
from ai_recon.core.scope import ScopeEngine
from ai_recon.models.entities import Confidence, Subdomain


class SubdomainCollector:
    def __init__(self, timeout: float = 10, client: httpx.AsyncClient | None = None) -> None:
        self.timeout = timeout
        self.client = client

    @staticmethod
    def normalize(name: str) -> str:
        return name.strip().lower().lstrip("*.").rstrip(".")

    async def collect(self, domain: str, scope: ScopeEngine) -> list[Subdomain]:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        own_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        try:
            response = await retry_async(lambda: client.get(url), retries=2, timeout=self.timeout)
            response.raise_for_status()
            rows = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            return []
        finally:
            if own_client:
                await client.aclose()

        discovered: dict[str, Subdomain] = {}
        for row in rows:
            for raw in str(row.get("name_value", "")).splitlines():
                name = self.normalize(raw)
                if not name or name == self.normalize(domain):
                    continue
                status = scope.check(name)
                discovered[name] = Subdomain(
                    name=name,
                    source="crt.sh",
                    confidence=Confidence.HIGH,
                    scope_status=status,
                )
        return sorted(discovered.values(), key=lambda item: item.name)
