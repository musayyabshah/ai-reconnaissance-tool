from __future__ import annotations

from urllib.parse import urljoin

import httpx

from ai_recon.core.scope import ScopeEngine


class PassiveOSINTCollector:
    """Collects public metadata only; it never authenticates or performs exploitation."""

    def __init__(self, scope: ScopeEngine, timeout: float = 10) -> None:
        self.scope = scope
        self.timeout = timeout

    async def collect(self, host: str) -> dict[str, str | int | bool]:
        self.scope.require_active(host)
        result: dict[str, str | int | bool] = {
            "host": host,
            "security_txt": False,
            "robots_txt": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for path, key in (
                ("/.well-known/security.txt", "security_txt"),
                ("/robots.txt", "robots_txt"),
            ):
                try:
                    response = await client.get(urljoin(f"https://{host}", path))
                    result[key] = response.status_code < 500
                    if key == "security_txt" and response.status_code < 400:
                        result["security_txt_size"] = len(response.content)
                except httpx.HTTPError:
                    result[key] = False
        return result
