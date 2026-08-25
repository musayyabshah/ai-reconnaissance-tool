from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ai_recon.core.scope import ScopeEngine
from ai_recon.models.entities import HTTPObservation

SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
}


class SSRFBlocked(ValueError):
    pass


def _public_host(host: str, allow_private: bool = False) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return True
    if allow_private:
        return True
    return all(
        not (
            ipaddress.ip_address(address).is_private
            or ipaddress.ip_address(address).is_loopback
            or ipaddress.ip_address(address).is_link_local
        )
        for address in addresses
    )


class HTTPCollector:
    def __init__(
        self,
        scope: ScopeEngine,
        timeout: float = 10,
        user_agent: str = "AI-Reconnaissance-Tool/0.1",
        allow_private: bool = False,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.user_agent = user_agent
        self.allow_private = allow_private

    async def collect(self, host: str, scheme: str = "https") -> HTTPObservation | None:
        self.scope.require_active(host)
        parsed_host = urlparse(f"{scheme}://{host}").hostname
        if not parsed_host or not _public_host(parsed_host, self.allow_private):
            raise SSRFBlocked(f"HTTP probing blocked for private or local host: {host}")
        url = f"{scheme}://{host}/"
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=headers,
                max_redirects=5,
                verify=True,
            ) as client:
                response = await client.get(url)
                body = response.content[:2_000_000]
                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip() or None
                )
                title = None
                if content_type == "text/html" or "html" in (content_type or ""):
                    title_node = BeautifulSoup(body, "html.parser").find("title")
                    title = title_node.get_text(" ", strip=True)[:300] if title_node else None
                base = str(response.url).rstrip("/")
                robots = await self._exists(client, urljoin(base + "/", "/robots.txt"))
                sitemap = await self._exists(client, urljoin(base + "/", "/sitemap.xml"))
                return HTTPObservation(
                    host=host,
                    url=str(response.url),
                    status=response.status_code,
                    redirect_chain=[str(item.url) for item in response.history]
                    + [str(response.url)],
                    methods=[
                        item.strip()
                        for item in response.headers.get("allow", "").split(",")
                        if item.strip()
                    ],
                    headers={
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower() in SECURITY_HEADERS
                        or key.lower() in {"server", "content-type", "x-powered-by"}
                    },
                    server=response.headers.get("server"),
                    content_type=content_type,
                    title=title,
                    tls={"scheme": parsed_host and scheme},
                    robots_available=robots,
                    sitemap_available=sitemap,
                    response_size=len(response.content),
                )
        except (httpx.HTTPError, asyncio.TimeoutError):
            return None

    async def _exists(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            response = await client.get(url)
            return response.status_code < 500
        except httpx.HTTPError:
            return False
