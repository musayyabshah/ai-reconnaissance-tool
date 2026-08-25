from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ai_recon.core.scope import ScopeEngine, ScopeViolation
from ai_recon.models.entities import HTTPObservation

SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
}
REDIRECT_CODES = {301, 302, 303, 307, 308}


class SSRFBlocked(ValueError):
    pass


def _public_host(host: str, allow_private: bool = False) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return False
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

    def _validate_destination(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SSRFBlocked("Only HTTP(S) URLs with a hostname are permitted")
        self.scope.require_active(parsed.hostname)
        if not _public_host(parsed.hostname, self.allow_private):
            raise SSRFBlocked(
                f"HTTP probing blocked for private or unresolved host: {parsed.hostname}"
            )

    async def _request(
        self, client: httpx.AsyncClient, url: str, method: str = "GET"
    ) -> tuple[httpx.Response, list[str]]:
        current = url
        chain: list[str] = []
        for _ in range(5):
            self._validate_destination(current)
            response = await client.request(method, current)
            chain.append(str(response.url))
            if response.status_code not in REDIRECT_CODES or method == "HEAD":
                return response, chain
            location = response.headers.get("location")
            if not location:
                return response, chain
            current = urljoin(str(response.url), location)
        raise SSRFBlocked("Redirect limit exceeded")

    async def collect(self, host: str, scheme: str = "https") -> HTTPObservation | None:
        self.scope.require_active(host)
        url = f"{scheme}://{host}/"
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                headers=headers,
                max_redirects=0,
                verify=True,
            ) as client:
                response, redirect_chain = await self._request(client, url)
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
                    redirect_chain=redirect_chain,
                    methods=[
                        item.strip()
                        for item in response.headers.get("allow", "").split(",")
                        if item.strip()
                    ],
                    headers={
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower() in SECURITY_HEADERS
                        or key.lower()
                        in {"server", "content-type", "x-powered-by", "access-control-allow-origin"}
                    },
                    server=response.headers.get("server"),
                    content_type=content_type,
                    title=title,
                    tls={"scheme": scheme, "redirects_validated": True},
                    robots_available=robots,
                    sitemap_available=sitemap,
                    response_size=len(response.content),
                )
        except (httpx.HTTPError, asyncio.TimeoutError, SSRFBlocked, ScopeViolation):
            return None

    async def _exists(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            response, _ = await self._request(client, url)
            return response.status_code < 500
        except (httpx.HTTPError, SSRFBlocked):
            return False
