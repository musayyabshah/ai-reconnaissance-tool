from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass

from ai_recon.core.scope import ScopeEngine
from ai_recon.models.entities import Service


@dataclass(frozen=True)
class NmapProfile:
    name: str
    arguments: tuple[str, ...]


SAFE_PROFILES = {
    "top-ports": NmapProfile(
        "top-ports", ("-Pn", "--top-ports", "20", "-sV", "--version-light", "-oG", "-")
    ),
    "web": NmapProfile(
        "web", ("-Pn", "-p", "80,443,8080,8443", "-sV", "--version-light", "-oG", "-")
    ),
}


class NmapCollector:
    def __init__(self, scope: ScopeEngine, timeout: float = 60, profile: str = "web") -> None:
        self.scope = scope
        self.timeout = timeout
        self.profile = SAFE_PROFILES.get(profile, SAFE_PROFILES["web"])

    async def collect(self, target: str) -> list[Service]:
        self.scope.require_active(target)
        if shutil.which("nmap") is None:
            return []
        command = ["nmap", *self.profile.arguments, target]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except (OSError, asyncio.TimeoutError):
            return []
        return self.parse_grepable(stdout.decode("utf-8", errors="replace"), target)

    @staticmethod
    def parse_grepable(output: str, target: str) -> list[Service]:
        services: list[Service] = []
        for line in output.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            host_match = re.search(r"Host:\s+(\S+)", line)
            host = host_match.group(1) if host_match else target
            ports = line.split("Ports:", 1)[1].strip()
            for entry in ports.split(","):
                parts = entry.strip().split("/")
                if len(parts) < 5:
                    continue
                try:
                    port = int(parts[0])
                except ValueError:
                    continue
                state, protocol, service, version = (
                    parts[1],
                    parts[2],
                    parts[4],
                    parts[6] if len(parts) > 6 else "unknown",
                )
                services.append(
                    Service(
                        asset=target,
                        hostname=host,
                        port=port,
                        protocol=protocol,
                        service=service or "unknown",
                        version=version or "unknown",
                        state=state,
                    )
                )
        return services
