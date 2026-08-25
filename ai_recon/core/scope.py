from __future__ import annotations

import fnmatch
import ipaddress

from ai_recon.models.entities import ScopeConfig, ScopeStatus


class ScopeViolation(ValueError):
    """Raised when an active collector is asked to probe an unauthorized asset."""


class ScopeEngine:
    def __init__(self, config: ScopeConfig, allow_private_networks: bool = False) -> None:
        self.config = config
        self.allow_private_networks = allow_private_networks
        self._domains = {self._normalize_domain(d) for d in config.domains if d}
        self._allowed_subdomains = [
            d.strip().lower().rstrip(".") for d in config.allowed_subdomains if d
        ]
        self._ips = {
            str(ipaddress.ip_address(value)) for value in config.ips if self._valid_ip(value)
        }
        self._networks = [
            ipaddress.ip_network(value, strict=False)
            for value in config.cidrs
            if self._valid_network(value)
        ]

    @staticmethod
    def _normalize_domain(value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        return value

    @staticmethod
    def _valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _valid_network(value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def check(self, value: str) -> ScopeStatus:
        candidate = value.strip().lower().rstrip(".")
        try:
            address = ipaddress.ip_address(candidate)
            private_networks = (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
            is_restricted = (
                address.is_loopback
                or address.is_link_local
                or any(address in network for network in private_networks)
            )
            if not self.allow_private_networks and is_restricted:
                return ScopeStatus.OUT_OF_SCOPE
            if str(address) in self._ips or any(address in network for network in self._networks):
                return ScopeStatus.IN_SCOPE
            return ScopeStatus.OUT_OF_SCOPE
        except ValueError:
            pass

        if candidate in self._domains:
            return ScopeStatus.IN_SCOPE
        for allowed in self._allowed_subdomains:
            if fnmatch.fnmatch(candidate, allowed) or candidate == allowed:
                return ScopeStatus.IN_SCOPE
        if any(candidate == domain or candidate.endswith(f".{domain}") for domain in self._domains):
            return ScopeStatus.UNKNOWN
        return ScopeStatus.OUT_OF_SCOPE

    def require_active(self, value: str) -> None:
        status = self.check(value)
        if status is not ScopeStatus.IN_SCOPE:
            raise ScopeViolation(f"Active probing blocked for {value}: scope status is {status}")

    def classify_many(self, values: list[str]) -> dict[str, ScopeStatus]:
        return {value: self.check(value) for value in values}
