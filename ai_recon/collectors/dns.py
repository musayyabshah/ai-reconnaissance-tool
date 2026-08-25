from __future__ import annotations

import asyncio
from typing import Iterable

import dns.asyncresolver

from ai_recon.models.entities import DNSRecord, Evidence


class DNSCollector:
    record_types: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

    def __init__(self, timeout: float = 10) -> None:
        self.timeout = timeout

    async def collect(self, domain: str) -> list[DNSRecord]:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        async def one(record_type: str) -> DNSRecord | None:
            try:
                answer = await resolver.resolve(domain, record_type)
                values = [item.to_text().strip('"') for item in answer]
                evidence = Evidence(
                    source="DNS",
                    target=domain,
                    collector="DNSCollector",
                    observation=f"{record_type} record observed with {len(values)} value(s)",
                    confidence=0.98,
                )
                return DNSRecord(
                    name=domain,
                    record_type=record_type,
                    values=values,
                    ttl=answer.rrset.ttl,
                    evidence=[evidence],
                )
            except Exception:
                return None

        records = await asyncio.gather(*(one(record_type) for record_type in self.record_types))
        return [record for record in records if record is not None]

    @staticmethod
    def ips(records: Iterable[DNSRecord]) -> list[str]:
        values: set[str] = set()
        for record in records:
            if record.record_type in {"A", "AAAA"}:
                values.update(record.values)
        return sorted(values)
