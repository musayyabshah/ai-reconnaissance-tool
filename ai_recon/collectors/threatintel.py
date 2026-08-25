from __future__ import annotations

from datetime import datetime, timezone

import httpx

from ai_recon.models.vulnerability import VulnerabilityEnrichment


class ThreatIntelEnricher:
    def __init__(self, timeout: float = 10) -> None:
        self.timeout = timeout

    async def enrich(self, cve_id: str) -> VulnerabilityEnrichment:
        retrieved = datetime.now(timezone.utc).isoformat()
        cvss_score = None
        cvss_vector = None
        epss_score = None
        epss_percentile = None
        kev_listed = False
        kev_due_date = None
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                nvd = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id}
                )
                if nvd.is_success:
                    vulnerabilities = nvd.json().get("vulnerabilities", [])
                    metrics = (
                        vulnerabilities[0].get("cve", {}).get("metrics", {})
                        if vulnerabilities
                        else {}
                    )
                    entries = metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31") or []
                    if entries:
                        cvss = entries[0].get("cvssData", {})
                        cvss_score = cvss.get("baseScore")
                        cvss_vector = cvss.get("vectorString")
            except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
                pass
            try:
                epss = await client.get(
                    "https://api.first.org/data/v1/epss", params={"cve": cve_id}
                )
                if epss.is_success:
                    rows = epss.json().get("data", [])
                    if rows:
                        epss_score = float(rows[0].get("epss"))
                        epss_percentile = float(rows[0].get("percentile"))
            except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
                pass
            try:
                kev = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited-vulnerabilities.json"
                )
                if kev.is_success:
                    entries = kev.json().get("vulnerabilities", [])
                    match = next((item for item in entries if item.get("cveID") == cve_id), None)
                    if match:
                        kev_listed = True
                        kev_due_date = match.get("dueDate")
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                pass
        return VulnerabilityEnrichment(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            kev_listed=kev_listed,
            kev_due_date=kev_due_date,
            source="NVD+EPSS+CISA-KEV",
            retrieved_at=retrieved,
        )
