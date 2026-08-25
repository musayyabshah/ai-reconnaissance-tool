from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

from ai_recon.analyzers.analysis import (
    AdminInterfaceClassifier,
    HeaderAnalyzer,
    MetadataAnalyzer,
    RiskScorer,
    TechnologyAnalyzer,
)
from ai_recon.analyzers.semantic import SemanticAnalyzer
from ai_recon.analyzers.vulnerability import SafeVulnerabilityIndicatorEngine
from ai_recon.collectors.dns import DNSCollector
from ai_recon.collectors.http import HTTPCollector
from ai_recon.collectors.nmap import NmapCollector
from ai_recon.collectors.osint import PassiveOSINTCollector
from ai_recon.collectors.providers import CensysProvider, ShodanProvider
from ai_recon.collectors.subdomains import SubdomainCollector
from ai_recon.collectors.threatintel import ThreatIntelEnricher
from ai_recon.core.config import AppConfig
from ai_recon.core.reliability import TTLCache
from ai_recon.core.rules import load_rules
from ai_recon.core.scope import ScopeEngine, ScopeViolation
from ai_recon.models.entities import Asset, Finding, ScanReport, ScopeStatus, Target

ProgressCallback = Callable[[str], None]


class ReconOrchestrator:
    def __init__(self, config: AppConfig, progress: ProgressCallback | None = None) -> None:
        self.config = config
        self.scope = ScopeEngine(config.scope, config.limits.allow_private_networks)
        self.progress = progress or (lambda _: None)
        self.dns = DNSCollector(config.limits.request_timeout)
        self.subdomains = SubdomainCollector(config.limits.request_timeout)
        self.nmap = NmapCollector(self.scope, max(30, config.limits.request_timeout * 6))
        self.osint = PassiveOSINTCollector(self.scope, config.limits.request_timeout)
        self.http = HTTPCollector(
            self.scope,
            config.limits.request_timeout,
            config.user_agent,
            config.limits.allow_private_networks,
        )
        self.technology = TechnologyAnalyzer()
        self.headers = HeaderAnalyzer()
        self.metadata = MetadataAnalyzer()
        self.admin = AdminInterfaceClassifier()
        self.risk = RiskScorer()
        self.semantic = SemanticAnalyzer(
            config.ai.model, config.ai.enabled and config.recon.ai_analysis
        )
        self.cache = TTLCache(ttl_seconds=300)
        self.vulnerability_engine = SafeVulnerabilityIndicatorEngine(
            self.scope, config.limits.request_timeout, config.limits.allow_private_networks
        )
        self.threat_intel = ThreatIntelEnricher(config.limits.request_timeout)
        try:
            self.vulnerability_rules = (
                load_rules(config.vulnerability.rules_file) if config.vulnerability.enabled else []
            )
        except ValueError as exc:
            self.vulnerability_rules = []
            self.progress(f"Vulnerability rules disabled: {exc}")

    def _stage(self, message: str) -> None:
        self.progress(message)

    async def scan(self, value: str) -> ScanReport:
        status = self.scope.check(value)
        if status is not ScopeStatus.IN_SCOPE:
            raise ScopeViolation(
                f"Target must be explicitly IN_SCOPE before scanning: {value} ({status})"
            )
        target = Target(value=value, scope_status=status, authorized=True)
        report = ScanReport(target=target)
        self._stage("Scope validated")

        if self.config.recon.osint:
            try:
                report.metadata["passive_osint"] = await self.osint.collect(value)
                self._stage("Passive OSINT metadata collected")
            except Exception as exc:
                report.errors.append(f"OSINT: {exc}")

        if self.config.recon.dns:
            try:
                cached_dns = self.cache.get(f"dns:{value}")
                if cached_dns is None:
                    report.dns_records = await self.dns.collect(value)
                    self.cache.set(f"dns:{value}", report.dns_records)
                else:
                    report.dns_records = cached_dns  # type: ignore[assignment]
                self._stage("DNS discovery completed")
            except Exception as exc:
                report.errors.append(f"DNS: {exc}")

        if self.config.recon.subdomains:
            try:
                report.subdomains = await self.subdomains.collect(value, self.scope)
                self._stage(f"{len(report.subdomains)} subdomains discovered")
            except Exception as exc:
                report.errors.append(f"Subdomains: {exc}")

        active_hosts = [value] + [
            item.name for item in report.subdomains if item.scope_status is ScopeStatus.IN_SCOPE
        ]
        active_hosts = list(dict.fromkeys(active_hosts))[: self.config.limits.max_targets]

        if self.config.recon.network:
            try:
                service_groups = await asyncio.gather(
                    *(self.nmap.collect(host) for host in active_hosts), return_exceptions=True
                )
                for group in service_groups:
                    if isinstance(group, Exception):
                        report.errors.append(f"Nmap: {group}")
                    else:
                        report.services.extend(group)
                self._stage(f"{len(report.services)} services observed")
            except Exception as exc:
                report.errors.append(f"Nmap: {exc}")

        if self.config.recon.http:
            http_groups = await asyncio.gather(
                *(self.http.collect(host) for host in active_hosts), return_exceptions=True
            )
            for host, observation in zip(active_hosts, http_groups, strict=True):
                if isinstance(observation, Exception):
                    report.errors.append(f"HTTP {host}: {observation}")
                elif observation is not None:
                    report.http_observations.append(observation)
                    technologies = self.technology.detect(observation)
                    observation.technology_indicators = [item.name for item in technologies]
                    report.technologies.extend(technologies)
                    report.findings.extend(self.headers.analyze(observation))
                    metadata = self.metadata.extract(observation)
                    admin_finding = self.admin.classify(observation, metadata, technologies)
                    if admin_finding:
                        report.findings.append(admin_finding)
                    report.analyses.append(self.semantic.analyze(observation, technologies))
                    if self.vulnerability_rules:
                        try:
                            report.findings.extend(
                                await self.vulnerability_engine.evaluate(
                                    observation, self.vulnerability_rules
                                )
                            )
                        except Exception as exc:
                            report.errors.append(f"Safe vulnerability rules {host}: {exc}")
            self._stage(f"{len(report.http_observations)} HTTP services analyzed")

        if self.config.recon.shodan:
            try:
                report.intelligence.extend(
                    await ShodanProvider(
                        self.config.shodan_api_key, self.config.limits.request_timeout
                    ).search(value)
                )
            except Exception as exc:
                report.errors.append(f"Shodan: {exc}")
        if self.config.recon.censys:
            try:
                report.intelligence.extend(
                    await CensysProvider(
                        self.config.censys_api_id,
                        self.config.censys_api_secret,
                        self.config.limits.request_timeout,
                    ).search(value)
                )
            except Exception as exc:
                report.errors.append(f"Censys: {exc}")

        enriched_findings: list[Finding] = []
        for finding in report.findings:
            if finding.cve_id and self.config.vulnerability.enrich_cves:
                try:
                    enrichment = await self.threat_intel.enrich(finding.cve_id)
                    finding = finding.model_copy(
                        update=enrichment.model_dump(exclude={"cve_id", "source", "retrieved_at"})
                    )
                except Exception as exc:
                    report.errors.append(f"Threat intelligence {finding.cve_id}: {exc}")
            if finding.source == "SAFE_RULE_ENGINE":
                finding = self.risk.score_vulnerability(
                    finding,
                    asset_criticality=self.config.vulnerability.default_asset_criticality,
                    internet_exposed=True,
                )
            else:
                finding = self.risk.score(
                    finding,
                    weak_config=10 if finding.type == "MISSING_SECURITY_HEADERS" else 0,
                    sensitive=20 if finding.type == "POTENTIAL_ADMIN_INTERFACE" else 0,
                )
            enriched_findings.append(finding)
        report.findings = enriched_findings
        report.assets = self._correlate(report, active_hosts)
        report.metadata.update(
            {"cache_ttl_seconds": self.cache.ttl_seconds, "active_hosts": active_hosts}
        )
        report.completed_at = datetime.now(timezone.utc)
        self._stage("Asset correlation and risk prioritization completed")
        self._stage(f"{report.high_priority_count} high-priority observations")
        return report

    @staticmethod
    def _correlate(report: ScanReport, hostnames: list[str]) -> list[Asset]:
        assets: dict[str, Asset] = {
            host: Asset(name=host, scope_status=ScopeStatus.IN_SCOPE) for host in hostnames
        }
        for record in report.dns_records:
            if record.name not in assets:
                assets[record.name] = Asset(name=record.name, scope_status=ScopeStatus.IN_SCOPE)
            if record.record_type in {"A", "AAAA"}:
                assets[record.name].ips = sorted(set(assets[record.name].ips + record.values))
        for service in report.services:
            assets.setdefault(
                service.asset, Asset(name=service.asset, scope_status=ScopeStatus.IN_SCOPE)
            ).services.append(service)
        for observation in report.http_observations:
            assets.setdefault(
                observation.host, Asset(name=observation.host, scope_status=ScopeStatus.IN_SCOPE)
            ).http.append(observation)
        for tech in report.technologies:
            for asset in assets.values():
                if any(tech.name in obs.technology_indicators for obs in asset.http):
                    asset.technologies.append(tech)
        for analysis, asset in zip(
            report.analyses, [a for a in assets.values() if a.http], strict=False
        ):
            asset.ai_analysis = analysis
        return sorted(assets.values(), key=lambda item: item.name)
