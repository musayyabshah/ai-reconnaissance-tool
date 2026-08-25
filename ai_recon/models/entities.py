from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScopeStatus(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ObservationKind(StrEnum):
    OBSERVATION = "OBSERVATION"
    INDICATOR = "INDICATOR"
    POTENTIAL_RISK = "POTENTIAL_RISK"
    CONFIRMED_FINDING = "CONFIRMED_FINDING"


class Priority(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(min_length=1)
    kind: str = "hostname"
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    authorized: bool = False


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    allowed_subdomains: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utcnow)
    source: str
    target: str
    collector: str
    observation: str
    confidence: float = Field(ge=0, le=1)
    raw_reference: str | None = None
    analysis_result: dict[str, Any] = Field(default_factory=dict)


class DNSRecord(BaseModel):
    name: str
    record_type: str
    values: list[str]
    ttl: int | None = None
    observed_at: datetime = Field(default_factory=utcnow)
    evidence: list[Evidence] = Field(default_factory=list)


class Subdomain(BaseModel):
    name: str
    source: str
    confidence: Confidence
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    observed_at: datetime = Field(default_factory=utcnow)


class Service(BaseModel):
    asset: str
    ip: str | None = None
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = "unknown"
    state: str = "unknown"
    hostname: str | None = None
    observed_at: datetime = Field(default_factory=utcnow)


class HTTPObservation(BaseModel):
    host: str
    url: str
    status: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    server: str | None = None
    content_type: str | None = None
    title: str | None = None
    tls: dict[str, Any] = Field(default_factory=dict)
    robots_available: bool = False
    sitemap_available: bool = False
    technology_indicators: list[str] = Field(default_factory=list)
    response_size: int = 0
    observed_at: datetime = Field(default_factory=utcnow)


class Technology(BaseModel):
    name: str
    source: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)


class IntelligenceObservation(BaseModel):
    provider: str
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    organization: str | None = None
    location: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=utcnow)
    raw_evidence_reference: str | None = None


class AIAnalysis(BaseModel):
    application_type: str = "UNKNOWN"
    confidence: float = Field(ge=0, le=1)
    technologies: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    priority: Priority = Priority.INFO
    provider: str = "heuristic"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"F-{uuid4().hex[:8].upper()}")
    target: str
    type: str
    kind: ObservationKind = ObservationKind.INDICATOR
    confidence: float = Field(ge=0, le=1)
    severity: Priority = Priority.INFO
    source: str
    observed_at: datetime = Field(default_factory=utcnow)
    evidence: list[str] = Field(default_factory=list)
    evidence_items: list[Evidence] = Field(default_factory=list)
    recommended_action: str | None = None
    score: float = Field(default=0, ge=0, le=100)


class Asset(BaseModel):
    name: str
    kind: str = "hostname"
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    ips: list[str] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    http: list[HTTPObservation] = Field(default_factory=list)
    ai_analysis: AIAnalysis | None = None


class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"scan-{uuid4().hex[:12]}")
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    target: Target
    assets: list[Asset] = Field(default_factory=list)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    subdomains: list[Subdomain] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    http_observations: list[HTTPObservation] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    intelligence: list[IntelligenceObservation] = Field(default_factory=list)
    analyses: list[AIAnalysis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def high_priority_count(self) -> int:
        return sum(f.severity in {Priority.CRITICAL, Priority.HIGH} for f in self.findings)
