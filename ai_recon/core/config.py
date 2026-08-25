from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ai_recon.models.entities import ScopeConfig


class ModuleConfig(BaseModel):
    osint: bool = True
    dns: bool = True
    subdomains: bool = True
    network: bool = True
    http: bool = True
    shodan: bool = False
    censys: bool = False
    ai_analysis: bool = True


class LimitsConfig(BaseModel):
    concurrency: int = Field(default=10, ge=1, le=100)
    request_timeout: float = Field(default=10, gt=0, le=120)
    retry_count: int = Field(default=2, ge=0, le=5)
    max_targets: int = Field(default=100, ge=1, le=1000)
    allow_private_networks: bool = False


class AIConfig(BaseModel):
    model: str = "gpt-5-mini"
    enabled: bool = True


class VulnerabilityConfig(BaseModel):
    enabled: bool = True
    rules_file: str = "rules/safe-indicators.yaml"
    enrich_cves: bool = True
    default_asset_criticality: int = Field(default=50, ge=0, le=100)


class ReportingConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "html"])
    output_dir: str = "reports"


class AppConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    recon: ModuleConfig = Field(default_factory=ModuleConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    vulnerability: VulnerabilityConfig = Field(default_factory=VulnerabilityConfig)
    database_url: str = "sqlite:///data/recon.db"
    user_agent: str = "AI-Reconnaissance-Tool/0.1 (authorized defensive assessment)"
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "AppConfig":
        file_path = Path(path)
        raw: dict[str, Any] = {}
        if file_path.exists():
            raw = yaml.safe_load(file_path.read_text()) or {}
        raw["shodan_api_key"] = os.getenv("SHODAN_API_KEY") or raw.get("shodan_api_key")
        raw["censys_api_id"] = os.getenv("CENSYS_API_ID") or raw.get("censys_api_id")
        raw["censys_api_secret"] = os.getenv("CENSYS_API_SECRET") or raw.get("censys_api_secret")
        return cls.model_validate(raw)

    @classmethod
    def default(cls) -> "AppConfig":
        return cls()


def write_example(path: str | Path) -> None:
    config = {
        "scope": {
            "domains": ["example.com"],
            "ips": ["203.0.113.10"],
            "cidrs": ["203.0.113.0/28"],
            "allowed_subdomains": ["*.example.com"],
        },
        "recon": {
            "osint": True,
            "dns": True,
            "subdomains": True,
            "network": True,
            "http": True,
            "shodan": False,
            "censys": False,
            "ai_analysis": True,
        },
        "limits": {
            "concurrency": 10,
            "request_timeout": 10,
            "retry_count": 2,
            "max_targets": 100,
            "allow_private_networks": False,
        },
        "ai": {"model": "gpt-5-mini", "enabled": True},
        "reporting": {"formats": ["json", "html"], "output_dir": "reports"},
        "vulnerability": {
            "enabled": True,
            "rules_file": "rules/safe-indicators.yaml",
            "enrich_cves": True,
            "default_asset_criticality": 50,
        },
    }
    Path(path).write_text(yaml.safe_dump(config, sort_keys=False))
