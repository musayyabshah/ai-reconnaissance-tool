from __future__ import annotations

import re
from typing import Iterable

from ai_recon.models.entities import (
    Finding,
    HTTPObservation,
    ObservationKind,
    Priority,
    Technology,
)


class HeaderAnalyzer:
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    def analyze(self, observation: HTTPObservation) -> list[Finding]:
        findings: list[Finding] = []
        missing = [name for name in self.security_headers if name not in observation.headers]
        if missing:
            findings.append(
                Finding(
                    target=observation.host,
                    type="MISSING_SECURITY_HEADERS",
                    kind=ObservationKind.INDICATOR,
                    confidence=0.95,
                    severity=Priority.LOW,
                    source="HEADER_ANALYZER",
                    evidence=[
                        f"Missing: {', '.join(self.security_headers[name] for name in missing)}"
                    ],
                    recommended_action="Review the HTTP security-header baseline for this authorized asset.",
                    score=min(45, 10 + len(missing) * 5),
                )
            )
        return findings


class TechnologyAnalyzer:
    patterns = {
        "WordPress": [r"wp-content", r"wordpress"],
        "Drupal": [r"drupal-settings-json", r"/sites/default/"],
        "React": [r"react", r"__next_data__"],
        "Next.js": [r"__next_data__", r"/_next/"],
        "nginx": [r"nginx"],
        "Apache": [r"apache"],
        "PHP": [r"php", r"x-powered-by.*php"],
    }

    def detect(self, observation: HTTPObservation, body: str = "") -> list[Technology]:
        haystack = " ".join(
            [observation.title or "", observation.server or "", body, *observation.headers.values()]
        ).lower()
        technologies: list[Technology] = []
        for name, patterns in self.patterns.items():
            matches = [pattern for pattern in patterns if re.search(pattern, haystack, re.I)]
            if matches:
                technologies.append(
                    Technology(
                        name=name,
                        source="HTTP_ANALYZER",
                        confidence=min(0.98, 0.65 + len(matches) * 0.1),
                        evidence=matches,
                    )
                )
        return technologies


class MetadataAnalyzer:
    def extract(self, observation: HTTPObservation, body: str = "") -> dict[str, str | bool]:
        return {
            "title": observation.title or "",
            "server": observation.server or "",
            "content_type": observation.content_type or "",
            "robots_available": observation.robots_available,
            "sitemap_available": observation.sitemap_available,
            "response_size": str(observation.response_size),
            "has_login_signal": bool(
                re.search(
                    r"\b(log[ -]?in|sign[ -]?in|authenticate)\b",
                    f"{observation.title} {body}",
                    re.I,
                )
            ),
        }


class AdminInterfaceClassifier:
    def classify(
        self,
        observation: HTTPObservation,
        metadata: dict[str, str | bool],
        technologies: Iterable[Technology],
    ) -> Finding | None:
        evidence: list[str] = []
        text = f"{observation.title or ''} {observation.url}".lower()
        if metadata.get("has_login_signal"):
            evidence.append("Authentication-related text observed")
        if re.search(r"\b(admin|dashboard|management|console|control panel)\b", text, re.I):
            evidence.append("Management-console terminology observed")
        if not evidence:
            return None
        confidence = min(0.96, 0.62 + 0.12 * len(evidence))
        return Finding(
            target=observation.host,
            type="POTENTIAL_ADMIN_INTERFACE",
            kind=ObservationKind.POTENTIAL_RISK,
            confidence=confidence,
            severity=Priority.MEDIUM,
            source="ADMIN_INTERFACE_CLASSIFIER",
            evidence=evidence,
            recommended_action="Review exposure and verify authorization; do not attempt authentication.",
            score=65,
        )


class RiskScorer:
    def score(
        self,
        finding: Finding,
        exposure: int = 15,
        sensitive: int = 0,
        technology: int = 0,
        service: int = 0,
        weak_config: int = 0,
    ) -> Finding:
        raw = min(
            100.0,
            exposure + sensitive + technology + service + weak_config + finding.confidence * 10,
        )
        if raw >= 85:
            severity = Priority.CRITICAL
        elif raw >= 65:
            severity = Priority.HIGH
        elif raw >= 40:
            severity = Priority.MEDIUM
        elif raw >= 20:
            severity = Priority.LOW
        else:
            severity = Priority.INFO
        return finding.model_copy(update={"score": round(raw, 2), "severity": severity})
