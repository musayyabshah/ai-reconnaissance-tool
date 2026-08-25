from __future__ import annotations

import json
import os
import re
from typing import Any

from pydantic import ValidationError

from ai_recon.models.entities import AIAnalysis, HTTPObservation, Priority, Technology

APPLICATION_TYPES = [
    "CMS",
    "E-COMMERCE",
    "API",
    "AUTHENTICATION_PORTAL",
    "ADMIN_INTERFACE",
    "DOCUMENTATION",
    "DEVELOPER_PORTAL",
    "WEB_APPLICATION",
    "STATIC_SITE",
    "CLOUD_SERVICE",
    "UNKNOWN",
]


class SemanticAnalyzer:
    def __init__(self, model: str = "gpt-5-mini", enabled: bool = True) -> None:
        self.model = model
        self.enabled = enabled

    def _heuristic(
        self, observation: HTTPObservation, technologies: list[Technology]
    ) -> AIAnalysis:
        text = f"{observation.title or ''} {observation.url}".lower()
        tech_names = [item.name for item in technologies]
        indicators: list[str] = []
        if re.search(r"login|sign[ -]?in|authenticate", text):
            application_type = "AUTHENTICATION_PORTAL"
            indicators.append("Authentication-related page metadata")
        elif re.search(r"api|swagger|openapi", text):
            application_type = "API"
            indicators.append("API-related page metadata")
        elif re.search(r"docs|documentation|developer", text):
            application_type = "DOCUMENTATION"
            indicators.append("Documentation-related page metadata")
        elif tech_names:
            application_type = "WEB_APPLICATION"
            indicators.append("Observable technology indicators")
        else:
            application_type = "UNKNOWN"
        priority = (
            Priority.MEDIUM
            if application_type in {"AUTHENTICATION_PORTAL", "ADMIN_INTERFACE"}
            else Priority.INFO
        )
        return AIAnalysis(
            application_type=application_type,
            confidence=0.66 if application_type != "UNKNOWN" else 0.35,
            technologies=tech_names,
            indicators=indicators,
            priority=priority,
        )

    def analyze(self, observation: HTTPObservation, technologies: list[Technology]) -> AIAnalysis:
        fallback = self._heuristic(observation, technologies)
        if not self.enabled or not os.getenv("OPENAI_API_KEY"):
            return fallback
        try:
            from openai import OpenAI

            client = OpenAI()
            schema: dict[str, Any] = {
                "type": "object",
                "properties": {
                    "application_type": {"type": "string", "enum": APPLICATION_TYPES},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "technologies": {"type": "array", "items": {"type": "string"}},
                    "indicators": {"type": "array", "items": {"type": "string"}},
                    "priority": {"type": "string", "enum": [item.value for item in Priority]},
                },
                "required": [
                    "application_type",
                    "confidence",
                    "technologies",
                    "indicators",
                    "priority",
                ],
                "additionalProperties": False,
            }
            prompt = {
                "url": observation.url,
                "status": observation.status,
                "title": observation.title,
                "server": observation.server,
                "content_type": observation.content_type,
                "security_headers": observation.headers,
                "technology_indicators": [item.name for item in technologies],
            }
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "Classify only observable, non-sensitive web metadata. Never infer or claim a confirmed vulnerability. Output JSON only.",
                    },
                    {"role": "user", "content": json.dumps(prompt)},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "recon_classification",
                        "strict": True,
                        "schema": schema,
                    },
                },
                max_completion_tokens=600,
            )
            content = response.choices[0].message.content or ""
            parsed = AIAnalysis.model_validate(json.loads(content))
            return parsed.model_copy(update={"provider": self.model})
        except (ImportError, OSError, ValueError, ValidationError, json.JSONDecodeError, Exception):
            return fallback
