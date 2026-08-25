from __future__ import annotations

from pathlib import Path

import yaml

from ai_recon.models.vulnerability import DetectionRule


class RuleLoadError(ValueError):
    pass


def load_rules(path: str | Path) -> list[DetectionRule]:
    file_path = Path(path)
    if not file_path.exists():
        raise RuleLoadError(f"Rule file does not exist: {file_path}")
    raw = yaml.safe_load(file_path.read_text()) or {}
    entries = raw.get("rules", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise RuleLoadError("Rule file must contain a list under 'rules'")
    rules: list[DetectionRule] = []
    for entry in entries:
        try:
            rule = DetectionRule.model_validate(entry)
            rule.validate_safe()
            rules.append(rule)
        except (TypeError, ValueError) as exc:
            raise RuleLoadError(f"Invalid detection rule: {exc}") from exc
    return rules
