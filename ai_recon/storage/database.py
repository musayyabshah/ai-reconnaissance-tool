from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ai_recon.models.entities import ScanReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


class ScanRepository:
    def __init__(self, database_url: str = "sqlite:///data/recon.db") -> None:
        path = database_url.removeprefix("sqlite:///")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.executescript(SCHEMA)

    def save(self, report: ScanReport) -> None:
        payload = report.model_dump_json()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO scans(scan_id,target,started_at,completed_at,report_json) VALUES(?,?,?,?,?)",
                (
                    report.scan_id,
                    report.target.value,
                    report.started_at.isoformat(),
                    report.completed_at.isoformat() if report.completed_at else None,
                    payload,
                ),
            )

    def get(self, scan_id: str) -> ScanReport | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return ScanReport.model_validate_json(row[0]) if row else None

    def latest(self) -> ScanReport | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT report_json FROM scans ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return ScanReport.model_validate_json(row[0]) if row else None

    def list_assets(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        report = self.get(scan_id) if scan_id else self.latest()
        return [asset.model_dump(mode="json") for asset in report.assets] if report else []

    def list_findings(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        report = self.get(scan_id) if scan_id else self.latest()
        return [finding.model_dump(mode="json") for finding in report.findings] if report else []
