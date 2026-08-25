from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditStore:
    def __init__(self, database_url: str) -> None:
        self.path = Path(database_url.removeprefix("sqlite:///"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_events (event_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, actor_id TEXT, action TEXT NOT NULL, target TEXT, details_json TEXT NOT NULL, event_hash TEXT NOT NULL, previous_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_events(organization_id, created_at)"
            )

    def record(
        self,
        organization_id: str,
        action: str,
        actor_id: str | None = None,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        created_at = datetime.now(timezone.utc).isoformat()
        event_id = secrets.token_hex(12)
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(self.path) as connection:
            previous = connection.execute(
                "SELECT event_hash FROM audit_events WHERE organization_id = ? ORDER BY created_at DESC LIMIT 1",
                (organization_id,),
            ).fetchone()
            previous_hash = previous[0] if previous else "GENESIS"
            material = "|".join(
                [
                    event_id,
                    organization_id,
                    actor_id or "",
                    action,
                    target or "",
                    details_json,
                    previous_hash,
                    created_at,
                ]
            )
            event_hash = hashlib.sha256(material.encode()).hexdigest()
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    organization_id,
                    actor_id,
                    action,
                    target,
                    details_json,
                    event_hash,
                    previous_hash,
                    created_at,
                ),
            )
        return event_id

    def verify_chain(self, organization_id: str) -> bool:
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                "SELECT event_id, actor_id, action, target, details_json, event_hash, previous_hash, created_at FROM audit_events WHERE organization_id = ? ORDER BY created_at ASC",
                (organization_id,),
            ).fetchall()
        previous_hash = "GENESIS"
        for (
            event_id,
            actor_id,
            action,
            target,
            details_json,
            event_hash,
            stored_previous,
            created_at,
        ) in rows:
            if stored_previous != previous_hash:
                return False
            material = "|".join(
                [
                    event_id,
                    organization_id,
                    actor_id or "",
                    action,
                    target or "",
                    details_json,
                    previous_hash,
                    created_at,
                ]
            )
            if hashlib.sha256(material.encode()).hexdigest() != event_hash:
                return False
            previous_hash = event_hash
        return True
