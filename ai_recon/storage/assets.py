from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ai_recon.models.entities import Asset


class AssetRegistry:
    def __init__(self, database_url: str) -> None:
        self.path = Path(database_url.removeprefix("sqlite:///"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS managed_assets (organization_id TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL, criticality INTEGER NOT NULL, owner TEXT, environment TEXT NOT NULL, tags_json TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (organization_id, name))"
            )

    def upsert(self, organization_id: str, asset: Asset) -> Asset:
        updated = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO managed_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    organization_id,
                    asset.name,
                    asset.kind,
                    asset.criticality,
                    asset.owner,
                    asset.environment,
                    json.dumps(asset.tags),
                    updated,
                ),
            )
        return asset

    def get(self, organization_id: str, name: str) -> Asset | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT name, kind, criticality, owner, environment, tags_json FROM managed_assets WHERE organization_id=? AND name=?",
                (organization_id, name),
            ).fetchone()
        if not row:
            return None
        return Asset(
            name=row[0],
            kind=row[1],
            criticality=row[2],
            owner=row[3],
            environment=row[4],
            tags=json.loads(row[5]),
        )

    def list(self, organization_id: str) -> list[Asset]:
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                "SELECT name, kind, criticality, owner, environment, tags_json FROM managed_assets WHERE organization_id=? ORDER BY name",
                (organization_id,),
            ).fetchall()
        return [
            Asset(
                name=row[0],
                kind=row[1],
                criticality=row[2],
                owner=row[3],
                environment=row[4],
                tags=json.loads(row[5]),
            )
            for row in rows
        ]

    def hydrate(self, organization_id: str, assets: list[Asset]) -> list[Asset]:
        result: list[Asset] = []
        for asset in assets:
            managed = self.get(organization_id, asset.name)
            result.append(
                asset.model_copy(
                    update={
                        "criticality": managed.criticality,
                        "owner": managed.owner,
                        "environment": managed.environment,
                        "tags": managed.tags,
                    }
                )
                if managed
                else asset
            )
        return result
