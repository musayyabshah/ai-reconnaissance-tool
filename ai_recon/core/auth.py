from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, EmailStr


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Principal(BaseModel):
    user_id: str
    organization_id: str
    email: EmailStr
    role: Role


class AuthError(ValueError):
    pass


class AuthStore:
    """SQLite-backed identity store; only password hashes and token hashes are persisted."""

    def __init__(self, database_url: str) -> None:
        self.path = Path(database_url.removeprefix("sqlite:///"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS organizations (organization_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
                """
            )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _password_hash(password: str, salt: bytes | None = None) -> str:
        if len(password) < 12:
            raise AuthError("Password must contain at least 12 characters")
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            candidate = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
            ).hex()
            return hmac.compare_digest(candidate, digest_hex)
        except (ValueError, TypeError):
            return False

    def bootstrap(self, organization_name: str, email: str, password: str) -> Principal:
        with sqlite3.connect(self.path) as connection:
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise AuthError("Bootstrap has already been completed")
        organization_id = secrets.token_hex(12)
        user_id = secrets.token_hex(12)
        now = self._now().isoformat()
        try:
            with sqlite3.connect(self.path) as connection:
                connection.execute(
                    "INSERT INTO organizations VALUES (?, ?, ?)",
                    (organization_id, organization_name, now),
                )
                connection.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        organization_id,
                        email.lower(),
                        self._password_hash(password),
                        Role.OWNER.value,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthError(
                "Organization bootstrap failed because the identity already exists"
            ) from exc
        return Principal(
            user_id=user_id, organization_id=organization_id, email=email.lower(), role=Role.OWNER
        )

    def add_user(
        self, principal: Principal, email: str, password: str, role: Role = Role.ANALYST
    ) -> Principal:
        if principal.role not in {Role.OWNER, Role.ADMIN}:
            raise AuthError("Only organization owners or admins may add users")
        user_id = secrets.token_hex(12)
        now = self._now().isoformat()
        try:
            with sqlite3.connect(self.path) as connection:
                connection.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        principal.organization_id,
                        email.lower(),
                        self._password_hash(password),
                        role.value,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthError("User creation failed because the email already exists") from exc
        return Principal(
            user_id=user_id,
            organization_id=principal.organization_id,
            email=email.lower(),
            role=role,
        )

    def authenticate(self, email: str, password: str, ttl_hours: int = 12) -> tuple[str, Principal]:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT user_id, organization_id, email, password_hash, role FROM users WHERE email = ?",
                (email.lower(),),
            ).fetchone()
        if not row or not self._verify_password(password, row[3]):
            raise AuthError("Invalid credentials")
        principal = Principal(
            user_id=row[0], organization_id=row[1], email=row[2], role=Role(row[4])
        )
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?)",
                (
                    token_hash,
                    principal.user_id,
                    (self._now() + timedelta(hours=ttl_hours)).isoformat(),
                    self._now().isoformat(),
                ),
            )
        return token, principal

    def resolve(self, token: str) -> Principal:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT u.user_id, u.organization_id, u.email, u.role, s.expires_at FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token_hash=?",
                (token_hash,),
            ).fetchone()
        if not row or datetime.fromisoformat(row[4]) <= self._now():
            raise AuthError("Invalid or expired token")
        return Principal(user_id=row[0], organization_id=row[1], email=row[2], role=Role(row[3]))

    @staticmethod
    def require_role(principal: Principal, *roles: Role) -> None:
        if principal.role not in roles:
            raise AuthError("Insufficient role for this operation")
