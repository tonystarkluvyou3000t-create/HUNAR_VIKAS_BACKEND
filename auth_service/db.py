"""Auth-owned database schema.

Separate from the feature app's stores. Holds credentials, sessions,
organisations/approval and the audit trail; never profile data.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url

metadata = MetaData()


def utcnow() -> datetime:
    """Naive UTC timestamp (stored as UTC everywhere)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


users = Table(
    "users",
    metadata,
    Column("user_id", String(64), primary_key=True),  # "hv:user:<uuid4 hex>", immutable
    Column("member_code", String(20), nullable=False, unique=True),  # HVI-XXXX-XXXX-C
    Column("email", String(254), nullable=False, unique=True),
    Column("display_name", String(100), nullable=False, default=""),
    Column("role", String(16), nullable=False),
    Column("account_status", String(24), nullable=False),
    Column("email_verified_at", DateTime),
    Column("password_hash", String(255), nullable=False),
    Column("terms_version", String(32)),
    Column("terms_accepted_at", DateTime),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    CheckConstraint("role IN ('individual','employer')", name="ck_users_role"),
    CheckConstraint(
        "account_status IN ('pending_verification','active','suspended','deleted')",
        name="ck_users_status",
    ),
)

organizations = Table(
    "organizations",
    metadata,
    Column("organization_id", String(64), primary_key=True),
    Column("name", String(150), nullable=False),
    Column("approval_status", String(16), nullable=False, default="pending"),
    Column("reviewed_by", String(64)),
    Column("reviewed_at", DateTime),
    Column("review_reason", String(500)),  # restricted: never returned by any API
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    CheckConstraint(
        "approval_status IN ('pending','approved','rejected','revoked')",
        name="ck_org_approval",
    ),
)

organization_members = Table(
    "organization_members",
    metadata,
    Column("user_id", String(64), ForeignKey("users.user_id"), primary_key=True),
    Column("organization_id", String(64), ForeignKey("organizations.organization_id"), primary_key=True),
    Column("status", String(16), nullable=False, default="active"),  # active | removed
    Column("created_at", DateTime, nullable=False),
    CheckConstraint("status IN ('active','removed')", name="ck_member_status"),
)

sessions = Table(
    "sessions",
    metadata,
    Column("session_hash", String(64), primary_key=True),  # sha256 of the cookie value
    Column("user_id", String(64), ForeignKey("users.user_id"), nullable=False, index=True),
    Column("remember", Boolean, nullable=False, default=False),
    Column("created_at", DateTime, nullable=False),
    Column("last_seen_at", DateTime, nullable=False),
    Column("expires_at", DateTime, nullable=False),  # absolute expiry
    Column("idle_seconds", Integer, nullable=False),
    Column("revoked_at", DateTime),
)

verification_codes = Table(
    "verification_codes",
    metadata,
    Column("code_id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey("users.user_id"), nullable=False, index=True),
    Column("otp_hash", String(64), nullable=False),  # keyed hash; the 6-digit code is never stored
    Column("token_hash", String(64), nullable=False, index=True),  # link token
    Column("attempts", Integer, nullable=False, default=0),
    Column("expires_at", DateTime, nullable=False),
    Column("used_at", DateTime),
    Column("created_at", DateTime, nullable=False),
)

password_resets = Table(
    "password_resets",
    metadata,
    Column("reset_id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey("users.user_id"), nullable=False, index=True),
    Column("token_hash", String(64), nullable=False, index=True),
    Column("expires_at", DateTime, nullable=False),
    Column("used_at", DateTime),
    Column("created_at", DateTime, nullable=False),
)

rate_events = Table(
    "rate_events",
    metadata,
    Column("event_id", Integer, primary_key=True, autoincrement=True),
    Column("bucket", String(96), nullable=False),  # "<kind>:<keyed hash>", no raw IPs/e-mails
    Column("created_at", DateTime, nullable=False),
    Index("ix_rate_bucket_time", "bucket", "created_at"),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("audit_id", Integer, primary_key=True, autoincrement=True),
    Column("subject_type", String(16), nullable=False),  # organization | user
    Column("subject_id", String(64), nullable=False),
    Column("action", String(32), nullable=False),
    Column("reviewer", String(64), nullable=False),
    Column("reason", String(500)),
    Column("created_at", DateTime, nullable=False),
)


def make_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    kwargs = {"future": True, "pool_pre_ping": True}
    if url.get_backend_name() == "sqlite":
        if url.database and url.database != ":memory:":
            parent = os.path.dirname(os.path.abspath(url.database))
            os.makedirs(parent, exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine
