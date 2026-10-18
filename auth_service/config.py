"""Configuration for the Hunar Vikas authentication service.

Only variable *names* belong in tracked files. Values come from an ignored
local .env or the deployment's secret storage (see .env.example).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional


def _flag(value: Optional[str], default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AuthConfig:
    secret_key: str
    database_url: str = "sqlite:///instance/auth.sqlite3"
    environment: str = "development"  # development | test | production
    app_base_url: str = "http://localhost:5000"
    allowed_origins: tuple = ()
    verify_path: str = "/verify-email"  # token is sent in the URL fragment
    reset_path: str = "/reset-password"  # token is sent in the URL fragment

    # Cookie / session policy
    cookie_secure: bool = False  # must be True in production (HTTPS only)
    cookie_samesite: str = "Lax"
    remember_absolute_seconds: int = 30 * 24 * 3600
    remember_idle_seconds: int = 14 * 24 * 3600
    session_absolute_seconds: int = 12 * 3600
    session_idle_seconds: int = 2 * 3600

    # One-time secrets
    code_ttl_seconds: int = 10 * 60
    code_max_attempts: int = 5
    resend_cooldown_seconds: int = 60
    reset_ttl_seconds: int = 30 * 60

    # Mail
    mail_backend: str = "file"  # file (development only) | smtp | resend
    mail_async: bool = True
    mail_outbox_dir: str = "instance/outbox"
    mail_from: str = "Hunar Vikas India <no-reply@localhost>"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    resend_api_key: str = ""
    resend_api_url: str = "https://api.resend.com/emails"
    support_url: str = "mailto:hello@hunarvikas.in"

    # Operators allowed to approve employers / change account status (CLI)
    operator_ids: tuple = ()
    terms_version: str = "2026-10-17"

    @property
    def cookie_name(self) -> str:
        # The __Host- prefix pins the cookie to this origin over HTTPS.
        return "__Host-hv_session" if self.cookie_secure else "hv_session"

    def validate(self) -> "AuthConfig":
        problems = []
        if len(self.secret_key) < 32:
            problems.append("AUTH_SECRET_KEY must be at least 32 characters")
        if self.environment not in {"development", "test", "production"}:
            problems.append("AUTH_ENV must be development, test or production")
        if self.cookie_samesite not in {"Lax", "Strict"}:
            problems.append("AUTH_COOKIE_SAMESITE must be Lax or Strict")
        if self.mail_backend not in {"file", "smtp", "resend"}:
            problems.append("AUTH_MAIL_BACKEND must be file, smtp or resend")
        if self.mail_backend == "smtp":
            if not self.smtp_host:
                problems.append("AUTH_SMTP_HOST is required for the smtp mail backend")
            if self.environment == "production" and not self.smtp_user:
                problems.append("AUTH_SMTP_USER is required for production SMTP")
            if self.environment == "production" and not self.smtp_password:
                problems.append("AUTH_SMTP_PASSWORD is required for production SMTP")
        if self.mail_backend == "resend" and self.environment == "production":
            if not self.resend_api_key:
                problems.append("AUTH_RESEND_API_KEY is required for production Resend")
        if self.environment == "production":
            if not self.cookie_secure:
                problems.append("AUTH_COOKIE_SECURE must be true in production")
            if self.mail_backend not in {"smtp", "resend"}:
                problems.append("production requires AUTH_MAIL_BACKEND=smtp or resend")
            if not self.app_base_url.startswith("https://"):
                problems.append("AUTH_APP_BASE_URL must be https in production")
        if problems:
            raise ValueError("Invalid auth configuration: " + "; ".join(problems))
        return self

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "AuthConfig":
        env = os.environ if env is None else env
        operators = tuple(
            o.strip() for o in env.get("AUTH_OPERATOR_IDS", "").split(",") if o.strip()
        )
        defaults = cls(secret_key="")
        configured_origins = tuple(
            origin.strip().rstrip("/") for origin in env.get("AUTH_ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        )
        environment = env.get("AUTH_ENV", defaults.environment)
        if not configured_origins and environment != "production":
            configured_origins = (
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            )
        return cls(
            secret_key=env.get("AUTH_SECRET_KEY", ""),
            database_url=env.get("AUTH_DATABASE_URL", defaults.database_url),
            environment=environment,
            app_base_url=env.get("AUTH_APP_BASE_URL", defaults.app_base_url).rstrip("/"),
            allowed_origins=configured_origins,
            verify_path=env.get("AUTH_VERIFY_PATH", defaults.verify_path),
            reset_path=env.get("AUTH_RESET_PATH", defaults.reset_path),
            cookie_secure=_flag(env.get("AUTH_COOKIE_SECURE"), False),
            cookie_samesite=env.get("AUTH_COOKIE_SAMESITE", defaults.cookie_samesite),
            mail_backend=env.get("AUTH_MAIL_BACKEND", defaults.mail_backend),
            mail_async=_flag(env.get("AUTH_MAIL_ASYNC"), True),
            mail_outbox_dir=env.get("AUTH_MAIL_OUTBOX_DIR", defaults.mail_outbox_dir),
            mail_from=env.get("AUTH_MAIL_FROM", defaults.mail_from),
            smtp_host=env.get("AUTH_SMTP_HOST", ""),
            smtp_port=int(env.get("AUTH_SMTP_PORT", "587")),
            smtp_user=env.get("AUTH_SMTP_USER", ""),
            smtp_password=env.get("AUTH_SMTP_PASSWORD", ""),
            resend_api_key=env.get("AUTH_RESEND_API_KEY", ""),
            resend_api_url=env.get("AUTH_RESEND_API_URL", "https://api.resend.com/emails"),
            support_url=env.get("AUTH_SUPPORT_URL", defaults.support_url),
            operator_ids=operators,
        ).validate()
