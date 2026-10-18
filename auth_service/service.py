
"""Authentication business logic (no HTTP concerns except the identity resolver)."""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from flask import g, request
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .config import AuthConfig
from .db import (
    audit_log,
    make_engine,
    metadata,
    organization_members,
    organizations,
    password_resets,
    rate_events,
    sessions,
    users,
    utcnow,
    verification_codes,
)
from .mailer import Mailer
from .security import (
    DUMMY_HASH,
    constant_time_equals,
    csrf_token_for,
    generate_member_code,
    generate_otp,
    hash_password,
    keyed_hash,
    new_token,
    password_needs_rehash,
    sha256_hex,
    verify_password,
)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "1234567890",
    "qwerty123", "iloveyou", "11111111", "00000000", "abcd1234",
}
APPROVAL_ACTIONS = {
    # action -> (new status, allowed current statuses)
    "approve": ("approved", {"pending", "rejected", "revoked"}),
    "reject": ("rejected", {"pending"}),
    "revoke": ("revoked", {"approved"}),
}
_UNSET = object()


class AuthError(Exception):
    def __init__(self, status: int, code: str, message: str, fields=None, headers=None):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.fields = fields or {}
        self.headers = headers or {}


class AuthUnavailable(AuthError):
    def __init__(self):
        super().__init__(503, "auth_unavailable", "Authentication service unavailable.")


@dataclass(frozen=True)
class SessionInfo:
    session_hash: str
    user_id: str
    member_code: str
    email: str
    display_name: str
    role: str
    organization: str  # organisation name (empty unless employer with a membership)
    approval_status: Optional[str]  # None for individuals
    approved: bool
    remember: bool


def norm_email(value) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


class AuthService:
    def __init__(self, config: AuthConfig, engine=None, mailer: Optional[Mailer] = None):
        self.cfg = config.validate()
        self.engine = engine or make_engine(config.database_url)
        self.mailer = mailer or Mailer(config)

    @classmethod
    def from_env(cls) -> "AuthService":
        return cls(AuthConfig.from_env())

    def init_db(self) -> None:
        metadata.create_all(self.engine)

    def init_app(self, app) -> None:
        """Mount /api/auth/*, the CSRF/origin guard and error handling on the feature app."""
        from .routes import init_app  # local import: routes imports this module

        init_app(app, self)

    # ------------------------------------------------------------------
    # Rate limiting (database-backed so it holds across worker processes;
    # keys are HMACs, so raw e-mails/IPs are not retained)
    # ------------------------------------------------------------------
    def _bucket(self, kind: str, value: str) -> str:
        return f"{kind}:{keyed_hash(self.cfg.secret_key, 'rl', value)}"

    def _limit_check(self, kind: str, value: str, limit: int, window: int) -> None:
        bucket, since = self._bucket(kind, value), utcnow() - timedelta(seconds=window)
        with self.engine.connect() as conn:
            count = conn.execute(
                select(func.count()).select_from(rate_events).where(
                    rate_events.c.bucket == bucket, rate_events.c.created_at > since
                )
            ).scalar_one()
        if count >= limit:
            raise AuthError(
                429, "rate_limited", "Too many attempts. Please wait and try again.",
                headers={"Retry-After": str(window)},
            )

    def _limit_record(self, kind: str, value: str) -> None:
        now = utcnow()
        with self.engine.begin() as conn:
            conn.execute(insert(rate_events).values(bucket=self._bucket(kind, value), created_at=now))
            if secrets.randbelow(50) == 0:  # opportunistic cleanup
                conn.execute(delete(rate_events).where(rate_events.c.created_at < now - timedelta(days=2)))

    def _limit_hit(self, kind: str, value: str, limit: int, window: int) -> None:
        self._limit_check(kind, value, limit, window)
        self._limit_record(kind, value)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @staticmethod
    def _check_password(password) -> Optional[str]:
        if not isinstance(password, str) or not (8 <= len(password) <= 128):
            return "Password must be 8 to 128 characters."
        if password.lower() in COMMON_PASSWORDS:
            return "Choose a less common password."
        return None

    def _validate_registration(self, data: dict) -> dict:
        fields = {}
        email = norm_email(data.get("email"))
        if not email or len(email) > 254 or not EMAIL_RE.match(email) or CONTROL_RE.search(email):
            fields["email"] = "Enter a valid email address."
        problem = self._check_password(data.get("password"))
        if problem:
            fields["password"] = problem
        name = data.get("display_name") or ""
        if not isinstance(name, str) or len(name.strip()) > 100 or CONTROL_RE.search(name):
            fields["display_name"] = "Name must be at most 100 characters."
            name = ""
        account_type = data.get("account_type")
        if account_type not in ("individual", "employer"):
            fields["account_type"] = "Account type must be individual or employer."
        org = data.get("organization_name")
        if account_type == "employer":
            if not isinstance(org, str) or not (2 <= len(org.strip()) <= 150) or CONTROL_RE.search(org):
                fields["organization_name"] = "Enter your organisation name (2 to 150 characters)."
        else:
            org = ""
        if data.get("accept_terms") is not True:
            fields["accept_terms"] = "Please accept the Terms to continue."
        if fields:
            raise AuthError(400, "invalid_input", "Please correct the highlighted fields.", fields)
        return {
            "email": email, "password": data["password"], "display_name": name.strip(),
            "account_type": account_type, "organization_name": (org or "").strip(),
        }

    # ------------------------------------------------------------------
    # Registration + e-mail verification
    # ------------------------------------------------------------------
    def _insert_user(self, conn, *, email, pw_hash, display_name, role, status, verified,
                     org_name="", org_status="pending") -> str:
        now = utcnow()
        user_id = "hv:user:" + uuid.uuid4().hex
        conn.execute(insert(users).values(
            user_id=user_id, member_code=generate_member_code(), email=email,
            display_name=display_name, role=role, account_status=status,
            email_verified_at=now if verified else None, password_hash=pw_hash,
            terms_version=self.cfg.terms_version, terms_accepted_at=now,
            created_at=now, updated_at=now,
        ))
        if role == "employer":
            org_id = "hv:org:" + uuid.uuid4().hex
            conn.execute(insert(organizations).values(
                organization_id=org_id, name=org_name, approval_status=org_status,
                created_at=now, updated_at=now,
            ))
            conn.execute(insert(organization_members).values(
                user_id=user_id, organization_id=org_id, status="active", created_at=now,
            ))
        return user_id

    def _issue_code(self, conn, user_id: str, respect_cooldown: bool = False):
        now = utcnow()
        if respect_cooldown:
            last = conn.execute(
                select(func.max(verification_codes.c.created_at)).where(
                    verification_codes.c.user_id == user_id, verification_codes.c.used_at.is_(None)
                )
            ).scalar()
            if last and (now - last).total_seconds() < self.cfg.resend_cooldown_seconds:
                return None
        conn.execute(delete(verification_codes).where(
            verification_codes.c.user_id == user_id, verification_codes.c.used_at.is_(None)))
        otp, token = generate_otp(), new_token()
        conn.execute(insert(verification_codes).values(
            code_id=uuid.uuid4().hex, user_id=user_id,
            otp_hash=keyed_hash(self.cfg.secret_key, f"otp:{user_id}", otp),
            token_hash=sha256_hex(token), attempts=0,
            expires_at=now + timedelta(seconds=self.cfg.code_ttl_seconds), created_at=now,
        ))
        return otp, token

    def _mail_verification(self, email: str, display_name: str, issued) -> None:
        otp, token = issued
        base = self.cfg.app_base_url
        self.mailer.send("verify", email, {
            "userName": display_name or "there", "userEmail": email, "otp": otp,
            "verificationUrl": f"{base}{self.cfg.verify_path}#token={token}",
            "expiryMinutes": self.cfg.code_ttl_seconds // 60,
            "exploreSkillsUrl": f"{base}/#skills", "trainingUrl": f"{base}/#training",
        })

    def register(self, data: dict, ip: str) -> dict:
        """Blocks already-active accounts before calling Resend (0 emails used)
        and reuses unexpired OTPs within the cooldown window for pending accounts."""
        clean = self._validate_registration(data)
        # Check IP rate limit first, and only check (don't record yet) email limit
        self._limit_hit("reg_ip", ip, 10, 3600)
        self._limit_check("reg_email", clean["email"], 5, 3600)

        pw_hash = hash_password(clean["password"])  # always hashed: uniform timing
        mail = None
        otp_already_sent = False
        cooldown_remaining = self.cfg.resend_cooldown_seconds

        for _ in range(3):
            try:
                with self.engine.begin() as conn:
                    existing = conn.execute(
                        select(users).where(users.c.email == clean["email"])
                    ).mappings().first()

                    if existing is None:
                        user_id = self._insert_user(
                            conn, email=clean["email"], pw_hash=pw_hash,
                            display_name=clean["display_name"], role=clean["account_type"],
                            status="pending_verification", verified=False,
                            org_name=clean["organization_name"]
                        )
                        mail = (
                            "verify",
                            clean["email"],
                            clean["display_name"],
                            self._issue_code(conn, user_id),
                        )

                    elif existing["account_status"] == "pending_verification":
                        now = utcnow()
                        # Update pending credentials in case the user is correcting a typo before verifying
                        conn.execute(
                            update(users)
                            .where(users.c.user_id == existing["user_id"])
                            .values(
                                password_hash=pw_hash,
                                display_name=clean["display_name"],
                                updated_at=now,
                            )
                        )

                        active_code = conn.execute(
                            select(verification_codes)
                            .where(
                                verification_codes.c.user_id == existing["user_id"],
                                verification_codes.c.used_at.is_(None),
                                verification_codes.c.expires_at > now,
                            )
                            .order_by(verification_codes.c.created_at.desc())
                            .limit(1)
                        ).mappings().first()

                        if active_code is not None:
                            elapsed = int((now - active_code["created_at"]).total_seconds())
                            if elapsed < self.cfg.resend_cooldown_seconds:
                                # Within 60s cooldown -> reuse OTP already in inbox (0 emails sent)
                                otp_already_sent = True
                                cooldown_remaining = max(0, self.cfg.resend_cooldown_seconds - elapsed)
                            else:
                                # Cooldown passed -> issue fresh OTP
                                issued = self._issue_code(conn, existing["user_id"], respect_cooldown=False)
                                if issued:
                                    mail = ("verify", clean["email"], clean["display_name"], issued)
                        else:
                            # Previous OTP expired -> issue fresh OTP
                            issued = self._issue_code(conn, existing["user_id"], respect_cooldown=False)
                            if issued:
                                mail = ("verify", clean["email"], clean["display_name"], issued)

                    elif existing["account_status"] == "active":
                        # Stop immediately: 0 Resend emails used, never goes to OTP page
                        raise AuthError(
                            409,
                            "account_exists",
                            "An account with this email already exists. Please sign in.",
                            fields={"email": "An account with this email already exists. Please sign in."},
                        )
                    else:
                        raise AuthError(
                            403,
                            "account_unavailable",
                            "This account is unavailable.",
                        )
                break
            except IntegrityError:
                continue  # concurrent signup or code collision: re-evaluate

        if mail:
            # Only record against the 5/hour email limit when an email is actually sent
            self._limit_record("reg_email", clean["email"])
            _, email, name, issued = mail
            self._mail_verification(email, name, issued)

        return {
            "verification_required": True,
            "otp_already_sent": otp_already_sent,
            "cooldown_seconds": cooldown_remaining,
        }

    def resend_verification(self, email_raw, ip: str) -> dict:
        email = norm_email(email_raw)
        self._limit_hit("resend_ip", ip, 10, 3600)
        if email:
            # Enforce 60-second cooldown BEFORE counting against the 5/hour limit
            self._limit_hit("resend_cooldown", email, 1, self.cfg.resend_cooldown_seconds)
            self._limit_hit("resend_email", email, 5, 3600)
            mail = None
            with self.engine.begin() as conn:
                row = conn.execute(select(users).where(
                    users.c.email == email, users.c.account_status == "pending_verification"
                )).mappings().first()
                if row:
                    issued = self._issue_code(conn, row["user_id"], respect_cooldown=False)
                    if issued:
                        mail = (row["email"], row["display_name"], issued)
            if mail:
                self._mail_verification(*mail)
        return {"ok": True, "cooldown_seconds": self.cfg.resend_cooldown_seconds}

    def verify_email(self, data: dict, ip: str, remember: bool = False):
        """Verify by e-mail+code or by link token. Returns (session_token, SessionInfo)."""
        self._limit_hit("verify_ip", ip, 30, 900)
        email, otp, token = norm_email(data.get("email")), data.get("otp"), data.get("token")
        if email:
            self._limit_hit("verify_email", email, 10, 900)
        bad = AuthError(400, "invalid_code", "That code is invalid or has expired.")
        if isinstance(token, str) and token:
            lookup = ("token", sha256_hex(token[:200]))
        elif email and isinstance(otp, str) and re.fullmatch(r"\d{6}", otp):
            lookup = ("otp", otp)
        else:
            raise bad
        now, outcome, user_id = utcnow(), "bad", None
        with self.engine.begin() as conn:
            if lookup[0] == "token":
                row = conn.execute(
                    select(verification_codes, users.c.account_status)
                    .join(users, users.c.user_id == verification_codes.c.user_id)
                    .where(verification_codes.c.token_hash == lookup[1])).mappings().first()
            else:
                row = conn.execute(
                    select(verification_codes, users.c.account_status)
                    .join(users, users.c.user_id == verification_codes.c.user_id)
                    .where(users.c.email == email, verification_codes.c.used_at.is_(None))
                    .order_by(verification_codes.c.created_at.desc()).limit(1)).mappings().first()
            if (row and row["used_at"] is None and row["expires_at"] > now
                    and row["attempts"] < self.cfg.code_max_attempts
                    and row["account_status"] == "pending_verification"):
                match = lookup[0] == "token" or constant_time_equals(
                    row["otp_hash"], keyed_hash(self.cfg.secret_key, f"otp:{row['user_id']}", lookup[1]))
                if match:
                    conn.execute(update(verification_codes).where(
                        verification_codes.c.code_id == row["code_id"]).values(used_at=now))
                    conn.execute(update(users).where(users.c.user_id == row["user_id"]).values(
                        account_status="active", email_verified_at=now, updated_at=now))
                    outcome, user_id = "ok", row["user_id"]
                else:
                    conn.execute(update(verification_codes).where(
                        verification_codes.c.code_id == row["code_id"]
                    ).values(attempts=verification_codes.c.attempts + 1))
        if outcome != "ok":  # raised after the transaction so the attempt count persists
            raise bad
        with self.engine.begin() as conn:
            session_token = self._create_session(conn, user_id, remember)
        return session_token, self.lookup_session(session_token)

    # ------------------------------------------------------------------
    # Login / sessions
    # ------------------------------------------------------------------
    def _create_session(self, conn, user_id: str, remember: bool) -> str:
        """Always mints a fresh id (rotation): a pre-login cookie is never reused."""
        token, now = new_token(), utcnow()
        absolute = self.cfg.remember_absolute_seconds if remember else self.cfg.session_absolute_seconds
        idle = self.cfg.remember_idle_seconds if remember else self.cfg.session_idle_seconds
        conn.execute(insert(sessions).values(
            session_hash=sha256_hex(token), user_id=user_id, remember=remember,
            created_at=now, last_seen_at=now, expires_at=now + timedelta(seconds=absolute),
            idle_seconds=idle))
        return token

    def login(self, data: dict, ip: str):
        email, password = norm_email(data.get("email")), data.get("password")
        if not email or not isinstance(password, str) or not password:
            raise AuthError(400, "invalid_input", "Email and password are required.")
        remember = data.get("remember") is True
        self._limit_check("login_ip", ip, 50, 900)
        self._limit_check("login_email", email, 10, 900)
        with self.engine.connect() as conn:
            row = conn.execute(select(users).where(users.c.email == email)).mappings().first()
        ok = verify_password(row["password_hash"] if row else DUMMY_HASH, password[:1024]) and len(password) <= 1024
        if not (row and ok):
            self._limit_record("login_ip", ip)
            self._limit_record("login_email", email)
            raise AuthError(401, "invalid_credentials", "Invalid email or password.")
        if row["account_status"] == "pending_verification" or row["email_verified_at"] is None:
            raise AuthError(403, "email_not_verified", "Please verify your email address first.")
        if row["account_status"] != "active":
            raise AuthError(403, "account_unavailable", "This account is unavailable.")
        with self.engine.begin() as conn:
            token = self._create_session(conn, row["user_id"], remember)
            if password_needs_rehash(row["password_hash"]):
                conn.execute(update(users).where(users.c.user_id == row["user_id"]).values(
                    password_hash=hash_password(password), updated_at=utcnow()))
        return token, self.lookup_session(token)

    def lookup_session(self, raw_token: Optional[str]) -> Optional[SessionInfo]:
        """Validate a cookie value against the database. Re-checks account status
        and employer approval on every call, so revocations apply immediately."""
        if not raw_token or len(raw_token) > 200:
            return None
        h, now = sha256_hex(raw_token), utcnow()
        with self.engine.begin() as conn:
            row = conn.execute(
                select(sessions.c.remember, sessions.c.expires_at, sessions.c.last_seen_at,
                       sessions.c.idle_seconds, sessions.c.revoked_at, users.c.user_id,
                       users.c.member_code, users.c.email, users.c.display_name, users.c.role,
                       users.c.account_status, users.c.email_verified_at)
                .join(users, users.c.user_id == sessions.c.user_id)
                .where(sessions.c.session_hash == h)).mappings().first()
            if (row is None or row["revoked_at"] is not None or row["expires_at"] <= now
                    or (now - row["last_seen_at"]).total_seconds() > row["idle_seconds"]
                    or row["account_status"] != "active" or row["email_verified_at"] is None):
                return None
            if (now - row["last_seen_at"]).total_seconds() > 60:
                conn.execute(update(sessions).where(sessions.c.session_hash == h).values(last_seen_at=now))
            org_name, approval = "", None
            if row["role"] == "employer":
                org = conn.execute(
                    select(organizations.c.name, organizations.c.approval_status)
                    .select_from(organization_members.join(
                        organizations,
                        organizations.c.organization_id == organization_members.c.organization_id))
                    .where(organization_members.c.user_id == row["user_id"],
                           organization_members.c.status == "active")
                    .order_by(organization_members.c.created_at).limit(1)).mappings().first()
                if org:
                    org_name, approval = org["name"], org["approval_status"]
                else:
                    approval = "pending"
        return SessionInfo(
            session_hash=h, user_id=row["user_id"], member_code=row["member_code"],
            email=row["email"], display_name=row["display_name"], role=row["role"],
            organization=org_name, approval_status=approval, approved=approval == "approved",
            remember=bool(row["remember"]))

    def revoke_session(self, session_hash: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(update(sessions).where(
                sessions.c.session_hash == session_hash, sessions.c.revoked_at.is_(None)
            ).values(revoked_at=utcnow()))

    def revoke_all_sessions(self, user_id: str, conn=None) -> None:
        stmt = update(sessions).where(
            sessions.c.user_id == user_id, sessions.c.revoked_at.is_(None)).values(revoked_at=utcnow())
        if conn is not None:
            conn.execute(stmt)
        else:
            with self.engine.begin() as c:
                c.execute(stmt)

    def csrf_for(self, info: SessionInfo) -> str:
        return csrf_token_for(self.cfg.secret_key, info.session_hash)

    def session_payload(self, info: SessionInfo) -> dict:
        return {
            "authenticated": True,
            "user": {
                "member_code": info.member_code, "display_name": info.display_name,
                "email": info.email, "role": info.role, "approved": info.approved,
                "approval_status": info.approval_status, "organization": info.organization,
            },
            "csrf_token": self.csrf_for(info),
        }

    # ------------------------------------------------------------------
    # Feature-app identity resolver (the contract in section 4)
    # ------------------------------------------------------------------
    def current_session(self) -> Optional[SessionInfo]:
        """Verified session for this request (memoised on flask.g). Fails closed."""
        cached = g.get("_hv_session", _UNSET)
        if cached is not _UNSET:
            return cached
        try:
            info = self.lookup_session(request.cookies.get(self.cfg.cookie_name))
        except SQLAlchemyError as exc:
            raise AuthUnavailable() from exc
        g._hv_session = info
        return info

    def resolve_identity(self) -> Optional[dict]:
        info = self.current_session()
        if info is None:
            return None
        approved = bool(info.role == "employer" and info.approved)
        return {
            "id": info.user_id,
            "role": info.role,
            "organization": info.organization if approved else "",
            "approved": approved,
        }

    # ------------------------------------------------------------------
    # Account recovery
    # ------------------------------------------------------------------
    def forgot_password(self, email_raw, ip: str) -> dict:
        """Always the same response; mail only goes to active, verified accounts."""
        email = norm_email(email_raw)
        self._limit_hit("forgot_ip", ip, 10, 3600)
        if not email:
            return {"ok": True}
        self._limit_hit("forgot_email", email, 3, 3600)
        mail, now = None, utcnow()
        with self.engine.begin() as conn:
            row = conn.execute(select(users).where(
                users.c.email == email, users.c.account_status == "active")).mappings().first()
            if row:
                conn.execute(delete(password_resets).where(
                    password_resets.c.user_id == row["user_id"], password_resets.c.used_at.is_(None)))
                token = new_token()
                conn.execute(insert(password_resets).values(
                    reset_id=uuid.uuid4().hex, user_id=row["user_id"], token_hash=sha256_hex(token),
                    expires_at=now + timedelta(seconds=self.cfg.reset_ttl_seconds), created_at=now))
                mail = (row["email"], row["display_name"], token)
        if mail:
            to, name, token = mail
            base = self.cfg.app_base_url
            self.mailer.send("reset", to, {
                "userName": name or "there", "userEmail": to,
                "resetUrl": f"{base}{self.cfg.reset_path}#token={token}",
                "expiryMinutes": self.cfg.reset_ttl_seconds // 60,
                "supportUrl": self.cfg.support_url,
                "exploreSkillsUrl": f"{base}/#skills", "trainingUrl": f"{base}/#training",
                # Deliberately not collected: IP address and location.
                "requestTime": now.strftime("%d %b %Y, %H:%M UTC"),
                "requestDevice": "a web browser",
                "requestIp": "not recorded", "requestLocation": "not recorded",
            })
        return {"ok": True}

    def reset_password(self, data: dict, ip: str) -> dict:
        self._limit_hit("reset_ip", ip, 20, 900)
        token, new_password = data.get("token"), data.get("new_password")
        problem = self._check_password(new_password)
        if problem:
            raise AuthError(400, "invalid_input", problem, {"new_password": problem})
        bad = AuthError(400, "invalid_token", "This reset link is invalid or has expired.")
        if not isinstance(token, str) or not token or len(token) > 200:
            raise bad
        now = utcnow()
        new_hash = hash_password(new_password)
        with self.engine.begin() as conn:
            row = conn.execute(
                select(password_resets, users.c.account_status)
                .join(users, users.c.user_id == password_resets.c.user_id)
                .where(password_resets.c.token_hash == sha256_hex(token))).mappings().first()
            if (not row or row["used_at"] is not None or row["expires_at"] <= now
                    or row["account_status"] != "active"):
                raise bad
            conn.execute(update(password_resets).where(
                password_resets.c.reset_id == row["reset_id"]).values(used_at=now))
            conn.execute(update(users).where(users.c.user_id == row["user_id"]).values(
                password_hash=new_hash, updated_at=now))
            self.revoke_all_sessions(row["user_id"], conn=conn)  # recovery revokes every session
        return {"ok": True}

    # ------------------------------------------------------------------
    # Operator actions (used by the CLI; every change is audited)
    # ------------------------------------------------------------------
    def _audit(self, conn, subject_type, subject_id, action, reviewer, reason):
        conn.execute(insert(audit_log).values(
            subject_type=subject_type, subject_id=subject_id, action=action,
            reviewer=reviewer, reason=(reason or "")[:500], created_at=utcnow()))

    def _find_org(self, conn, identifier: str):
        if identifier.startswith("hv:org:"):
            cond = organizations.c.organization_id == identifier
            stmt = select(organizations).where(cond)
        else:
            stmt = (select(organizations)
                    .select_from(organizations
                                 .join(organization_members, organization_members.c.organization_id == organizations.c.organization_id)
                                 .join(users, users.c.user_id == organization_members.c.user_id))
                    .where(users.c.email == norm_email(identifier)))
        return conn.execute(stmt).mappings().first()

    def set_org_approval(self, identifier: str, action: str, reviewer: str, reason: str = "") -> dict:
        if action not in APPROVAL_ACTIONS:
            raise ValueError("action must be approve, reject or revoke")
        new_status, allowed = APPROVAL_ACTIONS[action]
        with self.engine.begin() as conn:
            org = self._find_org(conn, identifier)
            if not org:
                raise LookupError("organisation not found")
            if org["approval_status"] not in allowed:
                raise ValueError(f"cannot {action} an organisation that is {org['approval_status']}")
            now = utcnow()
            conn.execute(update(organizations).where(
                organizations.c.organization_id == org["organization_id"]).values(
                approval_status=new_status, reviewed_by=reviewer, reviewed_at=now,
                review_reason=(reason or "")[:500], updated_at=now))
            self._audit(conn, "organization", org["organization_id"], action, reviewer, reason)
        return {"organization_id": org["organization_id"], "name": org["name"], "approval_status": new_status}

    def set_account_status(self, email: str, action: str, reviewer: str, reason: str = "") -> dict:
        """suspend | reactivate | delete. All revoke sessions immediately."""
        with self.engine.begin() as conn:
            row = conn.execute(select(users).where(users.c.email == norm_email(email))).mappings().first()
            if not row:
                raise LookupError("account not found")
            now = utcnow()
            if action == "suspend":
                values = {"account_status": "suspended"}
            elif action == "reactivate":
                if row["account_status"] != "suspended" or row["email_verified_at"] is None:
                    raise ValueError("only suspended, verified accounts can be reactivated")
                values = {"account_status": "active"}
            elif action == "delete":
                # Keep the row (tombstone) so user_id is never reused; scrub the
                # identifier and credentials and free the e-mail address.
                values = {"account_status": "deleted", "email": f"deleted+{row['user_id'][8:]}@invalid.local",
                          "display_name": "", "password_hash": "!deleted"}
            else:
                raise ValueError("action must be suspend, reactivate or delete")
            conn.execute(update(users).where(users.c.user_id == row["user_id"]).values(updated_at=now, **values))
            self.revoke_all_sessions(row["user_id"], conn=conn)
            self._audit(conn, "user", row["user_id"], action, reviewer, reason)
        return {"user_id": row["user_id"], "account_status": values["account_status"]}

    def list_pending_orgs(self) -> list:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(organizations.c.organization_id, organizations.c.name, users.c.email,
                       users.c.account_status, organizations.c.created_at)
                .select_from(organizations
                             .join(organization_members, organization_members.c.organization_id == organizations.c.organization_id)
                             .join(users, users.c.user_id == organization_members.c.user_id))
                .where(organizations.c.approval_status == "pending")
                .order_by(organizations.c.created_at)).mappings().all()
        return [dict(r) for r in rows]

    def create_verified_account(self, email: str, password: str, role: str,
                                org_name: str = "", org_status: str = "pending") -> str:
        """Operator/test helper: a verified, active account (no e-mail round trip)."""
        problem = self._check_password(password)
        if problem:
            raise ValueError(problem)
        with self.engine.begin() as conn:
            return self._insert_user(
                conn, email=norm_email(email), pw_hash=hash_password(password), display_name="",
                role=role, status="active", verified=True, org_name=org_name, org_status=org_status)
