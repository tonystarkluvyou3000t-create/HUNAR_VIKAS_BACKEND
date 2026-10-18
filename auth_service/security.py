"""Cryptographic helpers. No I/O, no Flask, no database."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()  # argon2id with the library's current defaults
# Verified against when the e-mail is unknown, so timing does not reveal it.
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


def new_token() -> str:
    """256-bit URL-safe secret (session ids, reset/verification link tokens)."""
    return secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    """Plain hash: enough for high-entropy random tokens."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def keyed_hash(secret_key: str, purpose: str, value: str) -> str:
    """HMAC-SHA256 for low-entropy values (6-digit codes, rate-limit keys)."""
    return hmac.new(
        secret_key.encode("utf-8"), f"{purpose}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


def generate_otp() -> str:
    return f"{secrets.randbelow(10 ** 6):06d}"


def csrf_token_for(secret_key: str, session_hash: str) -> str:
    """Per-session CSRF token, derived (not stored): HMAC(secret, session)."""
    return keyed_hash(secret_key, "csrf", session_hash)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --- Member code: "HVI-XXXX-XXXX-C" -------------------------------------
# Crockford Base32 member code (8-character payload + Luhn-mod-32 check
# character). The code carries no
# personal data and is for display only; it is NOT the feature-app identity.
MEMBER_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
MEMBER_PREFIX = "HVI"
_BASE = len(MEMBER_ALPHABET)
_PAYLOAD_LEN = 8


def _luhn_mod_sum(chars: str) -> int:
    total, factor = 0, 2
    for ch in reversed(chars):
        code = MEMBER_ALPHABET.find(ch)
        if code < 0:
            return -1
        addend = factor * code
        factor = 1 if factor == 2 else 2
        total += addend // _BASE + addend % _BASE
    return total


def _check_char(payload: str) -> str:
    return MEMBER_ALPHABET[(_BASE - (_luhn_mod_sum(payload) % _BASE)) % _BASE]


def generate_member_code() -> str:
    payload = "".join(
        MEMBER_ALPHABET[b % _BASE] for b in secrets.token_bytes(_PAYLOAD_LEN)
    )  # 256 % 32 == 0, so the mapping is unbiased
    return f"{MEMBER_PREFIX}-{payload[:4]}-{payload[4:]}-{_check_char(payload)}"


def normalize_member_code(value: str) -> str:
    stripped = "".join(value.upper().split()).replace("-", "")
    prefix, rest = stripped[:3], stripped[3:]
    rest = rest.replace("O", "0").replace("I", "1").replace("L", "1")
    if prefix in {"HVI", "HV1", "HVO"}:
        prefix = MEMBER_PREFIX
    return prefix + rest


def is_valid_member_code(value: object) -> bool:
    if not isinstance(value, str):
        return False
    clean = normalize_member_code(value)
    if not clean.startswith(MEMBER_PREFIX) or len(clean) != 3 + _PAYLOAD_LEN + 1:
        return False
    body = clean[3:]
    if any(MEMBER_ALPHABET.find(ch) < 0 for ch in body):
        return False
    return _check_char(body[:_PAYLOAD_LEN]) == body[_PAYLOAD_LEN]
