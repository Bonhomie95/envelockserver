"""Password hashing, TOTP and token issuance (PRD §15.1).

A security product whose own accounts are weakly protected is indefensible, so
MFA is mandatory rather than optional and tokens are short-lived with rotating
refresh.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from envelock.config import get_settings

# ── Roles ────────────────────────────────────────────────────────────────────


class Role(StrEnum):
    """PRD §15.1. E5's "IT sees who ignored an alert" depends on this split."""

    OWNER = "owner"  # billing, tenant deletion
    ADMIN = "admin"  # IT oversight: every mailbox, the full audit trail
    MEMBER = "member"  # own mailbox only


_RANK = {Role.MEMBER: 0, Role.ADMIN: 1, Role.OWNER: 2}


def role_at_least(actual: Role, required: Role) -> bool:
    return _RANK[actual] >= _RANK[required]


# ── Password hashing ─────────────────────────────────────────────────────────
# scrypt from the standard library: memory-hard, no native dependency, and
# available everywhere. Argon2id is the upgrade path if a dependency is
# acceptable — the stored format carries its parameters so migration is possible
# without invalidating existing hashes.

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1

#: OpenSSL caps scrypt at 32 MiB by default, and N=2^15 with r=8 needs
#: 128 * r * N = 32 MiB exactly — so the default rejects our parameters. Raise
#: the ceiling rather than weakening the cost factor.
_SCRYPT_MAXMEM = 128 * _SCRYPT_R * _SCRYPT_N * 2


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
        maxmem=_SCRYPT_MAXMEM,
    )
    return (
        f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"
    )


#: Computed once at import. Comparing against a live `hash_password()` call on
#: every unknown-email login let an attacker burn 80ms and 32 MB per request —
#: a few hundred concurrent requests exhaust the box. This keeps the timing
#: profile without the cost.
_DUMMY_HASH: str | None = None


def dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("not-a-real-password")
    return _DUMMY_HASH


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        derived = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
            # Read from the stored record, so raising the cost factor later does
            # not invalidate existing hashes.
            maxmem=128 * int(r) * int(n) * 2,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, base64.b64decode(hash_b64))


# ── TOTP (RFC 6238) ──────────────────────────────────────────────────────────


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_uri(secret: str, email: str, issuer: str = "Envelock") -> str:
    return (
        f"otpauth://totp/{issuer}:{email}?secret={secret}"
        f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )


def _totp_at(secret: str, counter: int) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_totp(secret: str, code: str, *, window: int = 1, now: int | None = None) -> bool:
    """`window=1` accepts the adjacent 30s steps for clock drift."""
    if not code or not code.strip().isdigit():
        return False
    counter = int((now if now is not None else time.time()) // 30)
    return any(
        hmac.compare_digest(_totp_at(secret, counter + drift), code.strip())
        for drift in range(-window, window + 1)
    )


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Shown once. Only hashes are stored."""
    return [
        f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        for _ in range(count)
    ]


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()


# ── Tokens ───────────────────────────────────────────────────────────────────
# Compact HMAC-signed tokens. No external JWT dependency: the payload is a
# signed JSON blob with the same guarantees for our single-issuer case.


class TokenError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class TokenClaims:
    sub: UUID  # user id
    tenant: UUID
    role: Role
    typ: str  # "access" | "refresh" | "mfa_pending"
    exp: int
    jti: str

    @property
    def expired(self) -> bool:
        return self.exp < int(time.time())


ACCESS_TTL = timedelta(minutes=15)
REFRESH_TTL = timedelta(days=14)
MFA_PENDING_TTL = timedelta(minutes=5)

#: Actions that require a fresh password re-entry regardless of session age.
SENSITIVE_ACTIONS = frozenset(
    {
        "mailbox.disconnect",
        "tenant.delete",
        "billing.update",
        "user.role_change",
        "mfa.disable",
        "export.token_create",
    }
)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload: bytes) -> bytes:
    key = get_settings().secret_key.get_secret_value().encode()
    return hmac.new(key, payload, hashlib.sha256).digest()


def issue_token(
    *, user_id: UUID, tenant_id: UUID, role: Role, typ: str, ttl: timedelta
) -> str:
    claims = {
        "sub": str(user_id),
        "tenant": str(tenant_id),
        "role": role.value,
        "typ": typ,
        "exp": int((datetime.now(UTC) + ttl).timestamp()),
        "jti": secrets.token_urlsafe(12),
    }
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    return f"{_b64(payload)}.{_b64(_sign(payload))}"


#: A token is a few hundred bytes; anything larger is an attempt to make us do
#: pointless base64 and HMAC work.
MAX_TOKEN_LENGTH = 4096


def decode_token(token: str, *, expect: str | None = None) -> TokenClaims:
    if not token or len(token) > MAX_TOKEN_LENGTH:
        raise TokenError("malformed token")
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = _unb64(payload_b64)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed token") from exc

    try:
        signature = _unb64(sig_b64)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed signature") from exc

    if not hmac.compare_digest(_sign(payload), signature):
        raise TokenError("bad signature")

    # Parsing happens only after the signature verifies, but a malformed field
    # must still surface as 401 rather than an unhandled 500.
    try:
        data = json.loads(payload)
        claims = TokenClaims(
            sub=UUID(data["sub"]),
            tenant=UUID(data["tenant"]),
            role=Role(data["role"]),
            typ=data["typ"],
            exp=int(data["exp"]),
            jti=data["jti"],
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise TokenError("malformed claims") from exc
    if claims.expired:
        raise TokenError("expired")
    if expect and claims.typ != expect:
        raise TokenError(f"expected {expect} token, got {claims.typ}")
    return claims


def issue_pair(*, user_id: UUID, tenant_id: UUID, role: Role) -> dict[str, object]:
    return {
        "access_token": issue_token(
            user_id=user_id, tenant_id=tenant_id, role=role, typ="access", ttl=ACCESS_TTL
        ),
        "refresh_token": issue_token(
            user_id=user_id, tenant_id=tenant_id, role=role, typ="refresh", ttl=REFRESH_TTL
        ),
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
        "role": role.value,
    }
