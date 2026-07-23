"""Authentication endpoints (PRD §15.1).

Accounts are persisted to the database. The security primitives, role model and
token flow live in `auth/security.py`; this module holds the endpoints and the
thin data-access helpers that read and write the `users` table.

A security product whose own accounts do not survive a restart is indefensible,
so there is no in-memory shortcut here — every account, its MFA secret and its
recovery-code hashes are durable.
"""

from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser
from envelock.auth.security import (
    MFA_PENDING_TTL,
    REFRESH_TTL,
    SENSITIVE_ACTIONS,
    Role,
    TokenError,
    assess_passphrase,
    decode_token,
    dummy_hash,
    generate_numeric_otp,
    generate_recovery_codes,
    generate_totp_secret,
    hash_otp,
    hash_password,
    hash_recovery_code,
    issue_pair,
    issue_token,
    totp_uri,
    verify_password,
    verify_totp,
)
from envelock.db import get_session
from envelock.models import Tenant, User
from envelock.security.limits import lockout, revocations, totp_replay

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

Session = Annotated[AsyncSession, Depends(get_session)]


def _reset_store() -> None:
    """Test hook: clear persisted accounts between tests.

    Uses a plain synchronous SQLite connection so it can run at fixture
    setup/teardown without an event loop. A no-op on any other backend and when
    the schema has not been created yet.
    """
    import sqlite3

    from envelock.config import get_settings

    dsn = get_settings().postgres_dsn
    if "sqlite" not in dsn:
        return
    path = dsn.rsplit(":///", 1)[-1] if ":///" in dsn else dsn.rsplit("://", 1)[-1]
    if not path or path == ":memory:":
        return
    try:
        conn = sqlite3.connect(path)
        try:
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM tenants")
            conn.commit()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        pass  # schema not yet created


# ── Schemas ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    # Length ceilings everywhere: an unbounded password is unbounded scrypt work.
    password: str = Field(min_length=12, max_length=256)
    tenant_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(max_length=4096)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoveryRequest(BaseModel):
    mfa_token: str = Field(max_length=4096)
    recovery_code: str = Field(max_length=64)


class TokenRequest(BaseModel):
    token: str = Field(max_length=4096)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _generic_401() -> HTTPException:
    """One message for every credential failure.

    Distinguishing "no such account" from "wrong password" hands an attacker a
    free account-enumeration oracle.
    """
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")


async def _user_by_email(session: AsyncSession, email: str) -> User | None:
    return (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def _user_by_id(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise _generic_401()
    return user


def _role_of(user: User) -> Role:
    return Role(user.role)


def _issue_mfa_challenge(user: User) -> str:
    return issue_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=_role_of(user),
        typ="mfa_pending",
        ttl=MFA_PENDING_TTL,
    )


async def _complete_login(
    session: AsyncSession, user: User, *, first_time: bool = False
) -> dict:
    lockout.record_success(user.email)
    tokens = issue_pair(
        user_id=user.id, tenant_id=user.tenant_id, role=_role_of(user)
    )
    if first_time:
        codes = generate_recovery_codes()
        user.recovery_hashes = [hash_recovery_code(c) for c in codes]
        tokens["recovery_codes"] = codes  # shown exactly once
    await session.commit()
    return tokens


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, session: Session) -> dict:
    """First user of a tenant becomes its owner."""
    email = req.email.lower().strip()

    # Identical response whether or not the address exists — a 409 here would
    # turn signup into an account-enumeration endpoint.
    if await _user_by_email(session, email) is None:
        try:
            assess_passphrase(req.password)
            password_hash = hash_password(req.password)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)
            ) from exc
        tenant = Tenant(id=uuid4(), name=req.tenant_name)
        session.add(tenant)
        session.add(
            User(
                id=uuid4(),
                tenant_id=tenant.id,
                email=email,
                password_hash=password_hash,
                role=Role.OWNER.value,
                is_admin=True,  # owner has admin oversight (PRD §15.1)
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            # Lost a race to another concurrent signup of the same address.
            # Idempotent by design — surface the same response either way.
            await session.rollback()

    return {
        "status": "registration_received",
        "mfa_required": True,
        "next": "Sign in, then complete MFA setup. MFA is mandatory before this "
        "account can hold a session.",
    }


@router.post("/login")
async def login(req: LoginRequest, session: Session) -> dict:
    email = req.email.lower().strip()

    locked, retry_after = lockout.is_locked(email)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_email(session, email)
    # Compare against a precomputed hash when the account is unknown, so the
    # timing profile matches without doing 32 MB of scrypt per bogus request.
    stored = user.password_hash if user else dummy_hash()
    password_ok = verify_password(req.password, stored)

    if user is None or not password_ok:
        lockout.record_failure(email)
        raise _generic_401()

    return {
        "mfa_setup_required": not user.mfa_enabled,
        "mfa_required": user.mfa_enabled,
        "mfa_token": _issue_mfa_challenge(user),
    }


@router.post("/mfa/setup")
async def mfa_setup(req: TokenRequest, session: Session) -> dict:
    """Exchange an `mfa_pending` token for a TOTP secret to enrol."""
    try:
        claims = decode_token(req.token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)
    if user.mfa_enabled:
        # Re-enrolment must go through the authenticated reset flow, or anyone
        # holding the password could replace the second factor.
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    user.totp_secret = generate_totp_secret()
    await session.commit()
    return {
        "secret": user.totp_secret,
        "otpauth_uri": totp_uri(user.totp_secret, user.email),
        "next": "Confirm with /auth/mfa/verify to activate.",
    }


@router.post("/mfa/verify")
async def mfa_verify(req: MfaVerifyRequest, session: Session) -> dict:
    """Completes login, or activates MFA on first enrolment."""
    try:
        claims = decode_token(req.mfa_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)

    locked, retry_after = lockout.is_locked(f"mfa:{user.email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA not set up")

    if not verify_totp(user.totp_secret, req.code):
        lockout.record_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    # A TOTP code stays valid for its whole window, so without this an observed
    # code (phishing proxy, shoulder-surf, malware) can be replayed.
    if not totp_replay.check_and_record(f"{user.id}:{req.code}"):
        lockout.record_failure(f"mfa:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code already used")

    first_time = not user.mfa_enabled
    user.mfa_enabled = True
    lockout.record_success(f"mfa:{user.email}")
    return await _complete_login(session, user, first_time=first_time)


@router.post("/recovery")
async def recovery(req: RecoveryRequest, session: Session) -> dict:
    """Redeem a single-use recovery code when the authenticator is lost.

    Without this, generating recovery codes at enrolment was theatre — a user
    who lost their device had no way back in.
    """
    try:
        claims = decode_token(req.mfa_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = await _user_by_id(session, claims.sub)

    locked, retry_after = lockout.is_locked(f"rec:{user.email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    candidate = hash_recovery_code(req.recovery_code)
    # Constant-time membership test over the stored hashes.
    matched = None
    for stored in user.recovery_hashes or []:
        if secrets.compare_digest(stored, candidate):
            matched = stored
    if matched is None:
        lockout.record_failure(f"rec:{user.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid recovery code")

    # Reassign (not mutate in place) so SQLAlchemy tracks the change.
    user.recovery_hashes = [h for h in user.recovery_hashes if h != matched]
    lockout.record_success(f"rec:{user.email}")

    tokens = await _complete_login(session, user)
    tokens["recovery_codes_remaining"] = len(user.recovery_hashes)
    tokens["warning"] = (
        "Recovery code consumed. Re-enrol your authenticator and regenerate codes."
    )
    return tokens


@router.post("/refresh")
async def refresh(req: TokenRequest, session: Session) -> dict:
    """Rotating refresh with reuse detection.

    The presented token is revoked on use. If it is presented again it was
    stolen or replayed, so every session for that user is revoked rather than
    just the one token.
    """
    try:
        claims = decode_token(req.token, expect="refresh")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    if revocations.is_revoked(claims.jti, str(claims.sub)):
        revocations.revoke_user(
            str(claims.sub), until=time.time() + REFRESH_TTL.total_seconds()
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "refresh token reuse detected — all sessions revoked",
        )

    revocations.revoke_jti(claims.jti, expires_at=float(claims.exp))
    user = await _user_by_id(session, claims.sub)
    return issue_pair(
        user_id=user.id, tenant_id=user.tenant_id, role=_role_of(user)
    )


@router.post("/logout")
async def logout(principal: CurrentUser) -> dict:
    """Revokes every refresh token for the caller."""
    revocations.revoke_user(
        str(principal.user_id), until=time.time() + REFRESH_TTL.total_seconds()
    )
    return {"status": "logged_out"}


@router.get("/me")
async def me(principal: CurrentUser, session: Session) -> dict:
    user = await _user_by_id(session, principal.user_id)
    return {
        "user_id": str(user.id),
        "tenant_id": str(user.tenant_id),
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "phone": user.phone,
        "phone_verified": user.phone_verified,
        "is_admin": principal.is_admin,
        "recovery_codes_remaining": len(user.recovery_hashes or []),
    }


@router.get("/sensitive-actions")
async def sensitive_actions(principal: CurrentUser) -> dict:
    """Actions that force a fresh password re-entry regardless of session age."""
    return {"actions": sorted(SENSITIVE_ACTIONS), "role": principal.role.value}


# ── Phone verification (out-of-band + SMS-escalation channel) ─────────────────
class PhoneStartRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32, pattern=r"^\+?[0-9 ()-]{7,31}$")


class PhoneVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


_PHONE_OTP_TTL = timedelta(minutes=10)


@router.post("/phone/start")
async def phone_start(
    req: PhoneStartRequest, principal: CurrentUser, session: Session
) -> dict:
    """Begin proving possession of a phone number. A one-time code is sent by SMS;
    the phone is only trusted for out-of-band alerts and SMS escalation once
    verified (PRD §8.1/§8.2)."""
    from envelock.config import get_settings
    from envelock.core.enums import AlertTier
    from envelock.notify.senders import Notification, SmsSender

    locked, retry_after = lockout.is_locked(f"phone:{principal.user_id}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_id(session, principal.user_id)
    code = generate_numeric_otp()
    user.phone = req.phone.strip()
    user.phone_verified = False
    user.phone_otp_hash = hash_otp(code)
    user.phone_otp_expires_at = datetime.now(UTC) + _PHONE_OTP_TTL
    await session.commit()

    sender = SmsSender()
    delivered = await sender.send(
        Notification(
            alert_id=uuid4(),
            tenant_id=principal.tenant_id,
            tier=AlertTier.LOW,
            title=f"Your Envelock verification code is {code}",
            body="",
        ),
        to=user.phone,
    )

    out: dict = {"status": "code_sent", "delivered": delivered.delivered}
    # Outside production the SMS provider is usually unconfigured; surfacing the
    # code keeps local dev and tests usable, exactly as MFA setup returns its
    # secret. Never in production.
    if not get_settings().is_production:
        out["dev_code"] = code
    return out


@router.post("/phone/verify")
async def phone_verify(
    req: PhoneVerifyRequest, principal: CurrentUser, session: Session
) -> dict:
    """Confirm the code and mark the phone verified."""
    locked, retry_after = lockout.is_locked(f"phone:{principal.user_id}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = await _user_by_id(session, principal.user_id)
    expires = user.phone_otp_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if not user.phone_otp_hash or expires is None or expires < datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no active code — start again")

    if not secrets.compare_digest(user.phone_otp_hash, hash_otp(req.code)):
        lockout.record_failure(f"phone:{principal.user_id}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    user.phone_verified = True
    user.phone_otp_hash = None
    user.phone_otp_expires_at = None
    lockout.record_success(f"phone:{principal.user_id}")
    await session.commit()
    return {"phone_verified": True, "phone": user.phone}


@router.get("/admin/users")
async def list_users(principal: AdminUser, session: Session) -> dict:
    """Admin-only, and scoped to the caller's own tenant."""
    rows = (
        await session.execute(
            select(User).where(User.tenant_id == principal.tenant_id)
        )
    ).scalars()
    return {
        "users": [
            {"email": u.email, "role": u.role, "mfa_enabled": u.mfa_enabled}
            for u in rows
        ]
    }
