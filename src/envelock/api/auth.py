"""Authentication endpoints (PRD §15.1).

In-memory user store for now — persistence lands with the Alembic migrations.
The security primitives, role model and token flow are real; only the storage is
provisional, and it is isolated behind `_USERS` so swapping it does not touch
the endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from envelock.auth.deps import AdminUser, CurrentUser
from envelock.auth.security import (
    MFA_PENDING_TTL,
    SENSITIVE_ACTIONS,
    Role,
    TokenError,
    decode_token,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    hash_recovery_code,
    issue_pair,
    issue_token,
    totp_uri,
    verify_password,
    verify_totp,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@dataclass
class _User:
    id: UUID
    tenant_id: UUID
    email: str
    password_hash: str
    role: Role
    totp_secret: str | None = None
    mfa_enabled: bool = False
    recovery_hashes: set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


_USERS: dict[str, _User] = {}


def _reset_store() -> None:
    """Test hook."""
    _USERS.clear()


# ── Schemas ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    tenant_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MfaEnableRequest(BaseModel):
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest) -> dict:
    """First user of a tenant becomes its owner."""
    email = req.email.lower()
    if email in _USERS:
        # Same response shape as success would be better for enumeration
        # resistance, but a 409 is the honest answer for a self-serve signup.
        raise HTTPException(status.HTTP_409_CONFLICT, "account already exists")

    try:
        password_hash = hash_password(req.password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    user = _User(
        id=uuid4(),
        tenant_id=uuid4(),
        email=email,
        password_hash=password_hash,
        role=Role.OWNER,
    )
    _USERS[email] = user

    return {
        "user_id": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role.value,
        "mfa_required": True,
        "next": "Call /auth/mfa/setup — MFA is mandatory before this account can "
        "hold a session.",
    }


@router.post("/login")
async def login(req: LoginRequest) -> dict:
    user = _USERS.get(req.email.lower())
    # Verify against a dummy hash when the user is missing so timing does not
    # leak which addresses exist.
    stored = user.password_hash if user else hash_password("x" * 12)
    if not verify_password(req.password, stored) or user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if not user.mfa_enabled:
        return {
            "mfa_setup_required": True,
            "mfa_token": issue_token(
                user_id=user.id,
                tenant_id=user.tenant_id,
                role=user.role,
                typ="mfa_pending",
                ttl=MFA_PENDING_TTL,
            ),
        }

    return {
        "mfa_required": True,
        "mfa_token": issue_token(
            user_id=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            typ="mfa_pending",
            ttl=MFA_PENDING_TTL,
        ),
    }


def _user_by_id(user_id: UUID) -> _User:
    for user in _USERS.values():
        if user.id == user_id:
            return user
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown user")


@router.post("/mfa/setup")
async def mfa_setup(req: RefreshRequest) -> dict:
    """Exchange an `mfa_pending` token for a TOTP secret to enrol."""
    try:
        claims = decode_token(req.refresh_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = _user_by_id(claims.sub)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    user.totp_secret = generate_totp_secret()
    return {
        "secret": user.totp_secret,
        "otpauth_uri": totp_uri(user.totp_secret, user.email),
        "next": "Confirm with /auth/mfa/verify to activate.",
    }


@router.post("/mfa/verify")
async def mfa_verify(req: MfaVerifyRequest) -> dict:
    """Completes login, or activates MFA on first enrolment."""
    try:
        claims = decode_token(req.mfa_token, expect="mfa_pending")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = _user_by_id(claims.sub)
    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA not set up")
    if not verify_totp(user.totp_secret, req.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")

    first_time = not user.mfa_enabled
    user.mfa_enabled = True

    tokens = issue_pair(user_id=user.id, tenant_id=user.tenant_id, role=user.role)
    if first_time:
        codes = generate_recovery_codes()
        user.recovery_hashes = {hash_recovery_code(c) for c in codes}
        # Shown exactly once — only hashes are retained.
        tokens["recovery_codes"] = codes
    return tokens


@router.post("/refresh")
async def refresh(req: RefreshRequest) -> dict:
    """Refresh tokens rotate: the presented token is replaced, not reused."""
    try:
        claims = decode_token(req.refresh_token, expect="refresh")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = _user_by_id(claims.sub)
    return issue_pair(user_id=user.id, tenant_id=user.tenant_id, role=user.role)


@router.get("/me")
async def me(principal: CurrentUser) -> dict:
    user = _user_by_id(principal.user_id)
    return {
        "user_id": str(user.id),
        "tenant_id": str(user.tenant_id),
        "email": user.email,
        "role": user.role.value,
        "mfa_enabled": user.mfa_enabled,
        "is_admin": principal.is_admin,
    }


@router.get("/sensitive-actions")
async def sensitive_actions(principal: CurrentUser) -> dict:
    """Actions that force a fresh password re-entry regardless of session age."""
    return {"actions": sorted(SENSITIVE_ACTIONS), "role": principal.role.value}


@router.get("/admin/users")
async def list_users(principal: AdminUser) -> dict:
    """Admin-only. Demonstrates both the role guard and tenant isolation."""
    return {
        "users": [
            {"email": u.email, "role": u.role.value, "mfa_enabled": u.mfa_enabled}
            for u in _USERS.values()
            if u.tenant_id == principal.tenant_id
        ]
    }
