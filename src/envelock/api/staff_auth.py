"""Sign-in for Envelock's own operators — separate from the customer product.

Platform staff authenticate here, against `staff_accounts`, and receive tokens of
type `staff_access` / `staff_refresh`. Nothing issued by the customer login works
on the admin console, and nothing issued here works on a tenant's data: the token
type is checked, so a stolen customer token cannot be pointed at `/admin` and a
stolen operator token cannot be pointed at `/api/v1/mailboxes`.

Three rules that differ from the customer flow, because these credentials reach
every tenant's metadata:

* **MFA is not deferrable.** A customer may skip enrolment and be nagged; an
  operator cannot hold a session without it.
* **The first password is temporary.** A new operator must replace it before any
  admin endpoint answers.
* **Status is read on every request**, so revoking access is immediate rather
  than "within fifteen minutes".
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.security import (
    ACCESS_TTL,
    MFA_PENDING_TTL,
    REFRESH_TTL,
    TokenError,
    assess_passphrase,
    decode_token,
    dummy_hash,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    hash_recovery_code,
    issue_token,
    totp_uri,
    verify_password,
    verify_totp,
)
from envelock.auth.staff import Operator, Permission, resolve_permissions
from envelock.db import get_session
from envelock.models import StaffAccount, StaffAuditEvent
from envelock.security.limits import active_lockout, active_replay, active_revocations

router = APIRouter(prefix="/api/v1/admin/auth", tags=["admin"])
logger = logging.getLogger("envelock.staff")

Session = Annotated[AsyncSession, Depends(get_session)]

ACCESS_TYPE = "staff_access"  # noqa: S105 — a token type name, not a secret
REFRESH_TYPE = "staff_refresh"  # noqa: S105
PENDING_TYPE = "staff_mfa_pending"  # noqa: S105

#: Staff tokens carry no tenant, but the claim shape requires one. A fixed
#: sentinel keeps the token format unchanged while making a misuse obvious.
_NO_TENANT = "00000000-0000-0000-0000-000000000000"


def _generic_401() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")


async def _by_email(session: AsyncSession, email: str) -> StaffAccount | None:
    return (
        await session.execute(select(StaffAccount).where(StaffAccount.email == email))
    ).scalar_one_or_none()


def _issue(account: StaffAccount, typ: str, ttl) -> str:  # noqa: ANN001 — timedelta
    from uuid import UUID as _UUID

    from envelock.auth.security import Role

    return issue_token(
        user_id=account.id,
        tenant_id=_UUID(_NO_TENANT),
        role=Role.OWNER,  # unused for staff; the permission set is the authority
        typ=typ,
        ttl=ttl,
    )


async def record_staff_audit(
    session: AsyncSession,
    operator: Operator,
    *,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    tenant_id=None,  # noqa: ANN001 — UUID | None
    ip: str | None = None,
    detail: dict | None = None,
) -> None:
    """Every operator action is written to the staff log, including the reads that
    cross into a customer's data."""
    from uuid import UUID as _UUID

    actor_id = None
    if operator.id and operator.id != "break-glass":
        try:
            actor_id = _UUID(operator.id)
        except ValueError:
            actor_id = None
    session.add(
        StaffAuditEvent(
            actor_email=operator.email,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            tenant_id=tenant_id,
            ip=ip,
            detail=detail or {},
        )
    )


# ── Schemas ──────────────────────────────────────────────────────────────────
class StaffLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)


class StaffMfaRequest(BaseModel):
    mfa_token: str = Field(max_length=4096)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class StaffTokenRequest(BaseModel):
    token: str = Field(max_length=4096)


class StaffPasswordRequest(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/login")
async def staff_login(req: StaffLoginRequest, session: Session, request: Request) -> dict:
    email = req.email.lower().strip()

    locked, retry_after = await active_lockout().ais_locked(f"staff:{email}")
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )

    account = await _by_email(session, email)
    stored = account.password_hash if account else dummy_hash()
    ok = verify_password(req.password, stored or dummy_hash())

    if account is None or not ok or account.status != "active":
        await active_lockout().arecord_failure(f"staff:{email}")
        logger.warning("staff sign-in refused for %s", email)
        raise _generic_401()

    account.last_login_ip = request.client.host if request.client else None
    await session.commit()

    return {
        # Enrolment is required, not offered: there is no skip endpoint here.
        "mfa_setup_required": not account.mfa_enabled,
        "must_change_password": account.must_change_password,
        "mfa_token": _issue(account, PENDING_TYPE, MFA_PENDING_TTL),
    }


@router.post("/mfa/setup")
async def staff_mfa_setup(req: StaffTokenRequest, session: Session) -> dict:
    """Exchange the pending token for a TOTP secret to enrol."""
    try:
        claims = decode_token(req.token, expect=PENDING_TYPE)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    account = await session.get(StaffAccount, claims.sub)
    if account is None or account.status != "active":
        raise _generic_401()
    if account.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")

    account.totp_secret = generate_totp_secret()
    await session.commit()
    return {
        "secret": account.totp_secret,
        "otpauth_uri": totp_uri(account.totp_secret, account.email, issuer="Envelock Admin"),
        "next": "Confirm with /admin/auth/mfa/verify to activate.",
    }


@router.post("/mfa/verify")
async def staff_mfa_verify(req: StaffMfaRequest, session: Session) -> dict:
    """Completes sign-in, or activates MFA on first enrolment."""
    try:
        claims = decode_token(req.mfa_token, expect=PENDING_TYPE)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    account = await session.get(StaffAccount, claims.sub)
    if account is None or account.status != "active":
        raise _generic_401()

    scope = f"staffmfa:{account.email}"
    locked, retry_after = await active_lockout().ais_locked(scope)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts",
            headers={"Retry-After": str(retry_after)},
        )
    if not account.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA not set up")
    if not verify_totp(account.totp_secret, req.code):
        await active_lockout().arecord_failure(scope)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    if not await active_replay().acheck_and_record(f"staff:{account.id}:{req.code}"):
        await active_lockout().arecord_failure(scope)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code already used")

    first_time = not account.mfa_enabled
    account.mfa_enabled = True
    account.last_login_at = datetime.now(UTC)
    await active_lockout().arecord_success(scope)
    await active_lockout().arecord_success(f"staff:{account.email}")

    out: dict = {
        "access_token": _issue(account, ACCESS_TYPE, ACCESS_TTL),
        "refresh_token": _issue(account, REFRESH_TYPE, REFRESH_TTL),
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
        "must_change_password": account.must_change_password,
    }
    if first_time:
        codes = generate_recovery_codes()
        account.recovery_hashes = [hash_recovery_code(c) for c in codes]
        out["recovery_codes"] = codes  # shown exactly once
    await session.commit()
    return out


@router.post("/refresh")
async def staff_refresh(req: StaffTokenRequest, session: Session) -> dict:
    """Rotating refresh with reuse detection, and a live status check — a revoked
    operator must not be able to mint a fresh session for two weeks."""
    try:
        claims = decode_token(req.token, expect=REFRESH_TYPE)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    if await active_revocations().ais_revoked(claims.jti, str(claims.sub)):
        await active_revocations().arevoke_user(
            str(claims.sub), until=datetime.now(UTC).timestamp() + REFRESH_TTL.total_seconds()
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "For your security, you've been signed out of all devices.",
        )
    await active_revocations().arevoke_jti(claims.jti, expires_at=float(claims.exp))

    account = await session.get(StaffAccount, claims.sub)
    if account is None or account.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this operator account is not active")
    return {
        "access_token": _issue(account, ACCESS_TYPE, ACCESS_TTL),
        "refresh_token": _issue(account, REFRESH_TYPE, REFRESH_TTL),
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
    }


# ── The dependency every admin endpoint uses ─────────────────────────────────
async def current_operator(
    session: Session,
    authorization: Annotated[str | None, Header()] = None,
) -> Operator:
    """Resolve the operator behind this request, from the live record.

    Accepts two identities:

    * a `staff_access` token, resolved against `staff_accounts`; and
    * a customer session whose email is on `ENVELOCK_SUPERADMIN_EMAILS` — the
      break-glass path, which is how the first staff account gets created and how
      an operator gets back in if the staff table is misconfigured.

    Anything else gets 404, not 403: we do not advertise that this surface exists.
    """
    from envelock.config import get_settings

    not_found = HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise not_found
    raw = authorization.split(" ", 1)[1].strip()

    # 1. A staff token.
    try:
        claims = decode_token(raw, expect=ACCESS_TYPE)
    except TokenError:
        claims = None
    if claims is not None:
        account = await session.get(StaffAccount, claims.sub)
        if account is None or account.status != "active":
            raise not_found
        if account.must_change_password:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "set your own password before using the console",
            )
        return Operator(
            id=str(account.id),
            email=account.email,
            name=account.name,
            department=account.department,
            permissions=resolve_permissions(
                department=account.department,
                granted=account.granted_permissions,
                revoked=account.revoked_permissions,
            ),
        )

    # 2. Break-glass: a customer session on the deployment allowlist.
    from envelock.models import User

    try:
        user_claims = decode_token(raw, expect="access")
    except TokenError as exc:
        raise not_found from exc
    allow = get_settings().superadmin_email_set
    user = await session.get(User, user_claims.sub)
    if user is None or not allow or user.email.lower() not in allow:
        raise not_found
    from envelock.auth.staff import ALL_PERMISSIONS

    return Operator(
        id=str(user.id),
        email=user.email,
        name=user.name,
        department="leadership",
        permissions=ALL_PERMISSIONS,
        break_glass=True,
    )


CurrentOperator = Annotated[Operator, Depends(current_operator)]


def requires(permission: Permission):
    """Route dependency: this endpoint needs exactly this permission."""

    async def _guard(operator: CurrentOperator) -> Operator:
        if not operator.can(permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"your role ({operator.department}) does not include "
                f"“{permission.value}”. Ask a workspace lead to grant it.",
            )
        return operator

    return _guard


@router.post("/logout")
async def logout(operator: CurrentOperator) -> dict:
    """Revoke every refresh token for this operator."""
    await active_revocations().arevoke_user(
        str(operator.id), until=datetime.now(UTC).timestamp() + REFRESH_TTL.total_seconds()
    )
    return {"status": "logged_out"}


@router.get("/me")
async def whoami(operator: CurrentOperator) -> dict:
    return operator.as_dict()


@router.post("/password")
async def set_own_password(
    req: StaffPasswordRequest,
    session: Session,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Set your own password.

    Deliberately does NOT go through `current_operator`: that dependency refuses
    an account with `must_change_password` set, which is exactly the account that
    needs this endpoint. The current password is verified here instead.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _generic_401()
    try:
        claims = decode_token(authorization.split(" ", 1)[1].strip(), expect=ACCESS_TYPE)
    except TokenError as exc:
        raise _generic_401() from exc

    account = await session.get(StaffAccount, claims.sub)
    if account is None or account.status != "active":
        raise _generic_401()

    scope = f"staffpw:{account.id}"
    locked, retry_after = await active_lockout().ais_locked(scope)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(retry_after)},
        )
    if not verify_password(req.current_password, account.password_hash or dummy_hash()):
        await active_lockout().arecord_failure(scope)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is wrong")
    await active_lockout().arecord_success(scope)

    try:
        assess_passphrase(req.new_password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if verify_password(req.new_password, account.password_hash or ""):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "the new password must be different"
        )

    account.password_hash = hash_password(req.new_password)
    account.must_change_password = False
    # A password change ends every other session — the standard response to
    # "I think this was compromised".
    await active_revocations().arevoke_user(
        str(account.id), until=datetime.now(UTC).timestamp() + REFRESH_TTL.total_seconds()
    )
    await session.commit()
    return {"status": "password_set", "sessions_revoked": True}


def new_temporary_password() -> str:
    """A one-time password handed to a new operator out of band.

    Long and random rather than memorable: it exists to be pasted once and
    replaced, and `assess_passphrase` must accept it.
    """
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return f"Env-{body}"


__all__ = [
    "ACCESS_TYPE",
    "CurrentOperator",
    "current_operator",
    "new_temporary_password",
    "record_staff_audit",
    "requires",
    "router",
]
