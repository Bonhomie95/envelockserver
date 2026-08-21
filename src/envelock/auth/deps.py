"""FastAPI dependencies for authentication and role checks (PRD §15.1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status

from envelock.auth.security import Role, TokenError, decode_token, role_at_least


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    role: Role

    @property
    def is_admin(self) -> bool:
        return role_at_least(self.role, Role.ADMIN)

    def owns(self, tenant_id: UUID) -> bool:
        """Tenant isolation is checked on every access, not assumed."""
        return self.tenant_id == tenant_id


async def current_principal(
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_token(authorization.split(" ", 1)[1].strip(), expect="access")
    except TokenError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    _bind_tenant(claims.tenant)
    return Principal(user_id=claims.sub, tenant_id=claims.tenant, role=claims.role)


def _bind_tenant(tenant_id: UUID) -> None:
    """Bind the request's tenant to the DB contextvar so Postgres RLS (when
    enabled) scopes every query on this task to it."""
    from envelock.db import set_current_tenant

    set_current_tenant(tenant_id)


async def optional_principal(
    authorization: Annotated[str | None, Header()] = None,
) -> Principal | None:
    """Like `current_principal`, but returns `None` instead of raising when no
    valid bearer token is present.

    Used by endpoints that are public but must redact the internal detection
    taxonomy for anonymous callers (PRD §16) while returning full detail to a
    signed-in session.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    try:
        claims = decode_token(authorization.split(" ", 1)[1].strip(), expect="access")
    except TokenError:
        return None
    _bind_tenant(claims.tenant)
    return Principal(user_id=claims.sub, tenant_id=claims.tenant, role=claims.role)


async def _live_user(principal: Principal):  # noqa: ANN202 — models.User
    """Load the caller's current row. The token is a 15-minute snapshot; every
    authorisation decision has to be made against what is true now."""
    from envelock.db import get_sessionmaker
    from envelock.models import User

    async with get_sessionmaker()() as session:
        return await session.get(User, principal.user_id)


def require_role(minimum: Role):
    """Route dependency enforcing a minimum role, against the LIVE account.

    Checking the token's role alone made suspension a paper control: an access
    token issued before a suspension kept full admin powers until it expired,
    and `/auth/refresh` would mint fresh ones from a 14-day refresh token, so a
    suspended admin could hold their access indefinitely. Both the role and the
    account status are therefore read from the database on every request.
    """

    async def _guard(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Principal:
        user = await _live_user(principal)
        if user is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if user.status != "active":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "this account is not active — ask a workspace admin to approve "
                "or reinstate it",
            )
        live_role = Role(user.role)
        if not role_at_least(live_role, minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"requires {minimum.value} role",
            )
        # Return the live role, not the token's: a demotion takes effect now.
        return Principal(
            user_id=user.id, tenant_id=user.tenant_id, role=live_role
        )

    return _guard


CurrentUser = Annotated[Principal, Depends(current_principal)]
OptionalUser = Annotated[Principal | None, Depends(optional_principal)]
AdminUser = Annotated[Principal, Depends(require_role(Role.ADMIN))]
OwnerUser = Annotated[Principal, Depends(require_role(Role.OWNER))]


@dataclass(frozen=True, slots=True)
class Actor:
    """A Principal enriched from the database with the fields needed for approval
    gating and per-member scoping — the live role/status/email, not the token's
    (so an approval or role change takes effect on the next request, not in 15
    minutes when the access token rotates)."""

    user_id: UUID
    tenant_id: UUID
    role: Role
    email: str
    status: str

    @property
    def is_admin(self) -> bool:
        return role_at_least(self.role, Role.ADMIN)

    @property
    def is_member(self) -> bool:
        return self.role is Role.MEMBER


async def active_actor(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Actor:
    """Load the caller and require an *active* account. A pending colleague can
    hold a session (to see the "awaiting approval" screen) but reaches no tenant
    data until an admin approves them."""
    # Imported here to avoid a module import cycle (models → db → config).
    from envelock.db import get_sessionmaker
    from envelock.models import User

    async with get_sessionmaker()() as session:
        user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if user.status != "active":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "your account is awaiting approval from a workspace admin",
        )
    return Actor(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=Role(user.role),
        email=user.email,
        status=user.status,
    )


ActiveUser = Annotated[Actor, Depends(active_actor)]


async def superadmin_actor(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Actor:
    """Platform operator gate for the cross-tenant admin console.

    Membership is an email allowlist set at deployment (`ENVELOCK_SUPERADMIN_EMAILS`)
    — never grantable through the product — so no in-app role change can escalate
    to seeing every tenant's data. A valid session whose email isn't on the list
    gets 404 (not 403): we don't advertise that a super-admin surface exists.
    """
    from envelock.config import get_settings
    from envelock.db import get_sessionmaker
    from envelock.models import User

    allow = get_settings().superadmin_email_set
    async with get_sessionmaker()() as session:
        user = await session.get(User, principal.user_id)
    if user is None or not allow or user.email.lower() not in allow:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return Actor(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=Role(user.role),
        email=user.email,
        status=user.status,
    )


SuperAdmin = Annotated[Actor, Depends(superadmin_actor)]
