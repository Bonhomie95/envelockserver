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

    return Principal(user_id=claims.sub, tenant_id=claims.tenant, role=claims.role)


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
    return Principal(user_id=claims.sub, tenant_id=claims.tenant, role=claims.role)


def require_role(minimum: Role):
    """Route dependency enforcing a minimum role."""

    async def _guard(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Principal:
        if not role_at_least(principal.role, minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"requires {minimum.value} role",
            )
        return principal

    return _guard


CurrentUser = Annotated[Principal, Depends(current_principal)]
OptionalUser = Annotated[Principal | None, Depends(optional_principal)]
AdminUser = Annotated[Principal, Depends(require_role(Role.ADMIN))]
OwnerUser = Annotated[Principal, Depends(require_role(Role.OWNER))]
