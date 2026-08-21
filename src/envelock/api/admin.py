"""Platform console API — cross-tenant operations.

This is the only place tenant isolation is deliberately crossed, so it is
deliberately narrow: operational metadata and a few support actions, never
secrets — no password hashes, TOTP secrets, mailbox credentials or card
fingerprints are returned by anything here.

Access is per-permission, not all-or-nothing. Each endpoint declares the one
permission it needs (`auth/staff.py`), so a support agent can approve a customer
user without also being able to suspend a tenant, and a billing clerk can change
a plan without reading anyone's alert queue. The deployment email allowlist
remains as break-glass and carries every permission.

Every mutation is written to both the customer's tenant audit log (so they can
see that we acted on their account) and the staff audit log (so we can see who
did it).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.api.staff_auth import CurrentOperator, record_staff_audit, requires
from envelock.auth.security import Role, role_at_least
from envelock.auth.staff import Operator, Permission
from envelock.db import get_session
from envelock.models import Alert, AuditEvent, Domain, Mailbox, Tenant, User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
Session = Annotated[AsyncSession, Depends(get_session)]

# One alias per permission the console needs, so a route reads as its own
# authorisation statement rather than deferring to a comment.
PlatformReader = Annotated[Operator, Depends(requires(Permission.PLATFORM_READ))]
TenantReader = Annotated[Operator, Depends(requires(Permission.TENANT_READ))]
UserReader = Annotated[Operator, Depends(requires(Permission.USER_READ))]
BillingOperator = Annotated[Operator, Depends(requires(Permission.TENANT_BILLING))]
SuspendOperator = Annotated[Operator, Depends(requires(Permission.TENANT_SUSPEND))]
UserOperator = Annotated[Operator, Depends(requires(Permission.USER_MANAGE))]
RoleOperator = Annotated[Operator, Depends(requires(Permission.USER_ROLE))]

_PLANS = {"guard", "essential", "complete", "solo"}
_ROLES = {"member", "admin", "owner"}


def _trial_view(tenant: Tenant) -> dict:
    now = datetime.now(UTC)
    ends = tenant.trial_ends_at
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    active = bool(ends and ends > now)
    days_left = None
    if ends:
        delta = ends - now
        days_left = max(0, delta.days + (1 if delta.seconds and delta.days >= 0 else 0))
    paid = tenant.payment_method_ok
    effective = tenant.plan if (active or paid) else "guard"
    return {
        "subscribed_plan": tenant.plan,
        "effective_plan": effective,
        "trial_active": active,
        "trial_days_left": days_left if active else 0,
        "trial_ends_at": ends.isoformat() if ends else None,
        "payment_method_ok": paid,
        "has_billing_account": bool(tenant.stripe_customer_id),
    }


async def _audit(
    session: AsyncSession,
    actor: Operator,
    *,
    tenant_id: UUID,
    action: str,
    target_type: str,
    target_id: UUID,
    detail: dict,
    request: Request | None = None,
) -> None:
    """Write the action to both logs.

    The tenant's own log, so a customer can see that Envelock touched their
    account — a platform action invisible to the customer is not acceptable in a
    product sold on oversight. And the staff log, which the customer cannot see
    and an operator cannot reach through a tenant view.
    """
    try:
        actor_id: UUID | None = UUID(actor.id)
    except ValueError:
        actor_id = None
    session.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail={"by": actor.email, "department": actor.department, **detail},
        )
    )
    await record_staff_audit(
        session,
        actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        tenant_id=tenant_id,
        ip=request.client.host if request and request.client else None,
        detail=detail,
    )


@router.get("/whoami")
async def whoami(actor: CurrentOperator) -> dict:
    """Who the console is talking to, and exactly what they may do — the client
    hides what it must not offer, and the server still enforces every check."""
    return {**actor.as_dict(), "is_superadmin": True}


@router.get("/overview")
async def overview(actor: PlatformReader, session: Session) -> dict:
    """Platform-wide counts for the console home."""
    now = datetime.now(UTC)

    async def _count(stmt) -> int:  # noqa: ANN001
        return int((await session.execute(stmt)).scalar_one())

    tenants = await _count(select(func.count()).select_from(Tenant))
    users = await _count(select(func.count()).select_from(User))
    pending_users = await _count(
        select(func.count()).select_from(User).where(User.status == "pending")
    )
    mailboxes = await _count(select(func.count()).select_from(Mailbox))
    open_alerts = await _count(
        select(func.count()).select_from(Alert).where(Alert.state == "open")
    )
    critical_open = await _count(
        select(func.count())
        .select_from(Alert)
        .where(Alert.state == "open", Alert.tier == "critical")
    )
    paying = await _count(
        select(func.count()).select_from(Tenant).where(Tenant.payment_method_ok.is_(True))
    )
    active_trials = await _count(
        select(func.count()).select_from(Tenant).where(Tenant.trial_ends_at > now)
    )

    plan_rows = (
        await session.execute(
            select(Tenant.plan, func.count()).group_by(Tenant.plan)
        )
    ).all()

    return {
        "tenants": tenants,
        "users": users,
        "pending_users": pending_users,
        "mailboxes": mailboxes,
        "open_alerts": open_alerts,
        "critical_open": critical_open,
        "paying_tenants": paying,
        "active_trials": active_trials,
        "plan_distribution": {plan: int(n) for plan, n in plan_rows},
        "generated_at": now.isoformat(),
    }


async def _counts_by_tenant(session: AsyncSession) -> tuple[dict, dict, dict]:
    users = {
        t: int(n)
        for t, n in (
            await session.execute(select(User.tenant_id, func.count()).group_by(User.tenant_id))
        ).all()
    }
    mailboxes = {
        t: int(n)
        for t, n in (
            await session.execute(
                select(Mailbox.tenant_id, func.count()).group_by(Mailbox.tenant_id)
            )
        ).all()
    }
    open_alerts = {
        t: int(n)
        for t, n in (
            await session.execute(
                select(Alert.tenant_id, func.count())
                .where(Alert.state == "open")
                .group_by(Alert.tenant_id)
            )
        ).all()
    }
    return users, mailboxes, open_alerts


@router.get("/tenants")
async def list_tenants(
    actor: TenantReader,
    session: Session,
    query: str = "",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Every tenant, newest first, with rollup counts. `query` matches the tenant
    name or any of its registrable domains."""
    stmt = select(Tenant)
    if query.strip():
        q = f"%{query.strip().lower()}%"
        matching = select(Domain.tenant_id).where(func.lower(Domain.registrable_domain).like(q))
        stmt = stmt.where(or_(func.lower(Tenant.name).like(q), Tenant.id.in_(matching)))
    total = int(
        (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    )
    tenants = (
        (
            await session.execute(
                stmt.order_by(Tenant.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    u_counts, m_counts, a_counts = await _counts_by_tenant(session)

    # Primary domain per listed tenant.
    ids = [t.id for t in tenants]
    domains: dict[UUID, str] = {}
    if ids:
        for tid, reg in (
            await session.execute(
                select(Domain.tenant_id, Domain.registrable_domain)
                .where(Domain.tenant_id.in_(ids))
                .order_by(Domain.created_at.asc())
            )
        ).all():
            domains.setdefault(tid, reg)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "tenants": [
            {
                "id": str(t.id),
                "name": t.name,
                "primary_domain": domains.get(t.id),
                "is_active": t.is_active,
                "users": u_counts.get(t.id, 0),
                "mailboxes": m_counts.get(t.id, 0),
                "open_alerts": a_counts.get(t.id, 0),
                "created_at": t.created_at.isoformat() if t.created_at else None,
                **_trial_view(t),
            }
            for t in tenants
        ],
    }


@router.get("/tenants/{tenant_id}")
async def tenant_detail(tenant_id: UUID, actor: TenantReader, session: Session) -> dict:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    users = (
        (await session.execute(select(User).where(User.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    mailboxes = (
        (await session.execute(select(Mailbox).where(Mailbox.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    domains = (
        (await session.execute(select(Domain).where(Domain.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    alerts = (
        (
            await session.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id)
                .order_by(Alert.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )

    return {
        "id": str(tenant.id),
        "name": tenant.name,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        **_trial_view(tenant),
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "mfa_enabled": u.mfa_enabled,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ],
        "mailboxes": [
            {
                "id": str(m.id),
                "address": m.address,
                "mailbox_class": m.mailbox_class,
                "protection_level": m.protection_level,
                "sources": list(m.sources or []),
            }
            for m in mailboxes
        ],
        "domains": [
            {
                "registrable_domain": d.registrable_domain,
                "verified": d.verified_at is not None,
                "dmarc_policy": d.dmarc_policy,
                "is_defensive": d.is_defensive,
            }
            for d in domains
        ],
        "recent_alerts": [
            {
                "id": str(a.id),
                "tier": a.tier,
                "title": a.title,
                "state": a.state,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }


@router.get("/users")
async def list_users(
    actor: UserReader,
    session: Session,
    query: str = "",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Every user across every tenant. `query` matches the email."""
    stmt = select(User, Tenant.name).join(Tenant, Tenant.id == User.tenant_id)
    if query.strip():
        stmt = stmt.where(func.lower(User.email).like(f"%{query.strip().lower()}%"))
    total = int(
        (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    )
    rows = (
        await session.execute(
            stmt.order_by(User.created_at.desc()).limit(limit).offset(offset)
        )
    ).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "mfa_enabled": u.mfa_enabled,
                "tenant_id": str(u.tenant_id),
                "tenant_name": tname,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for (u, tname) in rows
        ],
    }


# ── Actions ──────────────────────────────────────────────────────────────────
class SetPlanRequest(BaseModel):
    plan: str


class ExtendTrialRequest(BaseModel):
    days: int = Field(ge=1, le=365)


class SetRoleRequest(BaseModel):
    role: str


@router.post("/tenants/{tenant_id}/plan")
async def set_tenant_plan(
    tenant_id: UUID,
    req: SetPlanRequest,
    actor: BillingOperator,
    session: Session,
    request: Request,
) -> dict:
    plan = req.plan.strip().lower()
    if plan not in _PLANS:
        raise HTTPException(422, f"unknown plan: {req.plan}")
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    before = tenant.plan
    tenant.plan = plan
    await _audit(
        session, actor, tenant_id=tenant_id, action="admin.plan_changed",
        target_type="tenant", target_id=tenant_id, detail={"from": before, "to": plan},
        request=request,
    )
    await session.commit()
    return {"id": str(tenant_id), **_trial_view(tenant)}


@router.post("/tenants/{tenant_id}/extend-trial")
async def extend_trial(
    tenant_id: UUID,
    req: ExtendTrialRequest,
    actor: BillingOperator,
    session: Session,
    request: Request,
) -> dict:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    now = datetime.now(UTC)
    base = tenant.trial_ends_at
    if base is not None and base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    # Extend from now if the trial already lapsed, else from its current end.
    start = base if (base and base > now) else now
    if tenant.trial_started_at is None:
        tenant.trial_started_at = now
    tenant.trial_ends_at = start + timedelta(days=req.days)
    await _audit(
        session, actor, tenant_id=tenant_id, action="admin.trial_extended",
        target_type="tenant", target_id=tenant_id, detail={"days": req.days},
        request=request,
    )
    await session.commit()
    return {"id": str(tenant_id), **_trial_view(tenant)}


@router.post("/tenants/{tenant_id}/suspend")
async def suspend_tenant(
    tenant_id: UUID, actor: SuspendOperator, session: Session, request: Request
) -> dict:
    return await _set_tenant_active(session, actor, tenant_id, active=False, request=request)


@router.post("/tenants/{tenant_id}/activate")
async def activate_tenant(
    tenant_id: UUID, actor: SuspendOperator, session: Session, request: Request
) -> dict:
    return await _set_tenant_active(session, actor, tenant_id, active=True, request=request)


async def _set_tenant_active(
    session: AsyncSession,
    actor: Operator,
    tenant_id: UUID,
    *,
    active: bool,
    request: Request | None = None,
) -> dict:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    tenant.is_active = active
    await _audit(
        session, actor, tenant_id=tenant_id,
        action="admin.tenant_activated" if active else "admin.tenant_suspended",
        target_type="tenant", target_id=tenant_id, detail={}, request=request,
    )
    await session.commit()
    return {"id": str(tenant_id), "is_active": active}


async def _get_user(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return user


@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: UUID, actor: UserOperator, session: Session, request: Request
) -> dict:
    user = await _get_user(session, user_id)
    user.status = "active"
    await _audit(
        session, actor, tenant_id=user.tenant_id, action="admin.user_approved",
        target_type="user", target_id=user_id, detail={"email": user.email},
        request=request,
    )
    await session.commit()
    return {"id": str(user_id), "status": user.status}


@router.post("/users/{user_id}/suspend")
async def suspend_user(
    user_id: UUID, actor: UserOperator, session: Session, request: Request
) -> dict:
    user = await _get_user(session, user_id)
    if user.role == Role.OWNER.value:
        raise HTTPException(409, "suspend the owner via the tenant, not the user")
    user.status = "suspended"
    await _audit(
        session, actor, tenant_id=user.tenant_id, action="admin.user_suspended",
        target_type="user", target_id=user_id, detail={"email": user.email},
        request=request,
    )
    await session.commit()
    return {"id": str(user_id), "status": user.status}


@router.post("/users/{user_id}/activate")
async def activate_user(
    user_id: UUID, actor: UserOperator, session: Session, request: Request
) -> dict:
    user = await _get_user(session, user_id)
    user.status = "active"
    await _audit(
        session, actor, tenant_id=user.tenant_id, action="admin.user_activated",
        target_type="user", target_id=user_id, detail={"email": user.email},
        request=request,
    )
    await session.commit()
    return {"id": str(user_id), "status": user.status}


@router.post("/users/{user_id}/role")
async def set_user_role(
    user_id: UUID,
    req: SetRoleRequest,
    actor: RoleOperator,
    session: Session,
    request: Request,
) -> dict:
    role = req.role.strip().lower()
    if role not in _ROLES:
        raise HTTPException(422, f"unknown role: {req.role}")
    user = await _get_user(session, user_id)
    # Don't strip the last owner of a tenant of their ownership.
    if user.role == Role.OWNER.value and role != Role.OWNER.value:
        owners = int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(User)
                    .where(User.tenant_id == user.tenant_id, User.role == Role.OWNER.value)
                )
            ).scalar_one()
        )
        if owners <= 1:
            raise HTTPException(409, "a tenant must keep at least one owner")
    user.role = role
    user.is_admin = role_at_least(Role(role), Role.ADMIN)
    await _audit(
        session, actor, tenant_id=user.tenant_id, action="admin.role_changed",
        target_type="user", target_id=user_id, detail={"email": user.email, "role": role},
        request=request,
    )
    await session.commit()
    return {"id": str(user_id), "role": user.role, "is_admin": user.is_admin}
