"""Managing Envelock's own people: create an operator, set their department,
adjust the exceptions, take access away.

This is what replaces "add an email to ENVELOCK_SUPERADMIN_EMAILS and redeploy".
The rules that matter are enforced here, not left to whoever is on the form:

* **Least privilege by default.** A new operator gets their department's default
  permission set. Extra permissions are an explicit, audited grant.
* **No self-escalation.** Nobody can raise their own permissions or department,
  and nobody can grant a permission they do not themselves hold — otherwise
  `staff:manage` silently means "everything".
* **The temporary password is shown exactly once**, to the person creating the
  account, and must be replaced before the console answers anything.
* **Every action is written to the staff audit log**, with who did it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.api.staff_auth import (
    new_temporary_password,
    record_staff_audit,
    requires,
)
from envelock.auth.security import hash_password
from envelock.auth.staff import (
    Department,
    Operator,
    Permission,
    department_catalogue,
    permission_catalogue,
    resolve_permissions,
)
from envelock.db import get_session
from envelock.models import StaffAccount, StaffAuditEvent
from envelock.security.limits import active_revocations

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
Session = Annotated[AsyncSession, Depends(get_session)]

StaffReader = Annotated[Operator, Depends(requires(Permission.STAFF_READ))]
StaffManager = Annotated[Operator, Depends(requires(Permission.STAFF_MANAGE))]
AuditReader = Annotated[Operator, Depends(requires(Permission.AUDIT_READ))]


def _view(account: StaffAccount) -> dict:
    permissions = resolve_permissions(
        department=account.department,
        granted=account.granted_permissions,
        revoked=account.revoked_permissions,
    )
    return {
        "id": str(account.id),
        "email": account.email,
        "name": account.name,
        "department": account.department,
        "status": account.status,
        "permissions": sorted(p.value for p in permissions),
        "granted_permissions": list(account.granted_permissions or []),
        "revoked_permissions": list(account.revoked_permissions or []),
        "mfa_enabled": account.mfa_enabled,
        "must_change_password": account.must_change_password,
        "last_login_at": account.last_login_at.isoformat() if account.last_login_at else None,
        "created_by": account.created_by,
        "created_at": account.created_at.isoformat() if account.created_at else None,
    }


def _parse_permissions(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        try:
            out.append(Permission(value).value)
        except ValueError as exc:
            raise HTTPException(422, f"unknown permission: {value}") from exc
    return out


def _assert_can_delegate(operator: Operator, permissions: list[str]) -> None:
    """You cannot grant what you do not hold.

    Without this, `staff:manage` quietly means "every permission": a support lead
    could create an account with `tenant:suspend` and sign in as it.
    """
    if operator.break_glass:
        return
    excess = [p for p in permissions if not operator.can(Permission(p))]
    if excess:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "you can only grant permissions you hold yourself — not "
            + ", ".join(sorted(excess)),
        )


def _assert_can_assign_department(operator: Operator, department: Department) -> None:
    from envelock.auth.staff import DEPARTMENT_PERMISSIONS

    if operator.break_glass:
        return
    missing = [
        p.value for p in DEPARTMENT_PERMISSIONS[department] if not operator.can(p)
    ]
    if missing:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"the {department.value} department carries permissions you do not "
            "hold, so you cannot assign it: " + ", ".join(sorted(missing)),
        )


# ── Catalogue (what the console renders on the form) ─────────────────────────
@router.get("/staff/roles")
async def staff_roles(operator: StaffReader) -> dict:
    """Departments and the permissions each carries, so the person filling in the
    form can see what they are handing over before they hand it over."""
    return {
        "departments": department_catalogue(),
        "permissions": permission_catalogue(),
        "your_permissions": sorted(p.value for p in operator.permissions),
    }


# ── List / create / update ───────────────────────────────────────────────────
@router.get("/staff")
async def list_staff(operator: StaffReader, session: Session) -> dict:
    rows = (
        (await session.execute(select(StaffAccount).order_by(StaffAccount.created_at.asc())))
        .scalars()
        .all()
    )
    from envelock.config import get_settings

    return {
        "staff": [_view(a) for a in rows],
        # The deployment allowlist is still live and still all-powerful, so it has
        # to be visible here — an operator list that hides half the operators is
        # worse than no list.
        "break_glass_emails": sorted(get_settings().superadmin_email_set),
        "you": operator.as_dict(),
    }


class CreateStaffRequest(BaseModel):
    email: EmailStr
    name: str | None = Field(default=None, max_length=255)
    department: Department = Department.SUPPORT
    #: Exceptions on top of the department default.
    granted_permissions: list[str] = Field(default_factory=list)
    revoked_permissions: list[str] = Field(default_factory=list)


@router.post("/staff", status_code=status.HTTP_201_CREATED)
async def create_staff(
    req: CreateStaffRequest, operator: StaffManager, session: Session, request: Request
) -> dict:
    """Create an operator account and return its one-time password.

    The password is returned **once**, in this response, for the creator to hand
    over out of band. We do not email it (an emailed console password is a
    standing phishing target) and we do not store it — only its hash.
    """
    email = req.email.lower().strip()
    if (
        await session.execute(select(StaffAccount).where(StaffAccount.email == email))
    ).scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "that operator already exists")

    granted = _parse_permissions(req.granted_permissions)
    revoked = _parse_permissions(req.revoked_permissions)
    _assert_can_assign_department(operator, req.department)
    _assert_can_delegate(operator, granted)

    temporary = new_temporary_password()
    account = StaffAccount(
        email=email,
        name=(req.name or "").strip() or None,
        password_hash=hash_password(temporary),
        department=req.department.value,
        granted_permissions=granted,
        revoked_permissions=revoked,
        status="active",
        must_change_password=True,
        created_by=operator.email,
    )
    session.add(account)
    await session.flush()
    await record_staff_audit(
        session,
        operator,
        action="staff.created",
        target_type="staff",
        target_id=str(account.id),
        ip=request.client.host if request.client else None,
        detail={"email": email, "department": req.department.value, "granted": granted},
    )
    await session.commit()
    return {
        **_view(account),
        "temporary_password": temporary,
        "next": (
            "Give this password to them directly — it is shown once and never "
            "stored. They must set their own password and enrol an authenticator "
            "before the console will answer."
        ),
    }


class UpdateStaffRequest(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    department: Department | None = None
    granted_permissions: list[str] | None = None
    revoked_permissions: list[str] | None = None


@router.patch("/staff/{staff_id}")
async def update_staff(
    staff_id: UUID,
    req: UpdateStaffRequest,
    operator: StaffManager,
    session: Session,
    request: Request,
) -> dict:
    account = await session.get(StaffAccount, staff_id)
    if account is None:
        raise HTTPException(404, "operator not found")
    if str(account.id) == operator.id:
        # Self-escalation is the whole reason this check exists: with staff:manage
        # you could otherwise move yourself to leadership in one request.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "you cannot change your own department or permissions — ask a colleague",
        )

    before = {
        "department": account.department,
        "granted": list(account.granted_permissions or []),
        "revoked": list(account.revoked_permissions or []),
    }
    if req.name is not None:
        account.name = req.name.strip() or None
    if req.department is not None:
        _assert_can_assign_department(operator, req.department)
        account.department = req.department.value
    if req.granted_permissions is not None:
        granted = _parse_permissions(req.granted_permissions)
        _assert_can_delegate(operator, granted)
        account.granted_permissions = granted
    if req.revoked_permissions is not None:
        account.revoked_permissions = _parse_permissions(req.revoked_permissions)

    await record_staff_audit(
        session,
        operator,
        action="staff.updated",
        target_type="staff",
        target_id=str(account.id),
        ip=request.client.host if request.client else None,
        detail={"email": account.email, "before": before, "after": {
            "department": account.department,
            "granted": list(account.granted_permissions or []),
            "revoked": list(account.revoked_permissions or []),
        }},
    )
    await session.commit()
    return _view(account)


@router.post("/staff/{staff_id}/suspend")
async def suspend_staff(
    staff_id: UUID, operator: StaffManager, session: Session, request: Request
) -> dict:
    """Take access away now: the status is read on every request and every
    session is revoked, so it does not wait for a token to expire."""
    account = await session.get(StaffAccount, staff_id)
    if account is None:
        raise HTTPException(404, "operator not found")
    if str(account.id) == operator.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot suspend yourself")

    active_managers = int(
        (
            await session.execute(
                select(func.count())
                .select_from(StaffAccount)
                .where(
                    StaffAccount.status == "active",
                    StaffAccount.department.in_(
                        [Department.LEADERSHIP.value, Department.SECURITY.value]
                    ),
                )
            )
        ).scalar_one()
    )
    if (
        account.department in (Department.LEADERSHIP.value, Department.SECURITY.value)
        and active_managers <= 1
    ):
        # Break-glass would still get back in, but locking the last in-product
        # administrator out is a support incident nobody needs.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this is the last operator who can manage staff — promote someone "
            "else first",
        )

    account.status = "suspended"
    account.disabled_at = datetime.now(UTC)
    await active_revocations().arevoke_user(
        str(account.id), until=datetime.now(UTC).timestamp() + 14 * 24 * 3600
    )
    await record_staff_audit(
        session,
        operator,
        action="staff.suspended",
        target_type="staff",
        target_id=str(account.id),
        ip=request.client.host if request.client else None,
        detail={"email": account.email},
    )
    await session.commit()
    return _view(account)


@router.post("/staff/{staff_id}/reinstate")
async def reinstate_staff(
    staff_id: UUID, operator: StaffManager, session: Session, request: Request
) -> dict:
    account = await session.get(StaffAccount, staff_id)
    if account is None:
        raise HTTPException(404, "operator not found")
    account.status = "active"
    account.disabled_at = None
    await record_staff_audit(
        session,
        operator,
        action="staff.reinstated",
        target_type="staff",
        target_id=str(account.id),
        ip=request.client.host if request.client else None,
        detail={"email": account.email},
    )
    await session.commit()
    return _view(account)


@router.post("/staff/{staff_id}/reset-password")
async def reset_staff_password(
    staff_id: UUID, operator: StaffManager, session: Session, request: Request
) -> dict:
    """Issue a fresh one-time password — the lost-password path for an operator.

    Also clears the authenticator, because the usual reason for this call is "they
    lost the phone with it on". Both halves have to be re-established before the
    console answers again.
    """
    account = await session.get(StaffAccount, staff_id)
    if account is None:
        raise HTTPException(404, "operator not found")

    temporary = new_temporary_password()
    account.password_hash = hash_password(temporary)
    account.must_change_password = True
    account.mfa_enabled = False
    account.totp_secret = None
    account.recovery_hashes = []
    await active_revocations().arevoke_user(
        str(account.id), until=datetime.now(UTC).timestamp() + 14 * 24 * 3600
    )
    await record_staff_audit(
        session,
        operator,
        action="staff.password_reset",
        target_type="staff",
        target_id=str(account.id),
        ip=request.client.host if request.client else None,
        detail={"email": account.email, "mfa_cleared": True},
    )
    await session.commit()
    return {
        **_view(account),
        "temporary_password": temporary,
        "next": "Hand this over directly. Their authenticator was also cleared "
        "and must be re-enrolled at next sign-in.",
    }


# ── The staff audit trail ────────────────────────────────────────────────────
@router.get("/staff/audit")
async def staff_audit(
    operator: AuditReader,
    session: Session,
    limit: int = 200,
    actor: str = "",
) -> dict:
    """What operators have done. Separate from the customer-facing audit log so a
    customer never sees it and an operator cannot prune it from a tenant view."""
    stmt = select(StaffAuditEvent).order_by(StaffAuditEvent.created_at.desc())
    if actor.strip():
        stmt = stmt.where(
            func.lower(StaffAuditEvent.actor_email).like(f"%{actor.strip().lower()}%")
        )
    rows = (await session.execute(stmt.limit(min(max(limit, 1), 500)))).scalars().all()
    return {
        "events": [
            {
                "id": str(e.id),
                "at": e.created_at.isoformat() if e.created_at else None,
                "actor": e.actor_email,
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "tenant_id": str(e.tenant_id) if e.tenant_id else None,
                "ip": e.ip,
                "detail": e.detail or {},
            }
            for e in rows
        ]
    }


__all__ = ["router"]
